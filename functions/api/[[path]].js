const ROLES = new Set(['SUPER ADMIN', 'SUPPORT', 'TECHNICAL TEAM', 'MODERATOR', 'TEAM MEMBER', 'FORENSIC ANALYST']);
const LANES = new Set(['SUPPORT', 'TECHNICAL TEAM', 'MODERATOR', 'TEAM MEMBER']);
const TEST_CATEGORIES = new Set(['CODE_DEPENDENCY', 'WEB_API', 'NETWORK_SERVICE', 'CLOUD_CONFIGURATION']);
const encoder = new TextEncoder();

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function respond(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'"
    }
  });
}

function fail(status, message) {
  throw new ApiError(status, message);
}

function id() {
  return crypto.randomUUID();
}

function now() {
  return new Date().toISOString();
}

function base64UrlBytes(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function base64UrlJson(value) {
  return JSON.parse(new TextDecoder().decode(base64UrlBytes(value)));
}

async function sha256(value) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

async function verifyAccessAssertion(request, env) {
  const teamDomain = env.CF_ACCESS_TEAM_DOMAIN?.replace(/^https?:\/\//, '').replace(/\/$/, '');
  if (!teamDomain || !env.CF_ACCESS_AUD) fail(503, 'Cloudflare Access is not configured.');

  const token = request.headers.get('CF-Access-Jwt-Assertion');
  if (!token) fail(401, 'Sign in through the organization access gateway.');

  const parts = token.split('.');
  if (parts.length !== 3) fail(401, 'Invalid access assertion.');

  let header;
  let claims;
  try {
    header = base64UrlJson(parts[0]);
    claims = base64UrlJson(parts[1]);
  } catch {
    fail(401, 'Invalid access assertion.');
  }
  if (header.alg !== 'RS256' || typeof header.kid !== 'string') fail(401, 'Invalid access assertion.');

  const issuer = `https://${teamDomain}`;
  if (claims.iss !== issuer || !Number.isFinite(claims.exp) || claims.exp <= Date.now() / 1000) {
    fail(401, 'Expired or invalid access assertion.');
  }
  if (claims.nbf && claims.nbf > Date.now() / 1000 + 60) fail(401, 'Access assertion is not active yet.');
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(env.CF_ACCESS_AUD)) fail(401, 'Access assertion is for another application.');

  let certificates;
  try {
    const response = await fetch(`${issuer}/cdn-cgi/access/certs`, { cf: { cacheTtl: 300, cacheEverything: true } });
    if (!response.ok) fail(503, 'Could not verify organization identity.');
    certificates = await response.json();
  } catch (error) {
    if (error instanceof ApiError) throw error;
    fail(503, 'Could not verify organization identity.');
  }
  const jwk = certificates.keys?.find(key => key.kid === header.kid && key.kty === 'RSA');
  if (!jwk) fail(401, 'Unknown access signing key.');

  let valid = false;
  try {
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    valid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      base64UrlBytes(parts[2]),
      encoder.encode(`${parts[0]}.${parts[1]}`)
    );
  } catch {
    fail(401, 'Invalid access signature.');
  }
  if (!valid) fail(401, 'Invalid access signature.');

  const email = String(claims.email || '').trim().toLowerCase();
  if (!email || email.length > 254) fail(401, 'Access identity has no valid email.');
  return email;
}

async function authenticatedUser(request, env, allowInvitation = false) {
  const email = await verifyAccessAssertion(request, env);
  const user = await env.DB.prepare(
    'SELECT id, username, email, role, status FROM staff_users WHERE email = ? COLLATE NOCASE'
  ).bind(email).first();
  if (!user || (user.status !== 'ACTIVE' && !(allowInvitation && user.status === 'INVITED'))) {
    fail(403, 'This identity is not an active staff account.');
  }
  return user;
}

function requireRole(user, allowed) {
  if (!allowed.includes(user.role)) fail(403, 'Your staff role cannot perform this action.');
}

async function readJson(request) {
  if (!request.headers.get('content-type')?.toLowerCase().includes('application/json')) fail(415, 'Send a JSON request body.');
  const text = await request.text();
  if (encoder.encode(text).byteLength > 32768) fail(413, 'Request body is too large.');
  try {
    return JSON.parse(text);
  } catch {
    fail(400, 'Request body is not valid JSON.');
  }
}

function text(value, max = 200) {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}

function requireOrigin(request) {
  if (request.headers.get('Origin') !== new URL(request.url).origin) fail(403, 'Cross-origin requests are not allowed.');
}

async function audit(env, actorId, action, objectType, objectId = null, details = {}) {
  await env.DB.prepare(
    'INSERT INTO audit_events (id, actor_id, action, object_type, object_id, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(id(), actorId, action, objectType, objectId, JSON.stringify(details), now()).run();
}

async function listCustomers(env, user, url) {
  requireRole(user, ['SUPER ADMIN', 'SUPPORT']);
  const query = text(url.searchParams.get('q'), 80);
  const pattern = `%${query}%`;
  const result = await env.DB.prepare(
    `SELECT id, display_name, email, organization, contact_preference, contact_consent_at, created_at, updated_at
     FROM customers WHERE ? = '' OR display_name LIKE ? OR email LIKE ? OR organization LIKE ?
     ORDER BY display_name LIMIT 250`
  ).bind(query, pattern, pattern, pattern).all();
  return respond({ customers: result.results });
}

async function createCustomer(request, env, user) {
  requireRole(user, ['SUPER ADMIN', 'SUPPORT']);
  const body = await readJson(request);
  const displayName = text(body.displayName, 120);
  const email = text(body.email, 254).toLowerCase();
  const organization = text(body.organization, 160);
  const preference = text(body.contactPreference, 20) || 'EMAIL';
  if (!displayName || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail(400, 'Enter a name and valid email address.');
  if (!['EMAIL', 'PHONE', 'NO_CONTACT'].includes(preference)) fail(400, 'Invalid contact preference.');

  const customerId = id();
  const timestamp = now();
  try {
    await env.DB.prepare(
      `INSERT INTO customers (id, display_name, email, organization, contact_preference, contact_consent_at, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(customerId, displayName, email, organization, preference, body.contactConsent === true ? timestamp : null, user.id, timestamp, timestamp).run();
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) fail(409, 'A customer with this email already exists.');
    throw error;
  }
  await audit(env, user.id, 'customer.created', 'customer', customerId);
  return respond({ id: customerId }, 201);
}

function ticketRoles(user) {
  if (user.role === 'SUPER ADMIN' || user.role === 'SUPPORT') return null;
  if (LANES.has(user.role)) return user.role;
  fail(403, 'Your staff role cannot access support tickets.');
}

async function listTickets(env, user, url) {
  const lane = ticketRoles(user);
  const status = text(url.searchParams.get('status'), 16);
  if (status && !['OPEN', 'WAITING', 'CLOSED'].includes(status)) fail(400, 'Invalid ticket status.');
  const result = await env.DB.prepare(
    `SELECT t.id, t.subject, t.description, t.category, t.priority, t.status, t.assigned_role, t.created_at, t.updated_at,
            c.id AS customer_id, c.display_name AS customer_name, c.email AS customer_email, c.organization
     FROM support_tickets t JOIN customers c ON c.id = t.customer_id
     WHERE (? IS NULL OR t.assigned_role = ?) AND (? = '' OR t.status = ?)
     ORDER BY CASE t.priority WHEN 'URGENT' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'NORMAL' THEN 2 ELSE 3 END, t.created_at DESC LIMIT 250`
  ).bind(lane, lane, status, status).all();
  return respond({ tickets: result.results });
}

async function createTicket(request, env, user) {
  requireRole(user, ['SUPER ADMIN', 'SUPPORT']);
  const body = await readJson(request);
  const customerId = text(body.customerId, 64);
  const subject = text(body.subject, 180);
  const description = text(body.description, 4000);
  const category = text(body.category, 80);
  const priority = text(body.priority, 16) || 'NORMAL';
  const assignedRole = text(body.assignedRole, 32) || 'SUPPORT';
  if (!customerId || !subject || !description || !category) fail(400, 'Customer, subject, category, and description are required.');
  if (!['LOW', 'NORMAL', 'HIGH', 'URGENT'].includes(priority) || !LANES.has(assignedRole)) fail(400, 'Invalid priority or assignment.');
  const ticketId = id();
  const timestamp = now();
  const exists = await env.DB.prepare('SELECT id FROM customers WHERE id = ?').bind(customerId).first();
  if (!exists) fail(404, 'Customer not found.');
  await env.DB.prepare(
    `INSERT INTO support_tickets (id, customer_id, subject, description, category, priority, status, assigned_role, created_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?)`
  ).bind(ticketId, customerId, subject, description, category, priority, assignedRole, user.id, timestamp, timestamp).run();
  await audit(env, user.id, 'ticket.created', 'ticket', ticketId, { assignedRole, priority });
  return respond({ id: ticketId }, 201);
}

async function updateTicket(request, env, user, ticketId) {
  const lane = ticketRoles(user);
  const body = await readJson(request);
  const ticket = await env.DB.prepare('SELECT id, assigned_role, status FROM support_tickets WHERE id = ?').bind(ticketId).first();
  if (!ticket) fail(404, 'Ticket not found.');
  if (lane && lane !== ticket.assigned_role) fail(403, 'Ticket is outside your assigned team lane.');
  const status = body.status === undefined ? ticket.status : text(body.status, 16);
  const assignedRole = body.assignedRole === undefined ? ticket.assigned_role : text(body.assignedRole, 32);
  if (!['OPEN', 'WAITING', 'CLOSED'].includes(status) || !LANES.has(assignedRole)) fail(400, 'Invalid ticket update.');
  if (lane && assignedRole !== ticket.assigned_role) fail(403, 'Only Support or Super Admin may reassign tickets.');
  await env.DB.prepare('UPDATE support_tickets SET status = ?, assigned_role = ?, updated_at = ? WHERE id = ?')
    .bind(status, assignedRole, now(), ticketId).run();
  await audit(env, user.id, 'ticket.updated', 'ticket', ticketId, { status, assignedRole });
  return respond({ ok: true });
}

async function listUsers(env, user) {
  requireRole(user, ['SUPER ADMIN']);
  const result = await env.DB.prepare(
    'SELECT id, username, email, role, status, created_at FROM staff_users ORDER BY username LIMIT 250'
  ).all();
  return respond({ users: result.results });
}

async function updateUserRole(request, env, user, userId) {
  requireRole(user, ['SUPER ADMIN']);
  const body = await readJson(request);
  const role = text(body.role, 32);
  if (!ROLES.has(role)) fail(400, 'Select a valid staff role.');
  const result = await env.DB.prepare(
    `UPDATE staff_users SET role = ?, updated_at = ?
     WHERE id = ? AND (role <> 'SUPER ADMIN' OR ? = 'SUPER ADMIN' OR
       (SELECT COUNT(*) FROM staff_users WHERE role = 'SUPER ADMIN' AND status = 'ACTIVE') > 1)`
  ).bind(role, now(), userId, role).run();
  if (!result.meta.changes) fail(409, 'Role was not changed. The account may not exist or may be the last active Super Admin.');
  await audit(env, user.id, 'staff.role_changed', 'staff_user', userId, { role });
  return respond({ ok: true });
}

async function inviteUser(request, env, user) {
  requireRole(user, ['SUPER ADMIN']);
  if (!env.RESEND_API_KEY || !env.FROM_EMAIL) fail(503, 'Invitation email is not configured. Set RESEND_API_KEY and FROM_EMAIL.');
  const body = await readJson(request);
  const username = text(body.username, 40);
  const email = text(body.email, 254).toLowerCase();
  const role = text(body.role, 32);
  if (!/^[a-zA-Z0-9._-]{2,40}$/.test(username) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !ROLES.has(role)) {
    fail(400, 'Enter a valid username, email, and role.');
  }
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = Array.from(tokenBytes, byte => byte.toString(16).padStart(2, '0')).join('');
  const tokenHash = await sha256(token);
  const userId = id();
  const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();
  const timestamp = now();
  try {
    await env.DB.prepare(
      `INSERT INTO staff_users (id, username, email, role, status, invite_token_hash, invite_expires_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'INVITED', ?, ?, ?, ?)`
    ).bind(userId, username, email, role, tokenHash, expiresAt, timestamp, timestamp).run();
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) fail(409, 'Username or email is already registered.');
    throw error;
  }

  const inviteUrl = new URL('/staff.html', request.url);
  inviteUrl.hash = `invite=${token}`;
  let emailResponse;
  try {
    emailResponse = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: env.FROM_EMAIL,
        to: [email],
        subject: 'Axium Cyber staff invitation',
        text: `Hello ${username},\n\nYou have been invited to the Axium Cyber staff portal as ${role}. This link expires in 48 hours:\n\n${inviteUrl.href}\n\nSign in through the organization access gateway to accept the invitation.`
      })
    });
  } catch {
    emailResponse = null;
  }
  if (!emailResponse?.ok) {
    await env.DB.prepare("UPDATE staff_users SET status = 'SUSPENDED', invite_token_hash = NULL, invite_expires_at = NULL, updated_at = ? WHERE id = ?")
      .bind(now(), userId).run();
    fail(502, 'The invitation email could not be sent. The pending account was disabled.');
  }
  await audit(env, user.id, 'staff.invited', 'staff_user', userId, { role });
  return respond({ id: userId, status: 'INVITED' }, 201);
}

async function acceptInvitation(request, env, email) {
  const body = await readJson(request);
  const token = text(body.token, 128);
  if (!/^[a-f0-9]{64}$/.test(token)) fail(400, 'Invalid invitation token.');
  const tokenHash = await sha256(token);
  const result = await env.DB.prepare(
    `UPDATE staff_users SET status = 'ACTIVE', invite_token_hash = NULL, invite_expires_at = NULL, updated_at = ?
     WHERE email = ? COLLATE NOCASE AND status = 'INVITED' AND invite_token_hash = ? AND invite_expires_at > ?`
  ).bind(now(), email, tokenHash, now()).run();
  if (!result.meta.changes) fail(400, 'Invitation is invalid, expired, or belongs to another identity.');
  const user = await env.DB.prepare('SELECT id FROM staff_users WHERE email = ? COLLATE NOCASE').bind(email).first();
  await audit(env, user.id, 'staff.invitation_accepted', 'staff_user', user.id);
  return respond({ ok: true });
}

async function addSupportNote(request, env, user, ticketId) {
  const ticketRolesAllowed = ['SUPER ADMIN', 'SUPPORT', 'TECHNICAL TEAM', 'MODERATOR', 'TEAM MEMBER'];
  requireRole(user, ticketRolesAllowed);
  const ticket = await env.DB.prepare('SELECT id, assigned_role FROM support_tickets WHERE id = ?').bind(ticketId).first();
  if (!ticket) fail(404, 'Ticket not found.');
  if (user.role !== 'SUPER ADMIN' && user.role !== 'SUPPORT' && user.role !== ticket.assigned_role) fail(403, 'Ticket is outside your assigned team lane.');
  const body = await readJson(request);
  const note = text(body.body, 4000);
  if (!note) fail(400, 'Note cannot be empty.');
  const noteId = id();
  await env.DB.prepare('INSERT INTO support_notes (id, ticket_id, body, created_by, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(noteId, ticketId, note, user.id, now()).run();
  await audit(env, user.id, 'ticket.note_added', 'ticket', ticketId);
  return respond({ id: noteId }, 201);
}

async function listEngagements(env, user) {
  requireRole(user, ['SUPER ADMIN', 'TECHNICAL TEAM']);
  const result = await env.DB.prepare(
    `SELECT e.id, e.customer_id, c.display_name AS customer_name, e.title, e.categories_json, e.scope_json,
            e.authorization_reference, e.starts_at, e.expires_at, e.status, e.created_by, e.approved_by, e.created_at
     FROM security_engagements e JOIN customers c ON c.id = e.customer_id ORDER BY e.created_at DESC LIMIT 250`
  ).all();
  return respond({ engagements: result.results });
}

async function listEngagementCustomers(env, user) {
  requireRole(user, ['SUPER ADMIN', 'TECHNICAL TEAM']);
  const result = await env.DB.prepare(
    'SELECT id, display_name, organization FROM customers ORDER BY display_name LIMIT 250'
  ).all();
  return respond({ customers: result.results });
}

async function createEngagement(request, env, user) {
  requireRole(user, ['SUPER ADMIN', 'TECHNICAL TEAM']);
  const body = await readJson(request);
  const customerId = text(body.customerId, 64);
  const title = text(body.title, 180);
  const authorizationReference = text(body.authorizationReference, 300);
  const startsAt = text(body.startsAt, 40);
  const expiresAt = text(body.expiresAt, 40);
  if (!customerId || !title || !authorizationReference || !Array.isArray(body.scope) || body.scope.length < 1 || body.scope.length > 100) fail(400, 'Customer, title, written authorization reference, and scope are required.');
  const categories = Array.isArray(body.categories) ? body.categories : [];
  if (!categories.length || categories.some(category => !TEST_CATEGORIES.has(category))) fail(400, 'Select valid test categories.');
  const starts = Date.parse(startsAt);
  const expires = Date.parse(expiresAt);
  if (!Number.isFinite(starts) || !Number.isFinite(expires) || starts < Date.now() - 300000 || expires <= starts) fail(400, 'Engagement dates must be valid and in the future.');
  const scope = body.scope.map(value => text(value, 255));
  if (scope.some(value => !value || /[\s;]/.test(value))) fail(400, 'Each scope entry must be a hostname or network range without whitespace.');
  const exists = await env.DB.prepare('SELECT id FROM customers WHERE id = ?').bind(customerId).first();
  if (!exists) fail(404, 'Customer not found.');
  const engagementId = id();
  await env.DB.prepare(
    `INSERT INTO security_engagements (id, customer_id, title, categories_json, scope_json, authorization_reference, starts_at, expires_at, status, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'DRAFT', ?, ?)`
  ).bind(engagementId, customerId, title, JSON.stringify([...new Set(categories)]), JSON.stringify([...new Set(scope)]), authorizationReference, new Date(starts).toISOString(), new Date(expires).toISOString(), user.id, now()).run();
  await audit(env, user.id, 'engagement.created', 'engagement', engagementId);
  return respond({ id: engagementId, status: 'DRAFT' }, 201);
}

async function approveEngagement(env, user, engagementId) {
  requireRole(user, ['SUPER ADMIN']);
  const timestamp = now();
  const result = await env.DB.prepare(
    `UPDATE security_engagements SET status = 'APPROVED', approved_by = ?
     WHERE id = ? AND status = 'DRAFT' AND created_by <> ? AND starts_at <= ? AND expires_at > ?`
  ).bind(user.id, engagementId, user.id, timestamp, timestamp).run();
  if (!result.meta.changes) fail(409, 'Engagement cannot be approved: it may be expired, not a draft, missing, or created by this approver.');
  await audit(env, user.id, 'engagement.approved', 'engagement', engagementId);
  return respond({ ok: true, status: 'APPROVED' });
}

async function listForensicCases(env, user) {
  requireRole(user, ['SUPER ADMIN', 'FORENSIC ANALYST']);
  const result = await env.DB.prepare(
    'SELECT id, case_number, title, authority_name, authority_reference, purpose, status, expires_at, created_at FROM forensic_cases ORDER BY created_at DESC LIMIT 250'
  ).all();
  return respond({ cases: result.results });
}

async function createForensicCase(request, env, user) {
  requireRole(user, ['SUPER ADMIN', 'FORENSIC ANALYST']);
  const body = await readJson(request);
  const caseNumber = text(body.caseNumber, 80);
  const title = text(body.title, 180);
  const authorityName = text(body.authorityName, 180);
  const authorityReference = text(body.authorityReference, 300);
  const purpose = text(body.purpose, 2000);
  const expiresAt = Date.parse(text(body.expiresAt, 40));
  if (!caseNumber || !title || !authorityName || !authorityReference || !purpose || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) fail(400, 'Case details, legal authority reference, purpose, and future expiry are required.');
  const caseId = id();
  const timestamp = now();
  try {
    await env.DB.prepare(
      `INSERT INTO forensic_cases (id, case_number, title, authority_name, authority_reference, purpose, expires_at, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(caseId, caseNumber, title, authorityName, authorityReference, purpose, new Date(expiresAt).toISOString(), user.id, timestamp, timestamp).run();
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) fail(409, 'Case number already exists.');
    throw error;
  }
  await audit(env, user.id, 'forensic_case.created', 'forensic_case', caseId);
  return respond({ id: caseId }, 201);
}

async function addEvidence(request, env, user, caseId) {
  requireRole(user, ['SUPER ADMIN', 'FORENSIC ANALYST']);
  const caseRecord = await env.DB.prepare('SELECT id, status, expires_at FROM forensic_cases WHERE id = ?').bind(caseId).first();
  if (!caseRecord || caseRecord.status !== 'OPEN' || caseRecord.expires_at <= now()) fail(404, 'Open, current case not found.');
  const body = await readJson(request);
  const description = text(body.description, 500);
  const sourceReference = text(body.sourceReference, 300);
  const hash = text(body.sha256, 64).toLowerCase();
  const storageReference = text(body.storageReference, 200);
  const collectedAt = text(body.collectedAt, 40);
  if (!description || !sourceReference || !/^[a-f0-9]{64}$/.test(hash) || !/^[A-Za-z0-9:_/-]{1,200}$/.test(storageReference) || storageReference.includes('..') || !Number.isFinite(Date.parse(collectedAt))) {
    fail(400, 'Provide a description, source reference, SHA-256, secure vault reference, and collection time.');
  }
  const evidenceId = id();
  const timestamp = now();
  await env.DB.prepare(
    `INSERT INTO evidence_items (id, case_id, description, source_reference, sha256, secure_storage_reference, collected_by, collected_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(evidenceId, caseId, description, sourceReference, hash, storageReference, user.id, new Date(Date.parse(collectedAt)).toISOString(), timestamp).run();
  const event = { evidenceId, action: 'EVIDENCE_REGISTERED', by: user.id, at: timestamp, sha256: hash };
  const eventHash = await sha256(JSON.stringify(event));
  await env.DB.prepare(
    `INSERT INTO evidence_custody_events (id, evidence_id, action, to_custodian, performed_by, event_at, event_hash)
     VALUES (?, ?, 'EVIDENCE_REGISTERED', ?, ?, ?, ?)`
  ).bind(id(), evidenceId, user.email, user.id, timestamp, eventHash).run();
  await audit(env, user.id, 'evidence.registered', 'evidence_item', evidenceId, { caseId, sha256: hash });
  return respond({ id: evidenceId }, 201);
}

async function addCustodyEvent(request, env, user, evidenceId) {
  requireRole(user, ['SUPER ADMIN', 'FORENSIC ANALYST']);
  const evidence = await env.DB.prepare(
    `SELECT i.id, c.status, c.expires_at FROM evidence_items i JOIN forensic_cases c ON c.id = i.case_id WHERE i.id = ?`
  ).bind(evidenceId).first();
  if (!evidence || evidence.status !== 'OPEN' || evidence.expires_at <= now()) fail(404, 'Current evidence record not found.');
  const body = await readJson(request);
  const action = text(body.action, 80);
  const fromCustodian = text(body.fromCustodian, 180) || null;
  const toCustodian = text(body.toCustodian, 180) || null;
  const notes = text(body.notes, 1000);
  if (!action || (!fromCustodian && !toCustodian)) fail(400, 'Custody action and at least one custodian are required.');
  const previous = await env.DB.prepare(
    'SELECT event_hash FROM evidence_custody_events WHERE evidence_id = ? ORDER BY event_at DESC, id DESC LIMIT 1'
  ).bind(evidenceId).first();
  const timestamp = now();
  const event = { evidenceId, action, fromCustodian, toCustodian, notes, performedBy: user.id, at: timestamp, previousHash: previous?.event_hash || null };
  const eventHash = await sha256(JSON.stringify(event));
  await env.DB.prepare(
    `INSERT INTO evidence_custody_events (id, evidence_id, action, from_custodian, to_custodian, notes, performed_by, event_at, event_hash, previous_event_hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id(), evidenceId, action, fromCustodian, toCustodian, notes, user.id, timestamp, eventHash, previous?.event_hash || null).run();
  await audit(env, user.id, 'evidence.custody_recorded', 'evidence_item', evidenceId);
  return respond({ ok: true, eventHash }, 201);
}

async function listAudit(env, user) {
  requireRole(user, ['SUPER ADMIN']);
  const result = await env.DB.prepare(
    `SELECT a.id, a.action, a.object_type, a.object_id, a.details_json, a.created_at, u.username AS actor
     FROM audit_events a LEFT JOIN staff_users u ON u.id = a.actor_id ORDER BY a.created_at DESC LIMIT 200`
  ).all();
  return respond({ events: result.results });
}

async function route(request, env) {
  if (!env.DB) fail(503, 'D1 database binding is not configured.');
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const method = request.method.toUpperCase();
  if (!path.startsWith('/api/')) fail(404, 'Not found.');
  if (method !== 'GET' && method !== 'HEAD') requireOrigin(request);

  const isAccept = path === '/api/invites/accept' && method === 'POST';
  const user = await authenticatedUser(request, env, isAccept);
  if (path === '/api/me' && method === 'GET') return respond({ user: { id: user.id, username: user.username, email: user.email, role: user.role } });
  if (isAccept) return acceptInvitation(request, env, user.email);
  if (user.status !== 'ACTIVE') fail(403, 'Accept your staff invitation before continuing.');

  if (path === '/api/customers' && method === 'GET') return listCustomers(env, user, url);
  if (path === '/api/customers' && method === 'POST') return createCustomer(request, env, user);
  if (path === '/api/tickets' && method === 'GET') return listTickets(env, user, url);
  if (path === '/api/tickets' && method === 'POST') return createTicket(request, env, user);
  if (path === '/api/users' && method === 'GET') return listUsers(env, user);
  if (path === '/api/users' && method === 'POST') return inviteUser(request, env, user);
  if (path === '/api/engagements' && method === 'GET') return listEngagements(env, user);
  if (path === '/api/engagements' && method === 'POST') return createEngagement(request, env, user);
  if (path === '/api/engagement-customers' && method === 'GET') return listEngagementCustomers(env, user);
  if (path === '/api/forensics/cases' && method === 'GET') return listForensicCases(env, user);
  if (path === '/api/forensics/cases' && method === 'POST') return createForensicCase(request, env, user);
  if (path === '/api/audit' && method === 'GET') return listAudit(env, user);

  const ticketMatch = path.match(/^\/api\/tickets\/([\w-]+)$/);
  if (ticketMatch && method === 'PATCH') return updateTicket(request, env, user, ticketMatch[1]);
  const userMatch = path.match(/^\/api\/users\/([\w-]+)$/);
  if (userMatch && method === 'PATCH') return updateUserRole(request, env, user, userMatch[1]);
  const noteMatch = path.match(/^\/api\/tickets\/([\w-]+)\/notes$/);
  if (noteMatch && method === 'POST') return addSupportNote(request, env, user, noteMatch[1]);
  const inviteAcceptMatch = path.match(/^\/api\/invites\/accept$/);
  if (inviteAcceptMatch && method === 'POST') return acceptInvitation(request, env, user.email);
  const caseEvidenceMatch = path.match(/^\/api\/forensics\/cases\/([\w-]+)\/evidence$/);
  if (caseEvidenceMatch && method === 'POST') return addEvidence(request, env, user, caseEvidenceMatch[1]);
  const custodyMatch = path.match(/^\/api\/forensics\/evidence\/([\w-]+)\/custody$/);
  if (custodyMatch && method === 'POST') return addCustodyEvent(request, env, user, custodyMatch[1]);
  const approveMatch = path.match(/^\/api\/engagements\/([\w-]+)\/approve$/);
  if (approveMatch && method === 'POST') return approveEngagement(env, user, approveMatch[1]);
  if (path === '/api/security-tools' && method === 'GET') {
    requireRole(user, ['SUPER ADMIN', 'TECHNICAL TEAM']);
    return respond({ execution: 'DISABLED', categories: [...TEST_CATEGORIES], note: 'Tool execution requires a separately deployed, network-isolated runner.' });
  }
  if (path === '/api/test-runs' && method === 'POST') fail(503, 'No isolated test runner is configured. Tests are not executed by this portal.');
  return fail(404, 'Not found.');
}

export async function onRequest({ request, env }) {
  try {
    return await route(request, env);
  } catch (error) {
    if (error instanceof ApiError) return respond({ error: error.message }, error.status);
    console.error('Staff API request failed', error);
    return respond({ error: 'The request could not be completed.' }, 500);
  }
}