const ROLES = new Set(['SUPER ADMIN', 'SUPPORT', 'TECHNICAL TEAM', 'MODERATOR', 'TEAM MEMBER', 'FORENSIC ANALYST']);
const LANES = new Set(['SUPPORT', 'TECHNICAL TEAM', 'MODERATOR', 'TEAM MEMBER']);
const TEST_CATEGORIES = new Set(['CODE_DEPENDENCY', 'WEB_API', 'NETWORK_SERVICE', 'CLOUD_CONFIGURATION']);
const encoder = new TextEncoder();
const PASSWORD_ITERATIONS = 310000;
const SESSION_SECONDS = 8 * 60 * 60;

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function respond(data, status = 200, extraHeaders = {}) {
  return Response.json(data, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
      ...extraHeaders
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

async function sha256(value) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
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
    `SELECT id, username, contact_email AS email, role, status, created_at
     FROM staff_users WHERE deleted_at IS NULL ORDER BY username LIMIT 250`
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
     WHERE id = ? AND deleted_at IS NULL AND (role <> 'SUPER ADMIN' OR ? = 'SUPER ADMIN' OR
       (SELECT COUNT(*) FROM staff_users WHERE role = 'SUPER ADMIN' AND status = 'ACTIVE' AND deleted_at IS NULL) > 1)`
  ).bind(role, now(), userId, role).run();
  if (!result.meta.changes) fail(409, 'Role was not changed. The account may not exist or may be the last active Super Admin.');
  await audit(env, user.id, 'staff.role_changed', 'staff_user', userId, { role });
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
  ).bind(id(), evidenceId, user.contact_email || user.username, user.id, timestamp, eventHash).run();
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

  if (path === '/api/setup/status' && method === 'GET') return setupStatus(env);
  if (path === '/api/bootstrap' && method === 'POST') return bootstrapAdmin(request, env);
  if (path === '/api/auth/login' && method === 'POST') return login(request, env);

  const user = await authenticatedUser(request, env);
  if (path === '/api/me' && method === 'GET') return currentSession(request, env, user);
  if (method !== 'GET' && method !== 'HEAD') await requireCsrf(request, user);
  if (path === '/api/auth/logout' && method === 'POST') return logout(request, env, user);
  if (path === '/api/auth/change-password' && method === 'POST') return changePassword(request, env, user);
  if (user.must_change_password && path !== '/api/auth/logout') fail(428, 'Change your temporary password before continuing.');

  if (path === '/api/customers' && method === 'GET') return listCustomers(env, user, url);
  if (path === '/api/customers' && method === 'POST') return createCustomer(request, env, user);
  if (path === '/api/tickets' && method === 'GET') return listTickets(env, user, url);
  if (path === '/api/tickets' && method === 'POST') return createTicket(request, env, user);
  if (path === '/api/users' && method === 'GET') return listUsers(env, user);
  if (path === '/api/users' && method === 'POST') return createStaffUser(request, env, user);
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
  if (userMatch && method === 'DELETE') return deleteStaffUser(env, user, userMatch[1]);
  const noteMatch = path.match(/^\/api\/tickets\/([\w-]+)\/notes$/);
  if (noteMatch && method === 'POST') return addSupportNote(request, env, user, noteMatch[1]);
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

function randomHex(size = 32) {
  return Array.from(crypto.getRandomValues(new Uint8Array(size)), byte => byte.toString(16).padStart(2, '0')).join('');
}

function fromHex(value) {
  return Uint8Array.from(value.match(/.{2}/g) || [], pair => Number.parseInt(pair, 16));
}

function sameSecret(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function validPassword(value) {
  return typeof value === 'string' && value.length >= 12 && value.length <= 128 && !/[\u0000-\u001f\u007f]/.test(value);
}

async function derivePassword(password, saltHex) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: fromHex(saltHex), iterations: PASSWORD_ITERATIONS, hash: 'SHA-256' },
    key,
    256
  );
  return Array.from(new Uint8Array(bits), byte => byte.toString(16).padStart(2, '0')).join('');
}

function cookieValue(request, name) {
  const cookies = request.headers.get('Cookie') || '';
  const match = cookies.split(';').map(part => part.trim()).find(part => part.startsWith(`${name}=`));
  return match ? match.slice(name.length + 1) : '';
}

function sessionCookieName(request) {
  return new URL(request.url).protocol === 'https:' ? '__Host-axium_session' : 'axium_session';
}

function sessionCookie(request, token, maxAge = SESSION_SECONDS) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `${sessionCookieName(request)}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

async function createSession(request, env, user) {
  const token = randomHex();
  const csrfToken = randomHex(24);
  const expiresAt = new Date(Date.now() + SESSION_SECONDS * 1000).toISOString();
  await env.DB.prepare(
    'INSERT INTO staff_sessions (session_hash, staff_user_id, csrf_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(await sha256(token), user.id, await sha256(csrfToken), expiresAt, now()).run();
  return respond({
    user: { id: user.id, username: user.username, email: user.contact_email || null, role: user.role },
    csrfToken,
    mustChangePassword: Boolean(user.must_change_password)
  }, 200, { 'Set-Cookie': sessionCookie(request, token) });
}

async function authenticatedUser(request, env) {
  const token = cookieValue(request, sessionCookieName(request)) || cookieValue(request, 'axium_session');
  if (!token) fail(401, 'Sign in with your staff username and password.');
  const user = await env.DB.prepare(
      `SELECT u.id, u.username, u.contact_email, u.role, u.status, u.must_change_password,
        u.password_salt, u.password_hash, s.session_hash, s.csrf_hash
     FROM staff_sessions s JOIN staff_users u ON u.id = s.staff_user_id
     WHERE s.session_hash = ? AND s.expires_at > ? AND u.status = 'ACTIVE' AND u.deleted_at IS NULL`
  ).bind(await sha256(token), now()).first();
  if (!user) fail(401, 'Staff session expired. Sign in again.');
  return user;
}

async function requireCsrf(request, user) {
  const token = request.headers.get('X-CSRF-Token') || '';
  if (!token || !sameSecret(await sha256(token), user.csrf_hash)) fail(403, 'Session verification failed. Refresh and try again.');
}

function staffInput(body) {
  const username = text(body.username, 40);
  const email = text(body.email, 254).toLowerCase() || null;
  if (!/^[a-zA-Z0-9._-]{2,40}$/.test(username)) fail(400, 'Username must be 2-40 letters, numbers, dots, underscores, or hyphens.');
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail(400, 'Email address is invalid.');
  if (!validPassword(body.password)) fail(400, 'Password must be 12-128 characters with no control characters.');
  return { username, email, password: body.password };
}

function internalEmail(userId) {
  return `staff-${userId}@accounts.invalid`;
}

async function setupStatus(env) {
  const admin = await env.DB.prepare(
    `SELECT id FROM staff_users WHERE role = 'SUPER ADMIN' AND status = 'ACTIVE'
      AND deleted_at IS NULL AND password_hash IS NOT NULL LIMIT 1`
  ).first();
  return respond({ setupRequired: !admin, setupConfigured: Boolean(env.BOOTSTRAP_SECRET) });
}

async function bootstrapAdmin(request, env) {
  if (!env.BOOTSTRAP_SECRET || env.BOOTSTRAP_SECRET.length < 32) fail(503, 'First-admin setup secret is not configured.');
  const body = await readJson(request);
  if (!sameSecret(body.setupSecret, env.BOOTSTRAP_SECRET)) fail(403, 'First-admin setup secret is invalid.');
  const { username, email, password } = staffInput(body);
  const existingAdmin = await env.DB.prepare(
    `SELECT id FROM staff_users WHERE role = 'SUPER ADMIN' AND status = 'ACTIVE'
      AND deleted_at IS NULL AND password_hash IS NOT NULL LIMIT 1`
  ).first();
  if (existingAdmin) fail(409, 'First-admin setup is already complete.');

  const salt = randomHex(16);
  const passwordHash = await derivePassword(password, salt);
  const existingRecord = await env.DB.prepare(
    `SELECT id FROM staff_users WHERE role = 'SUPER ADMIN' AND status = 'ACTIVE'
      AND deleted_at IS NULL ORDER BY created_at LIMIT 1`
  ).first();
  let adminId;
  if (existingRecord) {
    adminId = existingRecord.id;
    const result = await env.DB.prepare(
      `UPDATE staff_users SET username = ?, email = ?, contact_email = ?, password_salt = ?, password_hash = ?,
              must_change_password = 0, updated_at = ? WHERE id = ? AND password_hash IS NULL AND deleted_at IS NULL`
    ).bind(username, email || internalEmail(adminId), email, salt, passwordHash, now(), adminId).run();
    if (!result.meta.changes) fail(409, 'First-admin setup was already completed.');
  } else {
    adminId = id();
    const result = await env.DB.prepare(
      `INSERT INTO staff_users (id, username, email, contact_email, role, status, password_salt, password_hash, must_change_password, created_at, updated_at)
       SELECT ?, ?, ?, ?, 'SUPER ADMIN', 'ACTIVE', ?, ?, 0, ?, ?
       WHERE NOT EXISTS (
         SELECT 1 FROM staff_users WHERE role = 'SUPER ADMIN' AND status = 'ACTIVE'
           AND deleted_at IS NULL AND password_hash IS NOT NULL
       )`
    ).bind(adminId, username, email || internalEmail(adminId), email, salt, passwordHash, now(), now()).run();
    if (!result.meta.changes) fail(409, 'First-admin setup was already completed.');
  }
  await audit(env, adminId, 'staff.bootstrap_completed', 'staff_user', adminId);
  const admin = await env.DB.prepare(
    'SELECT id, username, contact_email, role, must_change_password FROM staff_users WHERE id = ?'
  ).bind(adminId).first();
  return createSession(request, env, admin);
}

async function recordLoginFailure(env, attemptKey) {
  const timestamp = Date.now();
  const current = await env.DB.prepare('SELECT failure_count, window_started_at, locked_until FROM login_attempts WHERE attempt_key = ?')
    .bind(attemptKey).first();
  const windowMs = 15 * 60 * 1000;
  const freshWindow = !current || timestamp - Date.parse(current.window_started_at) >= windowMs;
  const failureCount = freshWindow ? 1 : current.failure_count + 1;
  const windowStartedAt = freshWindow ? new Date(timestamp).toISOString() : current.window_started_at;
  const lockedUntil = failureCount >= 5 ? new Date(timestamp + windowMs).toISOString() : null;
  await env.DB.prepare(
    `INSERT INTO login_attempts (attempt_key, failure_count, window_started_at, locked_until, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(attempt_key) DO UPDATE SET failure_count = excluded.failure_count,
       window_started_at = excluded.window_started_at, locked_until = excluded.locked_until, updated_at = excluded.updated_at`
  ).bind(attemptKey, failureCount, windowStartedAt, lockedUntil, now()).run();
}

async function login(request, env) {
  const body = await readJson(request);
  const username = text(body.username, 40);
  const password = typeof body.password === 'string' ? body.password : '';
  if (!username || password.length > 128) fail(400, 'Enter a valid username and password.');
  const clientAddress = request.headers.get('CF-Connecting-IP') || 'unknown';
  const attemptKey = await sha256(`${clientAddress}\n${username.toLowerCase()}`);
  const attempt = await env.DB.prepare('SELECT locked_until FROM login_attempts WHERE attempt_key = ?').bind(attemptKey).first();
  if (attempt?.locked_until && Date.parse(attempt.locked_until) > Date.now()) fail(429, 'Too many failed attempts. Try again in 15 minutes.');

  const user = await env.DB.prepare(
    `SELECT id, username, contact_email, role, status, password_salt, password_hash, must_change_password
     FROM staff_users WHERE username = ? COLLATE NOCASE AND deleted_at IS NULL`
  ).bind(username).first();
  const candidatePassword = password.length <= 128 ? password : 'invalid-password-input';
  const candidateHash = await derivePassword(candidatePassword, user?.password_salt || '00000000000000000000000000000000');
  const valid = user && user.status === 'ACTIVE' && user.password_hash && sameSecret(candidateHash, user.password_hash) && validPassword(password);
  if (!valid) {
    await recordLoginFailure(env, attemptKey);
    fail(401, 'Username or password is incorrect.');
  }

  await env.DB.prepare('DELETE FROM login_attempts WHERE attempt_key = ?').bind(attemptKey).run();
  return createSession(request, env, user);
}

async function currentSession(request, env, user) {
  const csrfToken = randomHex(24);
  await env.DB.prepare('UPDATE staff_sessions SET csrf_hash = ? WHERE session_hash = ?')
    .bind(await sha256(csrfToken), user.session_hash).run();
  return respond({
    user: { id: user.id, username: user.username, email: user.contact_email || null, role: user.role },
    csrfToken,
    mustChangePassword: Boolean(user.must_change_password)
  });
}

async function changePassword(request, env, user) {
  const body = await readJson(request);
  if (!validPassword(body.newPassword)) fail(400, 'New password must be 12-128 characters with no control characters.');
  const currentHash = await derivePassword(String(body.currentPassword || ''), user.password_salt || '00000000000000000000000000000000');
  if (!user.password_hash || !sameSecret(currentHash, user.password_hash)) fail(401, 'Current password is incorrect.');
  const salt = randomHex(16);
  const passwordHash = await derivePassword(body.newPassword, salt);
  await env.DB.prepare(
    'UPDATE staff_users SET password_salt = ?, password_hash = ?, must_change_password = 0, updated_at = ? WHERE id = ?'
  ).bind(salt, passwordHash, now(), user.id).run();
  await env.DB.prepare('DELETE FROM staff_sessions WHERE staff_user_id = ? AND session_hash <> ?')
    .bind(user.id, user.session_hash).run();
  await audit(env, user.id, 'staff.password_changed', 'staff_user', user.id);
  return respond({ ok: true });
}

async function logout(request, env, user) {
  await env.DB.prepare('DELETE FROM staff_sessions WHERE session_hash = ?').bind(user.session_hash).run();
  return respond({ ok: true }, 200, { 'Set-Cookie': sessionCookie(request, '', 0) });
}

async function createStaffUser(request, env, admin) {
  requireRole(admin, ['SUPER ADMIN']);
  const body = await readJson(request);
  const { username, email, password } = staffInput(body);
  const role = text(body.role, 32);
  if (!ROLES.has(role)) fail(400, 'Select a valid staff role.');
  const userId = id();
  const salt = randomHex(16);
  const passwordHash = await derivePassword(password, salt);
  try {
    await env.DB.prepare(
      `INSERT INTO staff_users (id, username, email, contact_email, role, status, password_salt, password_hash, must_change_password, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, 1, ?, ?)`
    ).bind(userId, username, internalEmail(userId), email, role, salt, passwordHash, now(), now()).run();
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) fail(409, 'That username is already in use.');
    throw error;
  }
  await audit(env, admin.id, 'staff.created', 'staff_user', userId, { role });
  let emailSent = false;
  if (email && env.RESEND_API_KEY && env.FROM_EMAIL) {
    try {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: env.FROM_EMAIL,
          to: [email],
          subject: 'Axium Cyber staff account created',
          text: `A staff account was created for ${username}. Sign in at ${new URL('/staff.html', request.url).href}. Your administrator will provide the temporary password through a separate secure channel. You must change it at first sign-in.`
        })
      });
      emailSent = response.ok;
    } catch {
      emailSent = false;
    }
  }
  return respond({ id: userId, emailSent, mustChangePassword: true }, 201);
}

async function deleteStaffUser(env, admin, userId) {
  requireRole(admin, ['SUPER ADMIN']);
  if (admin.id === userId) fail(400, 'You cannot delete your own signed-in account.');
  const deletedAt = now();
  const result = await env.DB.prepare(
    `UPDATE staff_users SET username = ?, email = ?, contact_email = NULL, role = 'TEAM MEMBER', status = 'SUSPENDED',
            password_salt = NULL, password_hash = NULL, must_change_password = 1, invite_token_hash = NULL,
            invite_expires_at = NULL, deleted_at = ?, updated_at = ?
     WHERE id = ? AND deleted_at IS NULL AND
       (role <> 'SUPER ADMIN' OR status <> 'ACTIVE' OR
        (SELECT COUNT(*) FROM staff_users WHERE role = 'SUPER ADMIN' AND status = 'ACTIVE' AND deleted_at IS NULL) > 1)`
  ).bind(`deleted-${userId.slice(0, 8)}`, `deleted-${userId}@accounts.invalid`, deletedAt, deletedAt, userId).run();
  if (!result.meta.changes) fail(409, 'Account cannot be deleted. It may be missing, already deleted, or the last active Super Admin.');
  await env.DB.prepare('DELETE FROM staff_sessions WHERE staff_user_id = ?').bind(userId).run();
  await audit(env, admin.id, 'staff.deleted', 'staff_user', userId);
  return respond({ ok: true, deletedAt });
}