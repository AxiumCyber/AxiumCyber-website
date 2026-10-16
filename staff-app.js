const byId = id => document.getElementById(id);
const loginView = byId('loginView');
const appView = byId('appView');
const enterButton = byId('enterDashboard');
const roleBadge = byId('roleBadge');
const roleNames = ['SUPER ADMIN', 'SUPPORT', 'TECHNICAL TEAM', 'MODERATOR', 'TEAM MEMBER', 'FORENSIC ANALYST'];
let staff = null;
let customers = [];
let tickets = [];
let activeView = 'overview';
let csrfToken = '';

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function toast(message) {
  const element = document.createElement('div');
  element.className = 'toast';
  element.textContent = message;
  document.body.append(element);
  setTimeout(() => element.remove(), 3500);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');
  if (options.body !== undefined) headers.set('Content-Type', 'application/json');
  const method = String(options.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken) headers.set('X-CSRF-Token', csrfToken);
  const response = await fetch(path, { credentials: 'same-origin', ...options, headers });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
  return result;
}

function setAccessProgress(value) {
  byId('accessProgress').style.width = `${value}%`;
  document.querySelector('.access-progress').setAttribute('aria-valuenow', String(value));
}

function setNavigation() {
  const role = staff.role;
  const admin = role === 'SUPER ADMIN';
  const support = role === 'SUPPORT';
  const technical = role === 'TECHNICAL TEAM';
  const forensic = role === 'FORENSIC ANALYST';
  byId('customersNav').classList.toggle('hidden', !admin && !support);
  byId('labNav').classList.toggle('hidden', !admin && !technical);
  byId('engagementsNav').classList.toggle('hidden', !admin && !technical);
  byId('forensicsNav').classList.toggle('hidden', !admin && !forensic);
  byId('teamNav').classList.toggle('hidden', !admin);
  byId('auditNav').classList.toggle('hidden', !admin);
  byId('newUserButton').classList.toggle('hidden', !admin);
  byId('customerForm').classList.toggle('hidden', !admin && !support);
}

function canOpen(view) {
  const role = staff.role;
  return view === 'overview' || view === 'queue' ||
    (view === 'customers' && ['SUPER ADMIN', 'SUPPORT'].includes(role)) ||
    (view === 'lab' && ['SUPER ADMIN', 'TECHNICAL TEAM'].includes(role)) ||
    (view === 'engagements' && ['SUPER ADMIN', 'TECHNICAL TEAM'].includes(role)) ||
    (view === 'forensics' && ['SUPER ADMIN', 'FORENSIC ANALYST'].includes(role)) ||
    (view === 'team' && role === 'SUPER ADMIN') || (view === 'audit' && role === 'SUPER ADMIN');
}

function showView(name, refresh = true) {
  if (!canOpen(name)) {
    toast('Your staff role cannot access that workspace.');
    return;
  }
  activeView = name;
  document.querySelectorAll('.view').forEach(section => section.classList.toggle('active', section.id === `view-${name}`));
  document.querySelectorAll('.nav-item').forEach(button => button.classList.toggle('active', button.dataset.view === name));
  if (refresh) loadView(name).catch(error => toast(error.message));
}

function ticketRow(ticket) {
  const status = escapeHtml(ticket.status);
  const priorityClass = ticket.priority === 'URGENT' ? 'urgent' : ['HIGH', 'NORMAL'].includes(ticket.priority) ? 'waiting' : 'open';
  const action = ticket.status === 'CLOSED' ? 'Reopen' : 'Resolve';
  return `<tr><td class="ticket-id">${escapeHtml(ticket.id.slice(0, 8))}</td><td><div class="ticket-name">${escapeHtml(ticket.customer_name)}</div><div class="ticket-type">${escapeHtml(ticket.subject)}</div></td><td>${escapeHtml(ticket.category)}</td><td><span class="pill ${priorityClass}">${escapeHtml(ticket.priority)}</span></td><td>${escapeHtml(ticket.assigned_role)}</td><td><span class="pill ${ticket.status.toLowerCase()}">${status}</span></td><td><button class="button small ticket-action" data-id="${escapeHtml(ticket.id)}" aria-label="${action} ticket">${action}</button></td></tr>`;
}

function renderTickets() {
  const query = byId('ticketSearch').value.trim().toLowerCase();
  const statusFilter = byId('ticketFilter').value;
  const shown = tickets.filter(ticket => (statusFilter === 'ALL' || ticket.status === statusFilter) &&
    Object.values(ticket).join(' ').toLowerCase().includes(query));
  byId('ticketRows').innerHTML = shown.length ? shown.map(ticketRow).join('') : '<tr><td colspan="7" class="empty-state">No matching support tickets.</td></tr>';
  byId('queueCount').textContent = `${shown.length} RECORDS`;
  byId('shownCount').textContent = String(shown.length);
  const open = tickets.filter(ticket => ticket.status !== 'CLOSED');
  byId('openCount').textContent = String(open.length);
  byId('priorityCount').textContent = String(open.filter(ticket => ['URGENT', 'HIGH'].includes(ticket.priority)).length);
  const priority = open.filter(ticket => ['URGENT', 'HIGH'].includes(ticket.priority)).slice(0, 4);
  byId('overviewTickets').innerHTML = priority.length ? priority.map(ticket =>
    `<tr><td class="ticket-id">${escapeHtml(ticket.id.slice(0, 8))}</td><td><div class="ticket-name">${escapeHtml(ticket.customer_name)}</div><div class="ticket-type">${escapeHtml(ticket.subject)}</div></td><td><span class="pill ${ticket.priority === 'URGENT' ? 'urgent' : 'waiting'}">${escapeHtml(ticket.priority)}</span></td><td>${escapeHtml(ticket.assigned_role)}</td><td><span class="pill ${ticket.status.toLowerCase()}">${escapeHtml(ticket.status)}</span></td></tr>`
  ).join('') : '<tr><td colspan="5" class="empty-state">No priority tickets.</td></tr>';
}

function renderCustomers() {
  const query = byId('customerSearch').value.trim().toLowerCase();
  const shown = customers.filter(customer => Object.values(customer).join(' ').toLowerCase().includes(query));
  byId('customerRows').innerHTML = shown.length ? shown.map(customer =>
    `<tr><td class="ticket-name">${escapeHtml(customer.display_name)}</td><td>${escapeHtml(customer.email)}</td><td>${escapeHtml(customer.organization || '—')}</td><td>${escapeHtml(customer.contact_preference)}</td><td>${escapeHtml(new Date(customer.created_at).toLocaleDateString())}</td></tr>`
  ).join('') : '<tr><td colspan="5" class="empty-state">No customer records found.</td></tr>';
  byId('customerRecordCount').textContent = `${shown.length} RECORDS`;
  byId('customerCount').textContent = String(customers.length);
  byId('engagementCustomer').innerHTML = customers.map(customer => `<option value="${escapeHtml(customer.id)}">${escapeHtml(customer.display_name)} · ${escapeHtml(customer.organization)}</option>`).join('');
}

function renderUsers(users) {
  byId('userRows').innerHTML = users.length ? users.map(user =>
    `<tr><td class="ticket-name">${escapeHtml(user.username)}</td><td>${escapeHtml(user.email || '—')}</td><td><select class="role-switch staff-role" data-id="${escapeHtml(user.id)}" aria-label="Role for ${escapeHtml(user.username)}">${roleNames.map(role => `<option ${user.role === role ? 'selected' : ''}>${role}</option>`).join('')}</select></td><td><span class="pill ${user.status === 'ACTIVE' ? 'open' : 'waiting'}">${escapeHtml(user.status)}</span></td><td><button class="button small warn delete-user" data-id="${escapeHtml(user.id)}">Delete</button></td></tr>`
  ).join('') : '<tr><td colspan="5" class="empty-state">No staff records.</td></tr>';
}

function renderEngagements(engagements) {
  byId('engagementRows').innerHTML = engagements.length ? engagements.map(engagement => {
    const canApprove = staff.role === 'SUPER ADMIN' && engagement.status === 'DRAFT' && engagement.created_by !== staff.id;
    const scope = JSON.parse(engagement.scope_json || '[]').join(', ');
    return `<tr><td>${escapeHtml(engagement.title)}</td><td>${escapeHtml(engagement.customer_name)}</td><td>${escapeHtml(scope)}</td><td>${escapeHtml(new Date(engagement.expires_at).toLocaleString())}</td><td><span class="pill ${engagement.status === 'APPROVED' ? 'open' : 'waiting'}">${escapeHtml(engagement.status)}</span></td><td>${canApprove ? `<button class="button small approve-engagement" data-id="${escapeHtml(engagement.id)}">Approve</button>` : '—'}</td></tr>`;
  }).join('') : '<tr><td colspan="6" class="empty-state">No security engagements.</td></tr>';
}

function renderCases(cases) {
  byId('caseRows').innerHTML = cases.length ? cases.map(record =>
    `<tr><td class="ticket-id">${escapeHtml(record.case_number)}</td><td>${escapeHtml(record.title)}</td><td>${escapeHtml(record.authority_name)}</td><td>${escapeHtml(new Date(record.expires_at).toLocaleString())}</td><td><span class="pill ${record.status === 'OPEN' ? 'open' : 'closed'}">${escapeHtml(record.status)}</span></td></tr>`
  ).join('') : '<tr><td colspan="5" class="empty-state">No forensic case records.</td></tr>';
}

function renderAudit(events) {
  byId('auditRows').innerHTML = events.length ? events.map(event =>
    `<div class="audit-row"><time>${escapeHtml(new Date(event.created_at).toLocaleString())}</time><b>${escapeHtml(event.actor || 'SYSTEM')}</b><span>${escapeHtml(event.action)} · ${escapeHtml(event.object_type)}</span></div>`
  ).join('') : '<div class="empty-state">No audit events.</div>';
  byId('activityFeed').innerHTML = events.slice(0, 5).map(event =>
    `<div class="activity"><span class="activity-icon">LOG</span><div><p>${escapeHtml(event.action)}</p><small>${escapeHtml(new Date(event.created_at).toLocaleString())} / ${escapeHtml(event.actor || 'SYSTEM')}</small></div></div>`
  ).join('') || '<div class="empty-state">No activity recorded.</div>';
}

async function loadTickets() {
  if (staff.role === 'FORENSIC ANALYST') {
    tickets = [];
    renderTickets();
    return;
  }
  const result = await api('/api/tickets');
  tickets = result.tickets;
  renderTickets();
}

async function loadCustomers() {
  if (!['SUPER ADMIN', 'SUPPORT'].includes(staff.role)) return;
  const result = await api('/api/customers');
  customers = result.customers;
  renderCustomers();
}

async function loadView(name) {
  if (name === 'overview' || name === 'queue') await loadTickets();
  if (name === 'customers') await loadCustomers();
  if (name === 'team') renderUsers((await api('/api/users')).users);
  if (name === 'engagements') {
    const [customersResult, engagementsResult] = await Promise.all([
      api('/api/engagement-customers'), api('/api/engagements')
    ]);
    customers = customersResult.customers;
    byId('engagementCustomer').innerHTML = customers.map(customer => `<option value="${escapeHtml(customer.id)}">${escapeHtml(customer.display_name)}${customer.organization ? ` · ${escapeHtml(customer.organization)}` : ''}</option>`).join('');
    renderEngagements(engagementsResult.engagements);
  }
  if (name === 'forensics') renderCases((await api('/api/forensics/cases')).cases);
  if (name === 'audit') renderAudit((await api('/api/audit')).events);
}

async function openDashboard() {
  if (!staff || !roleNames.includes(staff.role)) throw new Error('Staff role is not configured. Contact your Super Admin.');
  setNavigation();
  byId('roleBadge').textContent = staff.role;
  byId('staffGreeting').textContent = staff.username;
  byId('serviceStatus').textContent = 'CONNECTED';
  byId('serviceNote').textContent = 'Staff session verified';
  const initialLoads = [loadTickets()];
  if (['SUPER ADMIN', 'SUPPORT'].includes(staff.role)) initialLoads.push(loadCustomers());
  if (staff.role === 'SUPER ADMIN') {
    initialLoads.push(api('/api/audit').then(({ events }) => renderAudit(events)));
  } else {
    renderAudit([]);
  }
  await Promise.all(initialLoads);
  byId('accessProgress').style.width = '100%';
  document.querySelector('.access-progress').setAttribute('aria-valuenow', '100');
  byId('accessMessage').className = 'access-message granted';
  byId('accessMessage').innerHTML = '<span class="access-check" aria-hidden="true">✓</span>Access granted';
  setTimeout(() => {
    loginView.classList.add('hidden');
    appView.classList.remove('hidden');
    showView('overview', false);
  }, 350);
}

function showPasswordChange(currentPassword = '') {
  byId('loginForm').classList.add('hidden');
  byId('setupForm').classList.add('hidden');
  byId('changePasswordForm').classList.remove('hidden');
  byId('loginTitle').textContent = 'Change temporary password';
  byId('loginDescription').textContent = 'Set a new password before entering the dashboard.';
  byId('currentPassword').value = currentPassword;
  byId('loginPassword').value = '';
  byId('accessMessage').className = 'access-message granted';
  byId('accessMessage').textContent = 'Your Super Admin requires a password change at first sign-in.';
  setAccessProgress(100);
}

async function enterDashboard(event) {
  event?.preventDefault();
  const message = byId('accessMessage');
  message.className = 'access-message';
  message.textContent = 'Verifying staff credentials…';
  setAccessProgress(24);
  enterButton.disabled = true;
  try {
    if (staff && csrfToken) {
      await openDashboard();
      return;
    }
    const result = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: byId('loginUsername').value, password: byId('loginPassword').value })
    });
    staff = result.user;
    csrfToken = result.csrfToken;
    setAccessProgress(72);
    byId('currentPassword').value = '';
    byId('replacementPassword').value = '';
    byId('confirmPassword').value = '';
    if (result.mustChangePassword) {
      showPasswordChange(byId('loginPassword').value);
      return;
    }
    byId('loginPassword').value = '';
    await openDashboard();
  } catch (error) {
    setAccessProgress(100);
    message.className = 'access-message denied';
    message.textContent = error.message;
    byId('serviceStatus').textContent = 'UNAVAILABLE';
    byId('serviceNote').textContent = 'Sign-in was not completed';
  } finally {
    enterButton.disabled = false;
  }
}

async function bootstrapAdmin(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  byId('accessMessage').textContent = 'Creating the first Super Admin…';
  setAccessProgress(35);
  try {
    const result = await api('/api/bootstrap', { method: 'POST', body: JSON.stringify({
      setupSecret: byId('setupSecret').value,
      username: byId('setupUsername').value,
      password: byId('setupPassword').value,
      email: byId('setupEmail').value
    }) });
    staff = result.user;
    csrfToken = result.csrfToken;
    byId('setupForm').reset();
    await openDashboard();
  } catch (error) {
    byId('accessMessage').className = 'access-message denied';
    byId('accessMessage').textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function initializeSignIn() {
  try {
    const setup = await api('/api/setup/status');
    if (setup.setupRequired) {
      byId('loginForm').classList.add('hidden');
      byId('setupForm').classList.remove('hidden');
      byId('loginTitle').textContent = 'Initial Super Admin setup';
      byId('loginDescription').textContent = setup.setupConfigured ? 'Create the first administrator account.' : 'Configure the BOOTSTRAP_SECRET Pages secret before setup.';
      byId('setupForm').querySelector('button[type="submit"]').disabled = !setup.setupConfigured;
      return;
    }
    try {
      const session = await api('/api/me');
      staff = session.user;
      csrfToken = session.csrfToken;
      if (session.mustChangePassword) showPasswordChange();
      else await openDashboard();
    } catch {
      byId('loginForm').classList.remove('hidden');
    }
  } catch (error) {
    byId('accessMessage').className = 'access-message denied';
    byId('accessMessage').textContent = error.message;
  }
}

document.querySelectorAll('.nav-item').forEach(button => button.addEventListener('click', () => showView(button.dataset.view)));
document.querySelectorAll('[data-goto]').forEach(button => button.addEventListener('click', () => showView(button.dataset.goto)));
byId('loginForm').addEventListener('submit', enterDashboard);
byId('setupForm').addEventListener('submit', bootstrapAdmin);
byId('changePasswordForm').addEventListener('submit', async event => {
  event.preventDefault();
  const nextPassword = byId('replacementPassword').value;
  if (nextPassword !== byId('confirmPassword').value) {
    toast('New passwords do not match.');
    return;
  }
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    await api('/api/auth/change-password', { method: 'POST', body: JSON.stringify({
      currentPassword: byId('currentPassword').value,
      newPassword: nextPassword
    }) });
    byId('currentPassword').value = '';
    byId('replacementPassword').value = '';
    byId('confirmPassword').value = '';
    await openDashboard();
  } catch (error) {
    byId('accessMessage').className = 'access-message denied';
    byId('accessMessage').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
byId('signOut').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST', body: '{}' }); }
  finally { location.reload(); }
});
byId('ticketSearch').addEventListener('input', renderTickets);
byId('ticketFilter').addEventListener('change', renderTickets);
byId('customerSearch').addEventListener('input', renderCustomers);

byId('ticketRows').addEventListener('click', async event => {
  const button = event.target.closest('.ticket-action');
  if (!button) return;
  const ticket = tickets.find(item => item.id === button.dataset.id);
  if (!ticket) return;
  try {
    await api(`/api/tickets/${encodeURIComponent(ticket.id)}`, {
      method: 'PATCH', body: JSON.stringify({ status: ticket.status === 'CLOSED' ? 'OPEN' : 'CLOSED' })
    });
    await loadTickets();
    toast('Ticket status updated.');
  } catch (error) { toast(error.message); }
});

byId('customerForm').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await api('/api/customers', { method: 'POST', body: JSON.stringify({
      displayName: byId('customerName').value,
      email: byId('customerEmail').value,
      organization: byId('customerOrganization').value,
      contactPreference: byId('contactPreference').value,
      contactConsent: byId('contactConsent').checked
    }) });
    event.currentTarget.reset();
    await loadCustomers();
    toast('Customer saved to the database.');
  } catch (error) { toast(error.message); }
});

const modal = byId('userModal');
function closeModal() { modal.classList.remove('open'); }
byId('newUserButton').addEventListener('click', () => modal.classList.add('open'));
byId('closeModal').addEventListener('click', closeModal);
byId('cancelModal').addEventListener('click', closeModal);
modal.addEventListener('click', event => { if (event.target === modal) closeModal(); });
document.addEventListener('keydown', event => { if (event.key === 'Escape') closeModal(); });
byId('userForm').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const result = await api('/api/users', { method: 'POST', body: JSON.stringify({
      username: byId('newUsername').value,
      password: byId('newPassword').value,
      email: byId('newEmail').value,
      role: byId('newRole').value
    }) });
    event.currentTarget.reset();
    closeModal();
    if (activeView === 'team') await loadView('team');
    toast(result.emailSent ? 'Account created. A notice was emailed; share the temporary password separately.' : 'Account created. Share the temporary password through a separate secure channel.');
  } catch (error) { toast(error.message); }
});
byId('userRows').addEventListener('change', async event => {
  const select = event.target.closest('.staff-role');
  if (!select) return;
  try {
    await api(`/api/users/${encodeURIComponent(select.dataset.id)}`, {
      method: 'PATCH', body: JSON.stringify({ role: select.value })
    });
    toast('Staff role updated.');
  } catch (error) {
    toast(error.message);
    await loadView('team');
  }
});
byId('userRows').addEventListener('click', async event => {
  const button = event.target.closest('.delete-user');
  if (!button || !confirm('Delete this staff account? Its sessions will be revoked and personal account details anonymized.')) return;
  try {
    await api(`/api/users/${encodeURIComponent(button.dataset.id)}`, { method: 'DELETE', body: '{}' });
    await loadView('team');
    toast('Staff account deleted. Audit and record references are retained.');
  } catch (error) { toast(error.message); }
});

byId('engagementForm').addEventListener('submit', async event => {
  event.preventDefault();
  const categories = [...document.querySelectorAll('input[name="testCategory"]:checked')].map(input => input.value);
  try {
    await api('/api/engagements', { method: 'POST', body: JSON.stringify({
      customerId: byId('engagementCustomer').value,
      title: byId('engagementTitle').value,
      startsAt: new Date(byId('engagementStart').value).toISOString(),
      expiresAt: new Date(byId('engagementExpiry').value).toISOString(),
      authorizationReference: byId('engagementReference').value,
      scope: byId('engagementScope').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean),
      categories
    }) });
    event.currentTarget.reset();
    await loadView('engagements');
    toast('Authorization draft saved. A second Super Admin must approve it.');
  } catch (error) { toast(error.message); }
});

byId('engagementRows').addEventListener('click', async event => {
  const button = event.target.closest('.approve-engagement');
  if (!button) return;
  try {
    await api(`/api/engagements/${encodeURIComponent(button.dataset.id)}/approve`, { method: 'POST', body: '{}' });
    await loadView('engagements');
    toast('Engagement approved. Test execution remains disabled.');
  } catch (error) { toast(error.message); }
});

byId('caseForm').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await api('/api/forensics/cases', { method: 'POST', body: JSON.stringify({
      caseNumber: byId('caseNumber').value,
      title: byId('caseTitle').value,
      authorityName: byId('authorityName').value,
      authorityReference: byId('authorityReference').value,
      purpose: byId('casePurpose').value,
      expiresAt: new Date(byId('caseExpiry').value).toISOString()
    }) });
    event.currentTarget.reset();
    await loadView('forensics');
    toast('Forensic case record created.');
  } catch (error) { toast(error.message); }
});

byId('scopeCheck').addEventListener('click', () => {
  const host = byId('scopeTarget').value.trim().toLowerCase().replace(/\.$/, '');
  const roots = byId('scopeList').value.split(',').map(value => value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].replace(/\.$/, '')).filter(Boolean);
  const valid = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host);
  const inScope = valid && roots.some(root => host === root || host.endsWith(`.${root}`));
  byId('scopeOutput').textContent = inScope ? `IN SCOPE: ${host}. Text comparison only; no network request.` : `${valid ? 'OUT OF SCOPE' : 'INVALID HOSTNAME'}: ${host || 'no hostname supplied'}. No network request.`;
});

byId('headerCheck').addEventListener('click', () => {
  const source = byId('headerInput').value;
  const checks = [
    ['Strict-Transport-Security', /strict-transport-security\s*:/i],
    ['Content-Security-Policy', /content-security-policy\s*:/i],
    ['X-Content-Type-Options: nosniff', /x-content-type-options\s*:\s*nosniff/i],
    ['Referrer-Policy', /referrer-policy\s*:/i],
    ['Permissions-Policy', /permissions-policy\s*:/i]
  ];
  byId('headerOutput').textContent = source.trim() ? checks.map(([name, pattern]) => `${pattern.test(source) ? 'FOUND' : 'REVIEW'} ${name}`).join('\n') : 'Paste response headers first.';
});

byId('logCheck').addEventListener('click', () => {
  const lines = byId('logInput').value.split(/\r?\n/).filter(Boolean);
  const counts = Object.fromEntries(['ERROR', 'WARN', 'INFO', 'DEBUG'].map(level => [level, lines.filter(line => new RegExp(`\\b${level}\\b`, 'i').test(line)).length]));
  const errors = lines.filter(line => /\b(error|fatal|exception)\b/i.test(line)).slice(0, 5);
  byId('logOutput').textContent = lines.length ? `LINES ${lines.length} | ERROR ${counts.ERROR} | WARN ${counts.WARN} | INFO ${counts.INFO} | DEBUG ${counts.DEBUG}\n\n${errors.join('\n') || 'No obvious error labels found.'}` : 'Paste sanitized log lines first.';
});

byId('saveNotes').addEventListener('click', () => {
  byId('notesOutput').textContent = byId('debugNotes').value.trim() ? 'Notes remain in this tab only; nothing was uploaded.' : 'No notes to save.';
});
document.querySelectorAll('[data-clear]').forEach(button => button.addEventListener('click', () => { byId(button.dataset.clear).value = ''; }));

document.getElementById('serviceStatus').textContent = 'READY';
document.getElementById('serviceNote').textContent = 'Sign in to verify your staff account';
initializeSignIn();