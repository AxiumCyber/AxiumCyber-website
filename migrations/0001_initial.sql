CREATE TABLE staff_users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  role TEXT NOT NULL CHECK (role IN ('SUPER ADMIN', 'SUPPORT', 'TECHNICAL TEAM', 'MODERATOR', 'TEAM MEMBER', 'FORENSIC ANALYST')),
  status TEXT NOT NULL DEFAULT 'INVITED' CHECK (status IN ('INVITED', 'ACTIVE', 'SUSPENDED')),
  invite_token_hash TEXT,
  invite_expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE customers (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  email TEXT NOT NULL COLLATE NOCASE,
  organization TEXT NOT NULL DEFAULT '',
  contact_preference TEXT NOT NULL DEFAULT 'EMAIL' CHECK (contact_preference IN ('EMAIL', 'PHONE', 'NO_CONTACT')),
  contact_consent_at TEXT,
  created_by TEXT NOT NULL REFERENCES staff_users(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX customers_email_idx ON customers(email);
CREATE INDEX customers_org_idx ON customers(organization);

CREATE TABLE support_tickets (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE RESTRICT,
  subject TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'NORMAL' CHECK (priority IN ('LOW', 'NORMAL', 'HIGH', 'URGENT')),
  status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'WAITING', 'CLOSED')),
  assigned_role TEXT NOT NULL DEFAULT 'SUPPORT' CHECK (assigned_role IN ('SUPPORT', 'TECHNICAL TEAM', 'MODERATOR', 'TEAM MEMBER')),
  created_by TEXT NOT NULL REFERENCES staff_users(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX support_tickets_customer_idx ON support_tickets(customer_id, created_at DESC);
CREATE INDEX support_tickets_lane_idx ON support_tickets(assigned_role, status, priority);

CREATE TABLE support_notes (
  id TEXT PRIMARY KEY,
  ticket_id TEXT NOT NULL REFERENCES support_tickets(id) ON DELETE RESTRICT,
  body TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES staff_users(id),
  created_at TEXT NOT NULL
);

CREATE INDEX support_notes_ticket_idx ON support_notes(ticket_id, created_at);

CREATE TABLE security_engagements (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE RESTRICT,
  title TEXT NOT NULL,
  categories_json TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  authorization_reference TEXT NOT NULL,
  starts_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'APPROVED', 'CLOSED', 'EXPIRED')),
  created_by TEXT NOT NULL REFERENCES staff_users(id),
  approved_by TEXT REFERENCES staff_users(id),
  created_at TEXT NOT NULL,
  CHECK (expires_at > starts_at),
  CHECK (approved_by IS NULL OR approved_by <> created_by)
);

CREATE INDEX engagements_customer_idx ON security_engagements(customer_id, created_at DESC);

CREATE TABLE security_test_runs (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES security_engagements(id) ON DELETE RESTRICT,
  category TEXT NOT NULL CHECK (category IN ('CODE_DEPENDENCY', 'WEB_API', 'NETWORK_SERVICE', 'CLOUD_CONFIGURATION')),
  tool_name TEXT NOT NULL,
  target_scope TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETE', 'FAILED', 'CANCELLED')),
  result_reference TEXT,
  requested_by TEXT NOT NULL REFERENCES staff_users(id),
  requested_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE INDEX test_runs_engagement_idx ON security_test_runs(engagement_id, requested_at DESC);

CREATE TABLE forensic_cases (
  id TEXT PRIMARY KEY,
  case_number TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  authority_name TEXT NOT NULL,
  authority_reference TEXT NOT NULL,
  purpose TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ON_HOLD', 'CLOSED')),
  expires_at TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES staff_users(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX forensic_cases_status_idx ON forensic_cases(status, expires_at);

CREATE TABLE evidence_items (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES forensic_cases(id) ON DELETE RESTRICT,
  description TEXT NOT NULL,
  source_reference TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
  secure_storage_reference TEXT NOT NULL,
  collected_by TEXT NOT NULL REFERENCES staff_users(id),
  collected_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX evidence_case_idx ON evidence_items(case_id, collected_at);

CREATE TABLE evidence_custody_events (
  id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL REFERENCES evidence_items(id) ON DELETE RESTRICT,
  action TEXT NOT NULL,
  from_custodian TEXT,
  to_custodian TEXT,
  notes TEXT NOT NULL DEFAULT '',
  performed_by TEXT NOT NULL REFERENCES staff_users(id),
  event_at TEXT NOT NULL,
  event_hash TEXT NOT NULL,
  previous_event_hash TEXT
);

CREATE INDEX custody_evidence_idx ON evidence_custody_events(evidence_id, event_at);

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY,
  actor_id TEXT REFERENCES staff_users(id),
  action TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE INDEX audit_created_idx ON audit_events(created_at DESC);

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;

CREATE TRIGGER custody_events_no_update BEFORE UPDATE ON evidence_custody_events
BEGIN SELECT RAISE(ABORT, 'custody events are append-only'); END;

CREATE TRIGGER custody_events_no_delete BEFORE DELETE ON evidence_custody_events
BEGIN SELECT RAISE(ABORT, 'custody events are append-only'); END;