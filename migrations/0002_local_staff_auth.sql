ALTER TABLE staff_users ADD COLUMN contact_email TEXT;
ALTER TABLE staff_users ADD COLUMN password_salt TEXT;
ALTER TABLE staff_users ADD COLUMN password_hash TEXT;
ALTER TABLE staff_users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1));
ALTER TABLE staff_users ADD COLUMN deleted_at TEXT;
UPDATE staff_users SET contact_email = email;

CREATE TABLE staff_sessions (
  session_hash TEXT PRIMARY KEY,
  staff_user_id TEXT NOT NULL REFERENCES staff_users(id) ON DELETE CASCADE,
  csrf_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX staff_sessions_expiry_idx ON staff_sessions(expires_at);

CREATE TABLE login_attempts (
  attempt_key TEXT PRIMARY KEY,
  failure_count INTEGER NOT NULL,
  window_started_at TEXT NOT NULL,
  locked_until TEXT,
  updated_at TEXT NOT NULL
);