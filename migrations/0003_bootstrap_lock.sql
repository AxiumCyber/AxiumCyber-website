CREATE TABLE portal_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

INSERT INTO portal_settings (setting_key, setting_value, updated_at)
VALUES ('bootstrap_completed', '0', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
