CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGSERIAL PRIMARY KEY,
  actor_id    TEXT        NOT NULL,
  actor_type  TEXT        NOT NULL DEFAULT 'user',
  action      TEXT        NOT NULL,          -- e.g. auth.login.success, order.create
  target_type TEXT,
  target_id   TEXT,
  ip_address  INET,
  user_agent  TEXT,
  request_id  TEXT,
  metadata    JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  prev_hash   TEXT,
  hash        TEXT        NOT NULL
);

-- The application role may only append.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM app_user;
GRANT INSERT, SELECT ON audit_log TO app_user;

-- Retention: run nightly as the maintenance role (keeps 400 days).
CREATE OR REPLACE FUNCTION purge_old_audit() RETURNS void AS $$
  DELETE FROM audit_log WHERE created_at < now() - interval '400 days';
$$ LANGUAGE sql SECURITY DEFINER;
