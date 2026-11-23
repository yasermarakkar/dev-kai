CREATE TABLE IF NOT EXISTS orders (
  id         BIGSERIAL PRIMARY KEY,
  sku        TEXT NOT NULL,
  qty        INT  NOT NULL,
  user_id    BIGINT NOT NULL REFERENCES users(id),
  created_by TEXT NOT NULL,
  updated_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ
);
