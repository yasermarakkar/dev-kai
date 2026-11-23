SET lock_timeout = '5s';
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS users_name_key ON users (name);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_user_id ON orders (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_actor ON audit_log (actor_id, created_at);
