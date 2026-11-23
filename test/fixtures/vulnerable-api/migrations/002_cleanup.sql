ALTER TABLE orders DROP COLUMN note;
CREATE INDEX idx_orders_total ON orders (total);
