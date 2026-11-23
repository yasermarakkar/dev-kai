CREATE TABLE users (
  id    SERIAL PRIMARY KEY,
  email TEXT,
  name  TEXT,
  role  TEXT
);

CREATE TABLE orders (
  id          SERIAL PRIMARY KEY,
  customer_id INT REFERENCES users(id),
  status      TEXT,
  total       NUMERIC,
  note        TEXT
);

CREATE TABLE payments (
  id       SERIAL PRIMARY KEY,
  order_id INT REFERENCES orders(id),
  amount   NUMERIC
);
