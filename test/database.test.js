import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit, createContext } from '../src/index.js';
import { buildSchema, isIndexed } from '../src/core/schema.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);

const checks = async (root, opts = {}) => {
  const report = await runAudit({ root, only: ['database'], ...opts });
  return Object.fromEntries(report.checklists[0].checks.map((c) => [c.id, c]));
};

function tempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devkai-db-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

test('schema parser: Prisma relations and indexes', () => {
  const dir = tempProject({
    'package.json': JSON.stringify({ dependencies: { '@prisma/client': '^6.0.0' } }),
    'prisma/schema.prisma': `
datasource db { provider = "postgresql" url = env("DATABASE_URL") }
model User {
  id    Int     @id @default(autoincrement())
  email String  @unique
  posts Post[]
}
model Post {
  id       Int  @id
  authorId Int
  author   User @relation(fields: [authorId], references: [id])
  tagId    Int
  tag      Tag  @relation(fields: [tagId], references: [id])
  @@index([tagId, authorId])
}
model Tag { id Int @id }
`,
  });
  const schema = buildSchema(createContext(dir));
  const post = schema.tables.get('post');
  assert.deepEqual(post.fks.map((f) => f.column), ['authorId', 'tagId']);
  assert.equal(isIndexed(post, 'tagId'), true); // leading column of composite index
  assert.equal(isIndexed(post, 'authorId'), false); // second column does not count
  assert.equal(isIndexed(schema.tables.get('user'), 'email'), true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('schema parser: SQL inline/table FKs, CREATE INDEX CONCURRENTLY, snake/camel matching', () => {
  const dir = tempProject({
    'package.json': JSON.stringify({ dependencies: { pg: '^8.0.0' } }),
    'migrations/001.sql': `
CREATE TABLE accounts (id BIGSERIAL PRIMARY KEY);
CREATE TABLE invoices (
  id BIGSERIAL PRIMARY KEY,
  account_id BIGINT NOT NULL REFERENCES accounts(id),
  owner_id BIGINT,
  CONSTRAINT fk_owner FOREIGN KEY (owner_id) REFERENCES accounts (id)
);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_inv_account ON invoices USING btree (account_id);
`,
  });
  const inv = buildSchema(createContext(dir)).tables.get('invoices');
  assert.deepEqual(inv.fks.map((f) => f.column).sort(), ['account_id', 'owner_id']);
  assert.equal(isIndexed(inv, 'accountId'), true);
  assert.equal(isIndexed(inv, 'owner_id'), false);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('vulnerable app: database gaps are reported', async () => {
  const c = await checks(fixture('vulnerable-api'));
  assert.equal(c['DB-002'].status, 'fail'); // sync({ alter: true })
  assert.equal(c['DB-003'].status, 'fail');
  assert.equal(c['DB-003'].findings.length, 2); // orders.customer_id, payments.order_id (deduped across SQL + Sequelize)
  assert.equal(c['DB-005'].status, 'fail');
  assert.equal(c['DB-006'].status, 'fail'); // ssl: false
  assert.equal(c['DB-007'].status, 'fail');
  assert.equal(c['DB-008'].status, 'warn'); // DROP COLUMN + non-concurrent index
  assert.equal(c['DB-010'].status, 'fail');
});

test('vulnerable app --review: unindexed filters, N+1, writes without transaction', async () => {
  const c = await checks(fixture('vulnerable-api'), { review: true, offline: true });
  assert.equal(c['DB-R01'].status, 'fail');
  const cols = c['DB-R01'].findings.map((f) => f.text.split(' ')[0]);
  for (const col of ['orders.status', 'orders.customer_id', 'users.email']) assert.ok(cols.includes(col), `expected ${col}`);
  assert.equal(new Set(cols).size, cols.length, 'no duplicate columns');
  assert.equal(c['DB-R02'].status, 'fail');
  assert.ok(c['DB-R02'].findings.some((f) => f.file === 'src/reports.js'));
  assert.equal(c['DB-R03'].status, 'warn');
});

test('secure app: database passes in both modes', async () => {
  for (const review of [false, true]) {
    const c = await checks(fixture('secure-api'), { review, offline: true });
    const bad = Object.values(c).filter((x) => ['fail', 'warn', 'error'].includes(x.status));
    assert.deepEqual(bad.map((x) => `${x.id}: ${x.message}`), [], `review=${review}`);
  }
});
