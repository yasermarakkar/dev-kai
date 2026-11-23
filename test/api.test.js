import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit, createContext } from '../src/index.js';
import { allRoutes } from '../src/checklists/api.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);

const checks = async (root, opts = {}) => {
  const report = await runAudit({ root, only: ['api'], ...opts });
  return Object.fromEntries(report.checklists[0].checks.map((c) => [c.id, c]));
};

function tempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devkai-api-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

test('route inventory: Express, NestJS (with controller prefix) and Next.js route handlers', () => {
  const dir = tempProject({
    'package.json': JSON.stringify({ dependencies: { express: '^5.0.0', '@nestjs/core': '^10.0.0', next: '^15.0.0' } }),
    'src/a.js': "router.get('/v1/items', h);\naxios.get('/not-a-route');\n",
    'src/users.controller.ts': "@Controller('users')\nexport class U {\n  @Get(':id') one() {}\n  @Post() create() {}\n}\n",
    'app/api/orders/[id]/route.ts': 'export async function GET() {}\nexport async function DELETE() {}\n',
  });
  const routes = allRoutes(createContext(dir)).map((r) => `${r.method} ${r.path}`).sort();
  assert.deepEqual(routes, ['DELETE /api/orders/:id', 'GET /api/orders/:id', 'GET /users/:id', 'GET /v1/items', 'POST /users']);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('vulnerable app: API design gaps are reported', async () => {
  const c = await checks(fixture('vulnerable-api'));
  for (const id of ['API-001', 'API-003', 'API-005', 'API-006']) assert.equal(c[id].status, 'fail', `${id} should fail`);
  assert.equal(c['API-004'].status, 'warn');
  const naming = c['API-011'].findings.map((f) => f.text).join('\n');
  assert.match(naming, /verb in path: GET \/getUserOrders/);
  assert.match(naming, /snake_case segment: \/user_profile/);
});

test('vulnerable app --review: unpaginated lists and a leaked password hash', async () => {
  const c = await checks(fixture('vulnerable-api'), { review: true, offline: true });
  assert.equal(c['API-R01'].status, 'fail');
  assert.equal(c['API-R02'].status, 'fail');
  assert.match(c['API-R02'].findings[0].text, /GET \/user_profile\/:id returns User row including passwordHash|password_hash/);
});

test('secure app: API design passes in both modes (ZodError mapped to 400)', async () => {
  for (const review of [false, true]) {
    const c = await checks(fixture('secure-api'), { review, offline: true });
    const bad = Object.values(c).filter((x) => ['fail', 'warn', 'error'].includes(x.status));
    assert.deepEqual(bad.map((x) => `${x.id}: ${x.message}`), [], `review=${review}`);
  }
});

test('GraphQL without depth limits and with forced introspection fails API-007', async () => {
  const dir = tempProject({
    'package.json': JSON.stringify({ dependencies: { '@apollo/server': '^4.11.0', graphql: '^16.9.0' } }),
    'src/server.js': "import { ApolloServer } from '@apollo/server';\nconst server = new ApolloServer({ typeDefs, resolvers, introspection: true });\n",
  });
  const c = await checks(dir);
  assert.equal(c['API-001'].status, 'pass');
  assert.equal(c['API-007'].status, 'fail');
  assert.equal(c['API-003'].status, 'skip');
  fs.rmSync(dir, { recursive: true, force: true });
});
