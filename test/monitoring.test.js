import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit } from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);

const checks = async (root, opts = {}) => {
  const report = await runAudit({ root, only: ['monitoring'], ...opts });
  return Object.fromEntries(report.checklists[0].checks.map((c) => [c.id, c]));
};

test('vulnerable app: monitoring gaps are reported', async () => {
  const c = await checks(fixture('vulnerable-api'));
  assert.equal(c['MON-001'].status, 'pass'); // has a /health route…
  assert.equal(c['MON-002'].status, 'warn'); // …but no readiness endpoint
  for (const id of ['MON-003', 'MON-006', 'MON-007']) assert.equal(c[id].status, 'fail', `${id} should fail`);
  assert.equal(c['MON-008'].status, 'warn');
  assert.equal(c['MON-004'].status, 'skip'); // no frontend
});

test('vulnerable app --review: shallow health, public metrics, silent 5xx', async () => {
  const c = await checks(fixture('vulnerable-api'), { review: true, offline: true });
  assert.equal(c['MON-R01'].status, 'warn');
  assert.equal(c['MON-R02'].status, 'fail');
  assert.equal(c['MON-R03'].status, 'fail');
  assert.ok(c['MON-R03'].findings.some((f) => f.file === 'src/orders.js'));
});

test('secure app: monitoring passes in both modes', async () => {
  for (const review of [false, true]) {
    const c = await checks(fixture('secure-api'), { review, offline: true });
    const bad = Object.values(c).filter((x) => ['fail', 'warn', 'error'].includes(x.status));
    assert.deepEqual(bad.map((x) => `${x.id}: ${x.message}`), [], `review=${review}`);
  }
});

test('frontend checks run for a React site without monitoring', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devkai-web-'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'web', dependencies: { react: '^19.0.0', '@sentry/react': '^8.0.0' } }));
  fs.mkdirSync(path.join(dir, 'src'));
  fs.writeFileSync(path.join(dir, 'src', 'main.jsx'), "import * as Sentry from '@sentry/react';\nSentry.init({ dsn: import.meta.env.VITE_SENTRY_DSN });\n");
  const c = await checks(dir);
  assert.equal(c['MON-004'].status, 'pass');
  assert.equal(c['MON-009'].status, 'fail'); // no release/environment
  assert.equal(c['MON-010'].status, 'fail'); // no RUM
  assert.equal(c['MON-011'].status, 'fail'); // no source map upload
  assert.equal(c['MON-001'].status, 'skip'); // no backend
  fs.rmSync(dir, { recursive: true, force: true });
});
