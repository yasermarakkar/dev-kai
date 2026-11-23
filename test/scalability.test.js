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
  const report = await runAudit({ root, only: ['scalability'], ...opts });
  return Object.fromEntries(report.checklists[0].checks.map((c) => [c.id, c]));
};

test('vulnerable app: scalability gaps are reported', async () => {
  const c = await checks(fixture('vulnerable-api'));
  for (const id of ['SCL-001', 'SCL-002', 'SCL-003', 'SCL-004', 'SCL-005', 'SCL-006', 'SCL-007', 'SCL-012']) {
    assert.equal(c[id].status, 'fail', `${id} should fail`);
  }
  assert.equal(c['SCL-010'].status, 'warn');
  assert.equal(c['SCL-008'].status, 'skip'); // no in-app rate limiter
});

test('vulnerable app --review: module state, blocking handler, untimed fetch', async () => {
  const c = await checks(fixture('vulnerable-api'), { review: true, offline: true });
  const r01 = c['SCL-R01'].findings.map((f) => f.text.split(' ')[0]);
  assert.deepEqual(r01.sort(), ['recentUploads', 'uploadCount']);
  assert.ok(c['SCL-R02'].findings.some((f) => /readFileSync/.test(f.text)));
  assert.equal(c['SCL-R03'].status, 'fail');
});

test('secure app: scalability passes in both modes; load-test scripts are not app code', async () => {
  for (const review of [false, true]) {
    const c = await checks(fixture('secure-api'), { review, offline: true });
    const bad = Object.values(c).filter((x) => ['fail', 'warn', 'error'].includes(x.status));
    assert.deepEqual(bad.map((x) => `${x.id}: ${x.message}`), [], `review=${review}`);
  }
});

test('trust proxy `true` is flagged as spoofable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devkai-scl-'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { express: '^4.0.0' } }));
  fs.writeFileSync(path.join(dir, 'app.js'), "const app = require('express')();\napp.set('trust proxy', true);\napp.listen(3000);\n");
  const c = await checks(dir);
  assert.equal(c['SCL-012'].status, 'warn');
  fs.rmSync(dir, { recursive: true, force: true });
});
