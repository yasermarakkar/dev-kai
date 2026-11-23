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
  const report = await runAudit({ root, only: ['reliability'], ...opts });
  return Object.fromEntries(report.checklists[0].checks.map((c) => [c.id, c]));
};

function tempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devkai-rel-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

test('vulnerable app: reliability gaps are reported', async () => {
  const c = await checks(fixture('vulnerable-api'));
  for (const id of ['REL-001', 'REL-003', 'REL-004', 'REL-006', 'REL-008']) assert.equal(c[id].status, 'fail', `${id} should fail`);
  assert.equal(c['REL-002'].status, 'warn');
  assert.equal(c['REL-005'].status, 'pass'); // has an error middleware
});

test('vulnerable app --review: hanging handlers, floating promise, error answered as success', async () => {
  const c = await checks(fixture('vulnerable-api'), { review: true, offline: true });
  assert.ok(c['REL-R01'].findings.length >= 5);
  assert.ok(c['REL-R02'].findings.some((f) => f.file === 'src/webhooks.js'));
  assert.ok(c['REL-R03'].findings.some((f) => f.file === 'src/webhooks.js'));
});

test('secure app: reliability passes in both modes', async () => {
  for (const review of [false, true]) {
    const c = await checks(fixture('secure-api'), { review, offline: true });
    const bad = Object.values(c).filter((x) => ['fail', 'warn', 'error'].includes(x.status));
    assert.deepEqual(bad.map((x) => `${x.id}: ${x.message}`), [], `review=${review}`);
  }
});

test('Express 5 forwards async errors; build stage names are not floating images', async () => {
  const dir = tempProject({
    'package.json': JSON.stringify({ dependencies: { express: '^5.1.0' }, engines: { node: '>=22' } }),
    'app.js': "const app = require('express')();\napp.get('/x', async (req, res) => res.json(await load()));\n",
    Dockerfile: 'FROM node:22.11-slim AS build\nRUN npm ci\nFROM build\nCMD ["node", "app.js"]\n',
  });
  const c = await checks(dir, { review: true, offline: true });
  assert.equal(c['REL-006'].status, 'pass');
  assert.equal(c['REL-R01'].status, 'pass');
  assert.equal(c['REL-008'].status, 'pass');
  fs.rmSync(dir, { recursive: true, force: true });
});
