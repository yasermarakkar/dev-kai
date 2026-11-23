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
  const report = await runAudit({ root, only: ['cicd'], ...opts });
  return Object.fromEntries(report.checklists[0].checks.map((c) => [c.id, c]));
};

function tempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devkai-ci-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

test('vulnerable app: CI/CD gaps and dangerous workflow are reported', async () => {
  const c = await checks(fixture('vulnerable-api'));
  for (const id of ['CI-002', 'CI-003', 'CI-004', 'CI-005', 'CI-008', 'CI-009', 'CI-010', 'CI-011']) assert.equal(c[id].status, 'fail', `${id} should fail`);
  const wf = c['CI-011'].findings.map((f) => f.text).join('\n');
  assert.match(wf, /write-all/);
  assert.match(wf, /untrusted input in shell/);
  assert.match(wf, /secret printed/);
  assert.match(wf, /pull_request_target/);
  assert.doesNotMatch(wf, /Notify/, 'a step name is not shell');
  assert.doesNotMatch(wf, /DEPLOY_TOKEN/, 'secret names are masked');
});

test('vulnerable app --review: untested critical modules and a focused test', async () => {
  const c = await checks(fixture('vulnerable-api'), { review: true, offline: true });
  assert.ok(c['CI-R01'].findings.some((f) => f.file === 'src/payments.js'));
  assert.ok(!c['CI-R01'].findings.some((f) => f.file === 'src/orders.js'), 'orders.js is imported by a test');
  assert.equal(c['CI-R02'].status, 'fail');
});

test('secure app: CI/CD passes in both modes', async () => {
  for (const review of [false, true]) {
    const c = await checks(fixture('secure-api'), { review, offline: true });
    const bad = Object.values(c).filter((x) => ['fail', 'warn', 'error'].includes(x.status));
    assert.deepEqual(bad.map((x) => `${x.id}: ${x.message}`), [], `review=${review}`);
  }
});

test('install parser: package installs and frozen installs are fine, bare installs are not', async () => {
  const dir = tempProject({
    'package.json': JSON.stringify({ name: 'x' }),
    '.github/workflows/ci.yml': [
      'on: [pull_request]',
      'jobs:',
      '  a:',
      '    steps:',
      '      - uses: actions/setup-node@v4',
      '        with: { cache: yarn }',
      '      - run: npm install -g pnpm',
      '      - run: pnpm install --frozen-lockfile',
      '      - run: yarn install --immutable',
      '      - run: npm install',
    ].join('\n'),
  });
  const c = await checks(dir);
  assert.equal(c['CI-009'].status, 'fail');
  assert.deepEqual(c['CI-009'].findings.map((f) => f.line), [10]);
  fs.rmSync(dir, { recursive: true, force: true });
});
