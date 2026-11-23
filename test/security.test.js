import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit, worstFailure, writeMarkdown, readConfirmedManual } from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);

const statusOf = (report) =>
  Object.fromEntries(report.checklists.flatMap((cl) => cl.checks.map((c) => [c.id, c.status])));

test('vulnerable app: every planted issue is caught', async () => {
  const report = await runAudit({ root: fixture('vulnerable-api'), only: ['security'] });
  const s = statusOf(report);
  for (const id of ['SEC-001', 'SEC-002', 'SEC-004', 'SEC-005', 'SEC-006', 'SEC-007', 'SEC-008', 'SEC-009',
    'SEC-010', 'SEC-011', 'SEC-012', 'SEC-013', 'SEC-014', 'SEC-016', 'SEC-017']) {
    assert.equal(s[id], 'fail', `${id} should fail`);
  }
  assert.ok(report.score < 30);
  assert.equal(worstFailure(report), 4); // critical
});

test('secure app: no automated failures', async () => {
  const report = await runAudit({ root: fixture('secure-api'), only: ['security'] });
  const failed = report.checklists[0].checks.filter((c) => c.status === 'fail' || c.status === 'error');
  assert.deepEqual(failed.map((c) => c.id), []);
  assert.equal(report.score, 100);
});

test('secrets are masked in findings', async () => {
  const report = await runAudit({ root: fixture('vulnerable-api'), only: ['security'] });
  const sec = report.checklists[0].checks.find((c) => c.id === 'SEC-001');
  const text = JSON.stringify(sec.findings);
  assert.ok(!text.includes('k3y-9f8a7b6c5d4e3f2a1b'), 'raw secret must not appear');
});

test('config can disable checks and override severity', async () => {
  const report = await runAudit({
    root: fixture('vulnerable-api'),
    config: { disable: ['SEC-005'], severity: { 'SEC-007': 'low' } },
  });
  const checks = report.checklists[0].checks;
  assert.equal(checks.find((c) => c.id === 'SEC-005').status, 'skip');
  assert.equal(checks.find((c) => c.id === 'SEC-007').severity, 'low');
});

test('manual ticks survive a re-scan', async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'devkai-'));
  const first = await runAudit({ root: fixture('secure-api') });
  writeMarkdown(first, out);
  const file = path.join(out, 'security.md');
  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace(/- \[ \](.*devkai:SEC-M02 -->)/, '- [x]$1'));

  const confirmed = readConfirmedManual(out);
  assert.ok(confirmed.has('SEC-M02'));
  const second = await runAudit({ root: fixture('secure-api'), confirmed });
  writeMarkdown(second, out);
  assert.match(fs.readFileSync(file, 'utf8'), /- \[x\].*devkai:SEC-M02 -->/);
  fs.rmSync(out, { recursive: true, force: true });
});

test('unknown checklist id throws a helpful error', async () => {
  await assert.rejects(runAudit({ root: fixture('secure-api'), only: ['nope'] }), /Available: security/);
});
