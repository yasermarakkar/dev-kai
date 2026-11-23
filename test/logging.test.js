import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit } from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);

const checks = async (name, opts = {}) => {
  const report = await runAudit({ root: fixture(name), only: ['logging'], ...opts });
  return Object.fromEntries(report.checklists[0].checks.map((c) => [c.id, c]));
};

test('vulnerable app: logging gaps are reported', async () => {
  const c = await checks('vulnerable-api');
  for (const id of ['LOG-001', 'LOG-003', 'LOG-004', 'LOG-005', 'LOG-006', 'LOG-007', 'LOG-008']) {
    assert.equal(c[id].status, 'fail', `${id} should fail`);
  }
  assert.ok(['warn', 'fail'].includes(c['LOG-002'].status));
  assert.ok(c['LOG-006'].findings.some((f) => /cardNumber/.test(f.text)));
});

test('quick vs review: multi-line empty catch only caught in review', async () => {
  const quick = await checks('vulnerable-api');
  const review = await checks('vulnerable-api', { review: true, offline: true });
  const at9 = (c) => c['LOG-007'].findings.some((f) => f.file === 'src/payments.js' && f.line === 9);
  assert.ok(!at9(quick));
  assert.ok(at9(review));
  assert.equal(review['LOG-R01'].status, 'fail');
  assert.equal(review['LOG-R02'].status, 'fail');
});

test('secure app: logging checklist passes', async () => {
  const c = await checks('secure-api', { review: true, offline: true });
  const bad = Object.values(c).filter((x) => ['fail', 'warn', 'error'].includes(x.status));
  assert.deepEqual(bad.map((x) => `${x.id}: ${x.message}`), []);
});
