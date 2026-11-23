import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit } from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);

const checks = async (name, opts = {}) => {
  const report = await runAudit({ root: fixture(name), only: ['auditing'], ...opts });
  return Object.fromEntries(report.checklists[0].checks.map((c) => [c.id, c]));
};

test('vulnerable app: weak audit trail is reported', async () => {
  const c = await checks('vulnerable-api');
  assert.equal(c['AUD-001'].status, 'pass'); // a model exists…
  assert.equal(c['AUD-002'].status, 'fail'); // …but has no actor/target/source fields
  assert.match(c['AUD-002'].findings[0].text, /actor.*target.*source/);
  assert.equal(c['AUD-003'].status, 'fail'); // login not audited
  assert.equal(c['AUD-005'].status, 'fail'); // AuditLog.destroy in app code
  assert.equal(c['AUD-006'].status, 'fail');
  assert.equal(c['AUD-007'].status, 'fail'); // password in audit payload
  assert.equal(c['AUD-008'].status, 'warn');
});

test('vulnerable app --review: uncovered routes, spoofed actor, silent 403', async () => {
  const c = await checks('vulnerable-api', { review: true, offline: true });
  assert.ok(['warn', 'fail'].includes(c['AUD-R01'].status));
  assert.ok(c['AUD-R01'].findings.some((f) => f.file === 'src/admin.js' && /PUT \/admin\/users/.test(f.text)));
  assert.equal(c['AUD-R02'].status, 'fail');
  assert.equal(c['AUD-R03'].status, 'fail');
});

test('secure app: auditing passes in both modes', async () => {
  for (const review of [false, true]) {
    const c = await checks('secure-api', { review, offline: true });
    const bad = Object.values(c).filter((x) => ['fail', 'warn', 'error'].includes(x.status));
    assert.deepEqual(bad.map((x) => `${x.id}: ${x.message}`), [], `review=${review}`);
    assert.equal(c['AUD-005'].status, 'pass'); // REVOKE + hash chain detected
  }
});
