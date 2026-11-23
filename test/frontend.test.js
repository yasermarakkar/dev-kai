import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit } from '../src/index.js';
import { contrastRatio } from '../src/checklists/frontend.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);

const checks = async (name, opts = {}) => {
  const report = await runAudit({ root: fixture(name), only: ['frontend'], ...opts });
  return Object.fromEntries(report.checklists[0].checks.map((c) => [c.id, c]));
};

test('contrast ratio matches WCAG reference values', () => {
  assert.equal(contrastRatio([0, 0, 0], [255, 255, 255]).toFixed(1), '21.0');
  assert.equal(contrastRatio([0x76, 0x76, 0x76], [255, 255, 255]) >= 4.5, true); // #767676 passes on white
  assert.equal(contrastRatio([0xaa, 0xaa, 0xaa], [255, 255, 255]) < 4.5, true); // #aaa fails
});

test('API-only apps: frontend checks are not applicable', async () => {
  const report = await runAudit({ root: fixture('secure-api'), only: ['frontend'] });
  const cl = report.checklists[0];
  assert.equal(cl.score, null);
  assert.ok(cl.checks.filter((c) => !c.manual).every((c) => c.status === 'skip'));
});

test('web-bad: performance and accessibility problems are reported', async () => {
  const c = await checks('web-bad');
  for (const id of ['FE-001', 'FE-002', 'FE-004', 'FE-005', 'FE-006', 'FE-007', 'FE-008', 'FE-010', 'FE-011', 'FE-012', 'FE-013', 'FE-014', 'FE-015', 'FE-016']) {
    assert.equal(c[id].status, 'fail', `${id} should fail`);
  }
  assert.equal(c['FE-003'].status, 'warn');
  assert.ok(c['FE-003'].findings.some((f) => /moment/.test(f.text)));
  assert.ok(c['FE-003'].findings.some((f) => /lodash/.test(f.text)));
  assert.equal(c['FE-017'].status, 'warn');
  const clicks = c['FE-012'].findings.map((f) => f.text).join('\n');
  assert.match(clicks, /<div> with a click handler/);
  assert.match(clicks, /<li> with a click handler/);
  assert.match(clicks, /<a> used as a button/);
});

test('web-bad --review: icon button, heading skip, contrast, React pitfalls', async () => {
  const c = await checks('web-bad', { review: true, offline: true });
  assert.equal(c['FE-R01'].status, 'fail');
  assert.equal(c['FE-R02'].status, 'warn');
  assert.match(c['FE-R02'].findings[0].text, /h1 → h4/);
  const contrast = c['FE-R03'].findings.map((f) => f.text).join('\n');
  assert.match(contrast, /#aaaaaa on #ffffff = 2\.\d+:1/);
  assert.match(contrast, /text-gray-400/);
  const pitfalls = c['FE-R04'].findings.map((f) => f.text).join('\n');
  assert.match(pitfalls, /without a key/);
  assert.match(pitfalls, /useEffect without a dependency array/);
});

test('web-good: frontend checklist passes in both modes', async () => {
  for (const review of [false, true]) {
    const c = await checks('web-good', { review, offline: true });
    const bad = Object.values(c).filter((x) => ['fail', 'warn', 'error'].includes(x.status));
    assert.deepEqual(bad.map((x) => `${x.id}: ${x.message}`), [], `review=${review}`);
  }
});
