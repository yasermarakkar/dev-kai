import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runAudit } from '../src/index.js';

function tempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devkai-sup-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

const check = async (dir, id, opts = {}) => {
  const report = await runAudit({ root: dir, ...opts });
  return report.checklists.flatMap((cl) => cl.checks).find((c) => c.id === id);
};

test('devkai-ignore comments: same line, next line, file — ids required', async () => {
  const dir = tempProject({
    'package.json': JSON.stringify({ dependencies: { express: '^5.0.0' } }),
    'src/a.js': [
      "const x = eval(input); // devkai-ignore SEC-008",
      '// devkai-ignore-next-line SEC-008',
      'const y = eval(input);',
      'const z = eval(input); // devkai-ignore',
    ].join('\n'),
    'src/b.js': "/* devkai-ignore-file SEC-008 */\nconst w = eval(input);\n",
  });
  const c = await check(dir, 'SEC-008', { only: ['security'] });
  assert.equal(c.status, 'fail');
  assert.deepEqual(c.findings.map((f) => `${f.file}:${f.line}`), ['src/a.js:4'], 'directive without ids suppresses nothing');
  assert.equal(c.suppressed, 3);
  assert.match(c.message, /\(3 suppressed\)/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('all findings suppressed turns the check green and says so', async () => {
  const dir = tempProject({
    'package.json': JSON.stringify({ dependencies: { express: '^5.0.0' } }),
    'src/a.js': '/* devkai-ignore-file * — fixture */\nconst x = eval(input);\n',
  });
  const c = await check(dir, 'SEC-008', { only: ['security'] });
  assert.equal(c.status, 'pass');
  assert.match(c.message, /suppressed with devkai-ignore/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('pattern text inside strings and regexes is not mistaken for code', async () => {
  const dir = tempProject({
    'package.json': JSON.stringify({ dependencies: { express: '^5.0.0' } }),
    'src/rules.js': [
      "export const tip = 'Never set rejectUnauthorized: false or use dangerouslySetInnerHTML';",
      'export const re = /fetch\\(|eval\\(/;',
      "export const doc = `call fetch(url) with a timeout; read process.env.API_TOKEN`;",
      '.then(ok, (err) => log(err));',
      'try { run(); } catch { /* best effort: cache warm-up */ }',
    ].join('\n'),
  });
  const r = await runAudit({ root: dir, review: true, offline: true });
  const byId = Object.fromEntries(r.checklists.flatMap((cl) => cl.checks).map((c) => [c.id, c]));
  for (const id of ['SEC-015', 'SEC-018', 'SCL-R03', 'REL-R02', 'LOG-007']) {
    assert.ok(['pass', 'skip'].includes(byId[id].status), `${id} should not fire on text: ${byId[id].message}`);
  }
  assert.equal(byId['SEC-003'].status, 'skip', 'env var mentioned only in a string');
  fs.rmSync(dir, { recursive: true, force: true });
});
