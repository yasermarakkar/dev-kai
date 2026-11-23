import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit, stripComments, extractArgs, findTaintedSinks, findRoutes } from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);

const checksById = (report) => Object.fromEntries(report.checklists.flatMap((cl) => cl.checks.map((c) => [c.id, c])));

test('stripComments blanks comments but keeps strings, templates, regexes and line numbers', () => {
  const src = [
    "const a = 'not // a comment'; // real comment",
    '/* block',
    '   comment */ const re = /\\/\\/[a-z]+/g;',
    'const t = `x ${"//"} y`; // tail',
  ].join('\n');
  const out = stripComments(src);
  assert.equal(out.split('\n').length, 4);
  assert.equal(out.length, src.length);
  assert.match(out, /'not \/\/ a comment'/);
  assert.doesNotMatch(out, /real comment|block|tail/);
  assert.match(out, /\/\\\/\\\/\[a-z\]\+\/g/);
  assert.match(out, /`x \$\{"\/\/"\} y`/);
});

test('extractArgs splits top-level arguments only', () => {
  const code = "db.query(`SELECT ${a, b}`, [x, y], { k: (1, 2) })";
  const { args } = extractArgs(code, code.indexOf('('));
  assert.equal(args.length, 3);
  assert.equal(args[1], '[x, y]');
});

test('taint: parameterized query is safe, interpolated one is not', () => {
  const safe = "const { name } = req.query;\npool.query('SELECT * FROM u WHERE n = $1', [name]);";
  const bad = "const { name } = req.query;\nconst q = name;\npool.query(\n  `SELECT * FROM u WHERE n = '${q}'`\n);";
  assert.equal(findTaintedSinks(safe).length, 0);
  const hits = findTaintedSinks(bad);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].kind, 'SQL injection');
  assert.equal(hits[0].line, 3);
});

test('routes: guard middleware marks a route protected', () => {
  const code = "router.post('/a', requireAuth, h);\nrouter.delete('/b/:id', h);\nrouter.post('/login', h);";
  const routes = findRoutes('src/r.js', code);
  assert.deepEqual(routes.map((r) => [r.method, r.path, r.protected]), [
    ['POST', '/a', true], ['DELETE', '/b/:id', false], ['POST', '/login', false],
  ]);
});

test('quick mode does not run in-depth checks and reports how many were skipped', async () => {
  const report = await runAudit({ root: fixture('vulnerable-api') });
  assert.equal(report.mode, 'quick');
  assert.ok(report.reviewChecksSkipped >= 6);
  assert.equal(checksById(report)['SEC-R02'], undefined);
});

test('review mode: finds multi-line SQL, ignores commented-out eval', async () => {
  const quick = checksById(await runAudit({ root: fixture('vulnerable-api') }));
  const review = checksById(await runAudit({ root: fixture('vulnerable-api'), review: true, offline: true }));

  const evalIn = (c) => c.findings.some((f) => f.file === 'src/orders.js' && f.line === 8);
  assert.ok(evalIn(quick['SEC-008']), 'quick flags eval inside a comment');
  assert.ok(!evalIn(review['SEC-008']), 'review ignores eval inside a comment');

  const sqlIn = (c) => c.findings.some((f) => f.file === 'src/orders.js');
  assert.ok(!sqlIn(quick['SEC-009']), 'quick misses multi-line SQL');
  assert.ok(sqlIn(review['SEC-009']), 'review finds multi-line SQL');

  assert.ok(review['SEC-009'].findings[0].context.length > 0, 'review findings carry code context');
});

test('review mode: deep security checks fire on the vulnerable app', async () => {
  const c = checksById(await runAudit({ root: fixture('vulnerable-api'), review: true, offline: true }));
  assert.equal(c['SEC-R01'].status, 'fail');
  assert.equal(c['SEC-R02'].status, 'fail');
  const kinds = c['SEC-R02'].findings.map((f) => f.text.split(':')[0]);
  for (const k of ['SQL injection', 'Command injection', 'Path traversal', 'Open redirect', 'SSRF', 'Reflected XSS']) {
    assert.ok(kinds.includes(k), `expected ${k}`);
  }
  assert.equal(c['SEC-R03'].status, 'fail');
  assert.equal(c['SEC-R04'].status, 'skip'); // --offline
});

test('review mode: secure app stays clean', async () => {
  const report = await runAudit({ root: fixture('secure-api'), review: true, offline: true });
  const bad = report.checklists.flatMap((cl) => cl.checks).filter((c) => ['fail', 'error', 'warn'].includes(c.status));
  assert.deepEqual(bad.map((c) => `${c.id}: ${c.message}`), []);
});
