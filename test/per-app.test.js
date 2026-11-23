import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAuditPerApp, discoverApps, createContext, worstFailure, writeMarkdownPerApp, readConfirmedManual } from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const mono = path.join(here, 'fixtures', 'monorepo');

const byApp = (report) => Object.fromEntries(report.reports.map((r) => [
  r.app.name,
  { report: r, checks: Object.fromEntries(r.checklists.flatMap((cl) => cl.checks.map((c) => [c.id, c]))), lists: Object.fromEntries(r.checklists.map((cl) => [cl.id, cl])) },
]));

test('discoverApps: workspace packages, not the config-only root', () => {
  const apps = discoverApps(mono).map((a) => `${a.dir} ${a.slug}`).sort();
  assert.deepEqual(apps, ['apps/admin apps-admin', 'apps/api apps-api', 'apps/web apps-web', 'packages/shared-types packages-shared-types']);
});

test('scoped context: own files + shared repo files, never another app\'s files', () => {
  const ctx = createContext(mono, {}, { scope: 'apps/admin' });
  assert.ok(ctx.files.includes('apps/admin/src/server.js'));
  assert.ok(ctx.files.includes('.github/workflows/ci.yml'));
  assert.ok(!ctx.files.some((f) => f.startsWith('apps/api/')));
  assert.ok(ctx.hasDep('cors') && !ctx.hasDep('helmet'), 'only admin + root dependencies');
  assert.ok(ctx.hasDep('turbo'), 'root tooling dependencies are shared');
  assert.equal(ctx.repoApps.length, 5);
});

test('per-app audit isolates findings and dependencies', async () => {
  const report = await runAuditPerApp({ root: mono, offline: true });
  const a = byApp(report);
  // helmet/rate limit installed in api only
  assert.equal(a['@shop/api'].checks['SEC-004'].status, 'pass');
  assert.equal(a['@shop/admin'].checks['SEC-004'].status, 'fail');
  assert.equal(a['@shop/admin'].checks['SEC-006'].status, 'fail'); // cors() wildcard in admin only
  assert.equal(a['@shop/api'].checks['SEC-006'].status, 'pass');
  // admin's console.log does not show up in api's report
  assert.ok(a['@shop/admin'].checks['LOG-002'].findings.some((f) => f.file === 'apps/admin/src/server.js'));
  assert.ok(['pass', 'skip'].includes(a['@shop/api'].checks['LOG-002'].status));
  // shared CI is visible to every app; repo-level monorepo check still sees all packages
  for (const app of Object.values(a)) {
    assert.equal(app.checks['CI-001'].status, 'pass');
    assert.equal(app.checks['CI-013'].status, 'pass');
  }
  // frontend only applies to web; elsewhere manual items are hidden too
  assert.notEqual(a['@shop/web'].lists.frontend.score, null);
  assert.equal(a['@shop/web'].checks['FE-010'].status, 'fail');
  assert.equal(a['@shop/api'].lists.frontend.score, null);
  assert.ok(a['@shop/api'].lists.frontend.checks.every((c) => c.status === 'skip'));
  assert.equal(worstFailure(report) >= 3, true);
});

test('--app filter and unknown app error', async () => {
  const one = await runAuditPerApp({ root: mono, apps: ['@shop/web'], only: ['frontend'] });
  assert.deepEqual(one.reports.map((r) => r.app.name), ['@shop/web']);
  await assert.rejects(runAuditPerApp({ root: mono, apps: ['nope'] }), /Unknown app\(s\): nope/);
});

test('per-app markdown: matrix README + one folder per app; manual ticks kept per app', async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'devkai-mono-'));
  const first = await runAuditPerApp({ root: mono, only: ['security'] });
  writeMarkdownPerApp(first, out);
  const summary = fs.readFileSync(path.join(out, 'README.md'), 'utf8');
  assert.match(summary, /\| \[@shop\/api\]\(\.\/apps-api\/README\.md\)/);
  assert.match(summary, /\[\d+\]\(\.\/apps-admin\/security\.md\)/);

  const apiFile = path.join(out, 'apps-api', 'security.md');
  fs.writeFileSync(apiFile, fs.readFileSync(apiFile, 'utf8').replace(/- \[ \](.*devkai:SEC-M04 -->)/, '- [x]$1'));
  const second = await runAuditPerApp({ root: mono, only: ['security'], confirmedFor: (app) => readConfirmedManual(path.join(out, app.slug)) });
  const a = byApp(second);
  assert.equal(a['@shop/api'].checks['SEC-M04'].confirmed, true);
  assert.equal(a['@shop/admin'].checks['SEC-M04'].confirmed, false, 'ticks do not leak to other apps');
  fs.rmSync(out, { recursive: true, force: true });
});
