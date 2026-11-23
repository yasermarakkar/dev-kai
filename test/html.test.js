import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit, runAuditPerApp, renderHtml, safeJson, writeHtml } from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);

const embedded = (html) => JSON.parse(html.match(/<script type="application\/json" id="devkai-data">([\s\S]*?)<\/script>/)[1]);

test('safeJson cannot close the script element and survives line separators', () => {
  const out = safeJson({ s: '</script><script>alert(1)</script>', ls: 'a\u2028b\u2029c', amp: 'x & y' });
  assert.doesNotMatch(out, /</);
  assert.doesNotMatch(out, /[\u2028\u2029]/);
  assert.deepEqual(JSON.parse(out), { s: '</script><script>alert(1)</script>', ls: 'a\u2028b\u2029c', amp: 'x & y' });
});

test('hostile finding text and project name stay inert', async () => {
  const report = await runAudit({ root: fixture('vulnerable-api'), only: ['security'] });
  report.project = '<img src=x onerror=alert(1)>';
  report.checklists[0].checks[0].findings.push({ file: 'evil.js', line: 1, text: '</script><script>alert(document.cookie)</script>' });
  const html = renderHtml(report);
  assert.equal((html.match(/<script/g) ?? []).length, 2, 'only the data block and the app script');
  assert.doesNotMatch(html, /<img src=x/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.ok(embedded(html).apps[0].checklists[0].checks[0].findings.some((f) => f.text.includes('</script>')), 'data round-trips intact');
  const appScript = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  assert.doesNotMatch(appScript, /\.innerHTML|insertAdjacentHTML|document\.write|eval\(/, 'renderer never parses data as HTML');
});

test('single-app report renders as one app with every checklist', async () => {
  const report = await runAudit({ root: fixture('vulnerable-api'), review: true, offline: true });
  const data = embedded(renderHtml(report));
  assert.equal(data.perApp, false);
  assert.equal(data.apps.length, 1);
  assert.equal(data.apps[0].checklists.length, report.checklists.length);
  assert.equal(data.mode, 'review');
  const sql = data.apps[0].checklists.find((c) => c.id === 'security').checks.find((c) => c.id === 'SEC-009');
  assert.ok(sql.findings.some((f) => Array.isArray(f.context)), 'review context is carried into the page');
});

test('per-app report renders the matrix data; writeHtml writes index.html', async () => {
  const report = await runAuditPerApp({ root: fixture('monorepo'), only: ['security', 'frontend'] });
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'devkai-html-'));
  const [file] = writeHtml(report, out);
  assert.equal(path.basename(file), 'index.html');
  const data = embedded(fs.readFileSync(file, 'utf8'));
  assert.equal(data.perApp, true);
  assert.deepEqual(data.apps.map((a) => a.slug).sort(), ['apps-admin', 'apps-api', 'apps-web', 'packages-shared-types']);
  assert.equal(data.apps.find((a) => a.slug === 'apps-api').checklists.find((c) => c.id === 'frontend').score, null);
  fs.rmSync(out, { recursive: true, force: true });
});
