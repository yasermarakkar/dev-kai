import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { main } from '../src/cli.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);

/** Run the CLI in-process, capturing stdout/stderr. */
async function run(args) {
  const out = [];
  const err = [];
  const write = { out: process.stdout.write, err: process.stderr.write };
  process.stdout.write = (s) => { out.push(String(s)); return true; };
  process.stderr.write = (s) => { err.push(String(s)); return true; };
  try {
    const code = await main(args);
    return { code, stdout: out.join(''), stderr: err.join('') };
  } finally {
    process.stdout.write = write.out;
    process.stderr.write = write.err;
  }
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'devkai-cli-'));

test('help and unknown command', async () => {
  assert.match((await run([])).stdout, /Usage/);
  const bad = await run(['nope']);
  assert.equal(bad.code, 2);
  assert.match(bad.stderr, /Unknown command "nope"/);
});

test('list shows checklists with manual and review tags', async () => {
  const { code, stdout } = await run(['list', '--only', 'security']);
  assert.equal(code, 0);
  assert.match(stdout, /SEC-001/);
  assert.match(stdout, /\[manual\]/);
  assert.match(stdout, /\[review\]/);
  assert.doesNotMatch(stdout, /LOG-001/);
});

test('scan writes every format and --fail-on sets the exit code', async () => {
  const out = tmp();
  const res = await run(['scan', fixture('vulnerable-api'), '--format', 'console,md,json,html', '--out', out, '--fail-on', 'critical', '-v']);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /Failing: found issues at or above "critical"/);
  assert.match(res.stdout, /devkai readiness — vulnerable-api/);
  for (const f of ['README.md', 'security.md', 'api.md', 'report.json', 'index.html']) assert.ok(fs.existsSync(path.join(out, f)), f);
  const ok = await run(['scan', fixture('secure-api'), '--format', 'json', '--out', out, '--fail-on', 'high', '--review', '--offline']);
  assert.equal(ok.code, 0);
  fs.rmSync(out, { recursive: true, force: true });
});

test('scan rejects a bad --fail-on value before scanning', async () => {
  await assert.rejects(run(['scan', fixture('secure-api'), '--fail-on', 'urgent', '--format', 'json', '--out', tmp()]), /--fail-on must be one of/);
});

test('apps, per-app scan and single-app fallback', async () => {
  const apps = await run(['apps', fixture('monorepo')]);
  assert.match(apps.stdout, /@shop\/admin\s+apps\/admin/);
  assert.match(apps.stdout, /4 app\(s\)/);

  const out = tmp();
  const per = await run(['scan', fixture('monorepo'), '--per-app', '--only', 'security', '--out', out]);
  assert.equal(per.code, 0);
  assert.match(per.stdout, /4 apps\]/);
  assert.ok(fs.existsSync(path.join(out, 'apps-api', 'security.md')));

  const single = await run(['scan', fixture('secure-api'), '--per-app', '--only', 'security', '--format', 'console', '--out', out]);
  assert.match(single.stdout, /Only one app found/);
  fs.rmSync(out, { recursive: true, force: true });
});

test('init writes a config once; config is honoured by scan', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { express: '^5.0.0' } }));
  fs.writeFileSync(path.join(dir, 'app.js'), 'const x = eval(input);\n');
  assert.match((await run(['init', dir])).stdout, /Created/);
  assert.match((await run(['init', dir])).stdout, /Already exists/);
  const cfgFile = path.join(dir, 'devkai.config.json');
  const cfg = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
  fs.writeFileSync(cfgFile, JSON.stringify({ ...cfg, disable: ['SEC-008'], outDir: 'out' }));
  const res = await run(['scan', dir, '--only', 'security', '--format', 'json']);
  const report = JSON.parse(fs.readFileSync(path.join(dir, 'out', 'report.json'), 'utf8'));
  assert.equal(res.code, 0);
  assert.equal(report.checklists[0].checks.find((c) => c.id === 'SEC-008').status, 'skip');
  fs.writeFileSync(cfgFile, '{ not json');
  await assert.rejects(run(['scan', dir, '--format', 'json']), /Invalid JSON/);
  fs.rmSync(dir, { recursive: true, force: true });
});
