import path from 'node:path';
import { parseArgs } from 'node:util';
import { runAudit, runAuditPerApp, discoverApps, worstFailure } from './core/runner.js';
import { loadConfig, writeDefaultConfig } from './core/config.js';
import { SEVERITY_RANK, color } from './core/utils.js';
import { checklists } from './checklists/index.js';
import { printReport, printPerApp } from './reporters/console.js';
import { writeMarkdown, writeMarkdownPerApp, readConfirmedManual } from './reporters/markdown.js';
import { writeJson } from './reporters/json.js';
import { writeHtml } from './reporters/html.js';

const HELP = `
${color.bold('devkai')} — production-readiness checklists for your apps

${color.bold('Usage')}
  devkai scan [dir]        Scan a project and write checklist files
  devkai list              List available checklists and checks
  devkai apps [dir]        List the apps found in a monorepo
  devkai init [dir]        Create devkai.config.json

${color.bold('Scan options')}
  -o, --only <ids>         Comma list of checklists (e.g. security,logging)
  -f, --format <list>      console,md,json,html (default: console,md)
                           html = self-contained dashboard (readiness/index.html)
      --out <dir>          Output folder (default: <dir>/readiness)
      --fail-on <sev>      Exit 1 if any failure at/above severity
                           (critical|high|medium|low) — for CI
  -r, --review             In-depth review: ignores comments, follows code across
                           lines, traces request input into sinks, audits routes
                           for auth, runs npm audit. Slower, more precise.
      --offline            With --review: skip checks that need the network
  -p, --per-app            Monorepo: one report per app (each app's own code
                           and deps + shared CI/config) and a score matrix
  -a, --app <names>        Only these apps (name or dir, comma list); implies
                           --per-app
  -c, --config <file>      Path to config file
  -v, --verbose            Show passing checks in console output
  -h, --help               Show help
`;

function parseList(v) {
  return v ? v.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
}

async function scan(positionals, values) {
  const root = path.resolve(positionals[0] ?? '.');
  const config = loadConfig(root, values.config);
  const outDir = path.resolve(root, values.out ?? config.outDir ?? 'readiness');
  const formats = new Set(parseList(values.format) ?? ['console', 'md']);

  // Never scan our own output.
  const relOut = path.relative(root, outDir).split(path.sep).join('/');
  if (relOut && !relOut.startsWith('..')) config.ignore = [...(config.ignore ?? []), relOut];

  if (values['fail-on'] && SEVERITY_RANK[values['fail-on']] === undefined) throw new Error('--fail-on must be one of: critical, high, medium, low');

  const common = { root, only: parseList(values.only), config, review: Boolean(values.review), offline: Boolean(values.offline) };
  const apps = parseList(values.app);
  let perApp = Boolean(values['per-app'] || apps?.length || config.perApp);
  if (perApp && !apps?.length && discoverApps(root, config).length < 2) {
    process.stdout.write(color.gray('Only one app found — writing a single report.\n'));
    perApp = false;
  }

  const report = perApp
    // Manual ticks are kept per app, in readiness/<app>/*.md
    ? await runAuditPerApp({ ...common, apps, confirmedFor: (app) => readConfirmedManual(path.join(outDir, app.slug)) })
    : await runAudit({ ...common, confirmed: readConfirmedManual(outDir) });

  if (formats.has('console')) (perApp ? printPerApp : printReport)(report, { verbose: values.verbose });
  const written = [];
  if (formats.has('md')) written.push(...(perApp ? writeMarkdownPerApp(report, outDir) : writeMarkdown(report, outDir)));
  if (formats.has('json')) written.push(...writeJson(report, outDir));
  if (formats.has('html')) written.push(...writeHtml(report, outDir));
  if (written.length) {
    const shown = written.length > 14
      ? [`${written.length} files in ${path.relative(process.cwd(), outDir) || '.'}/ (start with README.md)`]
      : written.map((f) => path.relative(process.cwd(), f));
    process.stdout.write(`${color.gray('Wrote:')}\n${shown.map((f) => `  ${f}`).join('\n')}\n\n`);
  }

  if (values['fail-on']) {
    const threshold = SEVERITY_RANK[values['fail-on']];
    if (worstFailure(report) >= threshold) {
      process.stderr.write(color.red(`Failing: found issues at or above "${values['fail-on']}".\n`));
      return 1;
    }
  }
  return 0;
}

function list(values) {
  const only = parseList(values.only);
  for (const cl of checklists) {
    if (only && !only.includes(cl.id)) continue;
    process.stdout.write(`\n${color.bold(cl.title)} ${color.gray(`(${cl.id})`)}\n${color.gray(cl.description)}\n`);
    for (const c of cl.checks) {
      const tag = c.manual ? color.blue('[manual] ') : c.review ? color.magenta('[review] ') : '';
      process.stdout.write(`  ${c.id.padEnd(9)} ${c.severity.padEnd(8)} ${tag}${c.title}\n`);
    }
  }
  process.stdout.write('\n');
  return 0;
}

export async function main(argv = process.argv.slice(2)) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      only: { type: 'string', short: 'o' },
      format: { type: 'string', short: 'f' },
      out: { type: 'string' },
      'fail-on': { type: 'string' },
      config: { type: 'string', short: 'c' },
      verbose: { type: 'boolean', short: 'v' },
      review: { type: 'boolean', short: 'r' },
      'per-app': { type: 'boolean', short: 'p' },
      app: { type: 'string', short: 'a' },
      offline: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const [command, ...rest] = positionals;
  if (values.help || !command) {
    process.stdout.write(HELP);
    return 0;
  }
  switch (command) {
    case 'scan':
      return scan(rest, values);
    case 'list':
      return list(values);
    case 'apps': {
      const root = path.resolve(rest[0] ?? '.');
      const found = discoverApps(root, loadConfig(root, values.config));
      for (const a of found) process.stdout.write(`  ${a.name.padEnd(30)} ${color.gray(a.dir)}\n`);
      process.stdout.write(color.gray(`${found.length} app(s)${found.length > 1 ? ' — scan them with: devkai scan --per-app' : ''}\n`));
      return 0;
    }
    case 'init': {
      const { file, created } = writeDefaultConfig(path.resolve(rest[0] ?? '.'));
      process.stdout.write(created ? `Created ${file}\n` : `Already exists: ${file}\n`);
      return 0;
    }
    default:
      process.stderr.write(`Unknown command "${command}".\n${HELP}`);
      return 2;
  }
}
