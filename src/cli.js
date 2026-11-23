import path from 'node:path';
import { parseArgs } from 'node:util';
import { runAudit, worstFailure } from './core/runner.js';
import { loadConfig, writeDefaultConfig } from './core/config.js';
import { SEVERITY_RANK, color } from './core/utils.js';
import { checklists } from './checklists/index.js';
import { printReport } from './reporters/console.js';
import { writeMarkdown, readConfirmedManual } from './reporters/markdown.js';
import { writeJson } from './reporters/json.js';

const HELP = `
${color.bold('devkai')} — production-readiness checklists for your apps

${color.bold('Usage')}
  devkai scan [dir]        Scan a project and write checklist files
  devkai list              List available checklists and checks
  devkai init [dir]        Create devkai.config.json

${color.bold('Scan options')}
  -o, --only <ids>         Comma list of checklists (e.g. security,logging)
  -f, --format <list>      console,md,json (default: console,md)
      --out <dir>          Output folder (default: <dir>/readiness)
      --fail-on <sev>      Exit 1 if any failure at/above severity
                           (critical|high|medium|low) — for CI
  -r, --review             In-depth review: ignores comments, follows code across
                           lines, traces request input into sinks, audits routes
                           for auth, runs npm audit. Slower, more precise.
      --offline            With --review: skip checks that need the network
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

  const confirmed = readConfirmedManual(outDir);
  const report = await runAudit({
    root,
    only: parseList(values.only),
    config,
    confirmed,
    review: Boolean(values.review),
    offline: Boolean(values.offline),
  });

  if (formats.has('console')) printReport(report, { verbose: values.verbose });
  const written = [];
  if (formats.has('md')) written.push(...writeMarkdown(report, outDir));
  if (formats.has('json')) written.push(...writeJson(report, outDir));
  if (written.length) {
    process.stdout.write(`${color.gray('Wrote:')}\n${written.map((f) => `  ${path.relative(process.cwd(), f)}`).join('\n')}\n\n`);
  }

  if (values['fail-on']) {
    const threshold = SEVERITY_RANK[values['fail-on']];
    if (threshold === undefined) throw new Error(`--fail-on must be one of: critical, high, medium, low`);
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
