import { color, SEVERITY_RANK, truncate } from '../core/utils.js';

const SEV_COLOR = {
  critical: (s) => color.bold(color.red(s)),
  high: color.red,
  medium: color.yellow,
  low: color.cyan,
  info: color.gray,
};

const ICON = {
  pass: color.green('✔'),
  fail: color.red('✖'),
  warn: color.yellow('▲'),
  skip: color.gray('–'),
  manual: color.blue('?'),
  error: color.magenta('!'),
};

function scoreColor(score, pad = 0) {
  if (score === null) return color.gray('n/a'.padEnd(pad));
  const s = `${score}/100`.padEnd(pad);
  if (score >= 90) return color.green(s);
  if (score >= 70) return color.yellow(s);
  return color.red(s);
}

export function printReport(report, { verbose = false } = {}) {
  const log = (s = '') => process.stdout.write(`${s}\n`);
  log();
  log(`${color.bold(`devkai readiness — ${report.project}`)} ${color.gray(`[${report.mode} scan]`)}`);
  log(color.gray(report.root));
  log();

  for (const cl of report.checklists) {
    const n = cl.counts;
    log(`${color.bold(cl.title.padEnd(22))} ${scoreColor(cl.score, 8)} ${color.gray(`${n.pass} pass · ${n.fail} missing · ${n.warn} review · ${n.manual - n.confirmed} manual`)}`);

    const shown = cl.checks
      .filter((c) => verbose || c.status === 'fail' || c.status === 'warn' || c.status === 'error')
      .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0));

    for (const c of shown) {
      const sev = (SEV_COLOR[c.severity] ?? String)(c.severity.padEnd(8));
      log(`  ${ICON[c.status] ?? ' '} ${sev} ${c.title} ${color.gray(c.id)}`);
      if (c.message && (verbose || c.status !== 'pass')) log(`      ${color.gray(truncate(c.message, 120))}`);
      for (const f of (c.findings ?? []).slice(0, 3)) {
        log(`      ${color.dim(`${f.file}${f.line ? `:${f.line}` : ''}`)}`);
      }
      if ((c.findingsTotal ?? 0) > 3) log(`      ${color.dim(`…${c.findingsTotal - 3} more`)}`);
    }
    log();
  }

  log(`${color.bold('Overall')}  ${scoreColor(report.score)}`);
  if (report.reviewChecksSkipped) {
    log(color.gray(`${report.reviewChecksSkipped} in-depth check(s) not run. Use --review for taint tracing, route auth audit, npm audit and comment-aware matching.`));
  }
  log();
}

const SHORT = { security: 'sec', logging: 'log', monitoring: 'mon', auditing: 'aud', database: 'db', scalability: 'scale', reliability: 'rel', cicd: 'ci/cd', frontend: 'web', api: 'api' };

function scoreCell(score, width) {
  if (score === null) return color.gray('–'.padStart(width));
  const s = String(score).padStart(width);
  if (score >= 90) return color.green(s);
  if (score >= 70) return color.yellow(s);
  return color.red(s);
}

export function printPerApp(report, { verbose = false } = {}) {
  const log = (s = '') => process.stdout.write(`${s}\n`);
  if (verbose) for (const r of report.reports) printReport(r, { verbose });
  log();
  log(`${color.bold(`devkai readiness — ${report.project}`)} ${color.gray(`[${report.mode} scan, ${report.reports.length} apps]`)}`);
  log(color.gray(report.root));
  log();
  const lists = report.reports[0]?.checklists ?? [];
  const nameWidth = Math.min(28, Math.max(8, ...report.reports.map((r) => r.app.name.length)));
  const w = 6;
  log(`${'app'.padEnd(nameWidth)}  ${'all'.padStart(w)}${lists.map((cl) => (SHORT[cl.id] ?? cl.id).padStart(w)).join('')}`);
  for (const r of report.reports) {
    const name = r.app.name.length > nameWidth ? `${r.app.name.slice(0, nameWidth - 1)}…` : r.app.name;
    log(`${name.padEnd(nameWidth)}  ${scoreCell(r.score, w)}${r.checklists.map((cl) => scoreCell(cl.score, w)).join('')}`);
  }
  log();
  for (const r of report.reports) {
    const worst = r.checklists
      .flatMap((cl) => cl.checks.filter((c) => c.status === 'fail' && (SEVERITY_RANK[c.severity] ?? 0) >= SEVERITY_RANK.high))
      .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0));
    if (!worst.length) continue;
    log(`${color.bold(r.app.name)} ${color.gray(r.app.dir)}`);
    for (const c of worst.slice(0, 4)) log(`  ${ICON.fail} ${(SEV_COLOR[c.severity] ?? String)(c.severity.padEnd(8))} ${c.title} ${color.gray(c.id)}`);
    if (worst.length > 4) log(color.gray(`  …${worst.length - 4} more high/critical`));
  }
  log();
  log(`${color.bold('Overall')}  ${scoreColor(report.score)}`);
  log();
}
