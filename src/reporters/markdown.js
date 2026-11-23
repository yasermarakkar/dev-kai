import fs from 'node:fs';
import path from 'node:path';
import { SEVERITY_RANK, truncate } from '../core/utils.js';

const STATUS_LABEL = {
  pass: 'PASS',
  fail: 'MISSING',
  warn: 'REVIEW',
  skip: 'N/A',
  manual: 'MANUAL',
  error: 'ERROR',
};

const ID_MARKER = (id) => `<!-- devkai:${id} -->`;
const TICK_RE = /^\s*-\s*\[([ xX])\].*<!--\s*devkai:([A-Z0-9-]+)\s*-->/;

/**
 * Read manual checks a human has ticked in previously generated files,
 * so re-running the scan never wipes their sign-off.
 */
export function readConfirmedManual(outDir) {
  const confirmed = new Set();
  if (!fs.existsSync(outDir)) return confirmed;
  for (const f of fs.readdirSync(outDir)) {
    if (!f.endsWith('.md')) continue;
    const text = fs.readFileSync(path.join(outDir, f), 'utf8');
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(TICK_RE);
      if (m && m[1].toLowerCase() === 'x') confirmed.add(m[2]);
    }
  }
  return confirmed;
}

function scoreBadge(score) {
  if (score === null) return 'n/a';
  if (score >= 90) return `${score}/100 (strong)`;
  if (score >= 70) return `${score}/100 (fair)`;
  if (score >= 50) return `${score}/100 (weak)`;
  return `${score}/100 (at risk)`;
}

function bySeverity(a, b) {
  return (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
}

function renderCheck(c) {
  const ticked = c.status === 'pass' || (c.status === 'manual' && c.confirmed);
  const box = c.status === 'skip' ? '~' : ticked ? 'x' : ' ';
  const lines = [];
  // Skipped items use a strike-through instead of a checkbox.
  if (box === '~') {
    lines.push(`- ~~${c.title}~~ \`${c.id}\` — ${c.message || 'not applicable'} ${ID_MARKER(c.id)}`);
    return lines.join('\n');
  }
  lines.push(`- [${box}] **${c.title}** \`${c.id}\` · ${c.severity} · ${STATUS_LABEL[c.status]}${c.review ? ' · in-depth' : ''} ${ID_MARKER(c.id)}`);
  if (c.message) lines.push(`  - ${c.message}`);
  if (c.status !== 'pass' && !(c.status === 'manual' && c.confirmed)) {
    if (c.why) lines.push(`  - **Why:** ${c.why}`);
    if (c.fix) lines.push(`  - **Fix:** ${c.fix}`);
    if (c.findings?.length) {
      lines.push('  - **Where:**');
      for (const f of c.findings) {
        const loc = f.line ? `${f.file}:${f.line}` : f.file;
        lines.push(`    - \`${loc}\`${f.text ? ` — \`${truncate(f.text, 110).replace(/`/g, "'")}\`` : ''}`);
        if (f.context?.length) {
          const width = String(f.context.at(-1).line).length;
          lines.push('');
          lines.push('      ```');
          for (const l of f.context) {
            const marker = l.line === f.line ? '>' : ' ';
            const text = l.text.length > 160 ? `${l.text.slice(0, 159)}…` : l.text;
            lines.push(`      ${marker} ${String(l.line).padStart(width)} | ${text.replace(/```/g, "'''")}`);
          }
          lines.push('      ```');
          lines.push('');
        }
      }
      if (c.findingsTotal > c.findings.length) {
        lines.push(`    - …and ${c.findingsTotal - c.findings.length} more`);
      }
    }
    if (c.docs?.length) lines.push(`  - **Docs:** ${c.docs.map((d) => `<${d}>`).join(' ')}`);
  }
  return lines.join('\n');
}

export function renderChecklist(report, cl) {
  const automated = cl.checks.filter((c) => !c.manual).sort(bySeverity);
  const manual = cl.checks.filter((c) => c.manual).sort(bySeverity);
  const n = cl.counts;
  const out = [];
  out.push(`# ${cl.title} checklist`);
  out.push('');
  out.push(`> ${cl.description}`);
  out.push('');
  out.push(`**Project:** ${report.project}  `);
  out.push(`**Score:** ${scoreBadge(cl.score)}  `);
  out.push(`**Result:** ${n.pass} pass · ${n.fail} missing · ${n.warn} to review · ${n.manual - n.confirmed} manual pending · ${n.skip} n/a  `);
  out.push(`**Generated:** ${report.generatedAt} by devkai-readiness (${report.mode} scan)`);
  out.push('');
  if (report.mode === 'quick' && cl.checks.length && report.reviewChecksSkipped) {
    out.push('> Quick scan: pattern matching only. Run `devkai scan --review` for in-depth checks (taint tracing, route auth, dependency CVEs).');
    out.push('');
  }
  out.push('## Automated checks');
  out.push('');
  out.push(automated.length ? automated.map(renderCheck).join('\n') : '_None._');
  out.push('');
  if (manual.length) {
    out.push('## Manual checks');
    out.push('');
    out.push('_These cannot be verified from code. Tick the box (`[x]`) once confirmed — your ticks are kept on the next scan._');
    out.push('');
    out.push(manual.map(renderCheck).join('\n'));
    out.push('');
  }
  return out.join('\n');
}

export function renderSummary(report) {
  const out = [];
  out.push(`# Production readiness — ${report.project}`);
  out.push('');
  out.push(`**Overall score:** ${scoreBadge(report.score)}  `);
  out.push(`**Mode:** ${report.mode === 'review' ? 'in-depth review' : 'quick scan (pattern matching) — use `--review` for in-depth analysis'}  `);
  out.push(`**Generated:** ${report.generatedAt}`);
  out.push('');
  const s = report.stack;
  const stackBits = [
    s.server.length && `server: ${s.server.join(', ')}`,
    s.fullstack.length && `fullstack: ${s.fullstack.join(', ')}`,
    s.frontend.length && `frontend: ${s.frontend.join(', ')}`,
    s.data.length && `data: ${s.data.join(', ')}`,
    s.typescript && 'TypeScript',
    s.docker && 'Docker',
    s.ci && 'CI',
  ].filter(Boolean);
  out.push(`**Detected stack:** ${stackBits.join(' · ') || 'unknown'}  `);
  out.push(`**Apps/packages:** ${report.apps.length ? report.apps.map((a) => `${a.name} (\`${a.dir}\`)`).join(', ') : 'none found'}`);
  out.push('');
  out.push('| Checklist | Score | Pass | Missing | Review | Manual pending |');
  out.push('|---|---|---|---|---|---|');
  for (const cl of report.checklists) {
    const n = cl.counts;
    out.push(`| [${cl.title}](./${cl.id}.md) | ${cl.score ?? 'n/a'} | ${n.pass} | ${n.fail} | ${n.warn} | ${n.manual - n.confirmed} |`);
  }
  out.push('');
  const top = report.checklists
    .flatMap((cl) => cl.checks.filter((c) => c.status === 'fail').map((c) => ({ ...c, checklist: cl.id })))
    .sort(bySeverity)
    .slice(0, 10);
  if (top.length) {
    out.push('## Fix first');
    out.push('');
    top.forEach((c, i) => out.push(`${i + 1}. **[${c.severity}]** ${c.title} \`${c.id}\` — ${c.fix}`));
    out.push('');
  }
  return out.join('\n');
}

export function writeMarkdown(report, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const written = [];
  for (const cl of report.checklists) {
    const file = path.join(outDir, `${cl.id}.md`);
    fs.writeFileSync(file, `${renderChecklist(report, cl)}\n`);
    written.push(file);
  }
  const summary = path.join(outDir, 'README.md');
  fs.writeFileSync(summary, `${renderSummary(report)}\n`);
  written.push(summary);
  return written;
}

// ---------------- per-app (monorepo) ----------------

function cell(score) {
  return score === null ? '–' : String(score);
}

export function renderPerAppSummary(report) {
  const ids = report.reports[0]?.checklists.map((cl) => cl) ?? [];
  const out = [];
  out.push(`# Production readiness — ${report.project}`);
  out.push('');
  out.push(`**Overall score:** ${scoreBadge(report.score)}  `);
  out.push(`**Apps:** ${report.reports.length}  `);
  out.push(`**Mode:** ${report.mode === 'review' ? 'in-depth review' : 'quick scan (pattern matching) — use `--review` for in-depth analysis'}  `);
  out.push(`**Generated:** ${report.generatedAt}`);
  out.push('');
  out.push('Each app is scanned with its own code and dependencies plus the shared repo files (CI, root config, infra). Click a score for that app\'s checklist; `–` means not applicable.');
  out.push('');
  out.push(`| App | Overall | ${ids.map((cl) => cl.title).join(' | ')} |`);
  out.push(`|---|---|${ids.map(() => '---').join('|')}|`);
  for (const r of report.reports) {
    const cells = r.checklists.map((cl) => (cl.score === null ? '–' : `[${cl.score}](./${r.app.slug}/${cl.id}.md)`));
    out.push(`| [${r.app.name}](./${r.app.slug}/README.md) \`${r.app.dir}\` | **${cell(r.score)}** | ${cells.join(' | ')} |`);
  }
  out.push('');
  const top = report.reports
    .flatMap((r) => r.checklists.flatMap((cl) => cl.checks.filter((c) => c.status === 'fail').map((c) => ({ ...c, app: r.app, checklist: cl.id }))))
    .sort(bySeverity)
    .slice(0, 15);
  if (top.length) {
    out.push('## Fix first (across all apps)');
    out.push('');
    top.forEach((c, i) => out.push(`${i + 1}. **[${c.severity}]** \`${c.app.name}\` — ${c.title} [\`${c.id}\`](./${c.app.slug}/${c.checklist}.md)`));
    out.push('');
  }
  return out.join('\n');
}

export function writeMarkdownPerApp(report, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const written = [];
  for (const r of report.reports) written.push(...writeMarkdown(r, path.join(outDir, r.app.slug)));
  const summary = path.join(outDir, 'README.md');
  fs.writeFileSync(summary, `${renderPerAppSummary(report)}\n`);
  written.push(summary);
  return written;
}
