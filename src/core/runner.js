import { createContext } from './context.js';
import { SEVERITY_RANK, SEVERITY_WEIGHT } from './utils.js';
import { checklists as allChecklists } from '../checklists/index.js';

const FINDINGS_LIMIT = 25;

/**
 * Score = weighted share of applicable checks that pass.
 * warn earns half credit; skip/error/unconfirmed manual are excluded.
 */
export function computeScore(checks) {
  let earned = 0;
  let possible = 0;
  for (const c of checks) {
    const w = SEVERITY_WEIGHT[c.severity] ?? 1;
    if (c.status === 'pass' || (c.status === 'manual' && c.confirmed)) {
      earned += w;
      possible += w;
    } else if (c.status === 'warn') {
      earned += w / 2;
      possible += w;
    } else if (c.status === 'fail') {
      possible += w;
    }
  }
  return possible === 0 ? null : Math.round((earned / possible) * 100);
}

function tally(checks) {
  const counts = { pass: 0, fail: 0, warn: 0, skip: 0, manual: 0, confirmed: 0, error: 0 };
  for (const c of checks) {
    counts[c.status] = (counts[c.status] ?? 0) + 1;
    if (c.status === 'manual' && c.confirmed) counts.confirmed++;
  }
  return counts;
}

export function selectChecklists(only) {
  if (!only?.length) return allChecklists;
  const unknown = only.filter((id) => !allChecklists.some((c) => c.id === id));
  if (unknown.length) {
    throw new Error(`Unknown checklist(s): ${unknown.join(', ')}. Available: ${allChecklists.map((c) => c.id).join(', ')}`);
  }
  return allChecklists.filter((c) => only.includes(c.id));
}

/**
 * Run the audit.
 * @param {{
 *   root: string,
 *   only?: string[],
 *   config?: { ignore?: string[], disable?: string[], severity?: Record<string,string> },
 *   confirmed?: Set<string>,  // manual check ids a human already ticked
 *   review?: boolean,         // in-depth mode: comment-aware, multi-line, taint + route analysis
 *   offline?: boolean,        // skip checks that need the network (e.g. npm audit)
 * }} opts
 */
export async function runAudit({ root, only, config = {}, confirmed = new Set(), review = false, offline = false }) {
  const ctx = createContext(root, config, { review, offline });
  const disabled = new Set(config.disable ?? []);
  const results = [];
  let reviewOnly = 0;

  for (const checklist of selectChecklists(only)) {
    const checks = [];
    for (const check of checklist.checks) {
      if (check.review && !review) {
        reviewOnly++;
        continue;
      }
      const base = {
        id: check.id,
        title: check.title,
        severity: config.severity?.[check.id] ?? check.severity,
        why: check.why,
        fix: check.fix,
        docs: check.docs,
        tags: check.tags,
        manual: check.manual,
        review: Boolean(check.review),
      };

      if (disabled.has(check.id)) {
        checks.push({ ...base, status: 'skip', message: 'Disabled in config' });
        continue;
      }
      if (check.manual) {
        checks.push({ ...base, status: 'manual', confirmed: confirmed.has(check.id), message: check.prompt ?? '' });
        continue;
      }

      let result;
      try {
        result = (await check.run(ctx)) ?? { status: 'error', message: 'Check returned nothing' };
      } catch (err) {
        result = { status: 'error', message: `Check crashed: ${err.message}` };
      }
      // Several patterns in one check can hit the same line — keep one finding per location.
      const seen = new Set();
      const findings = (result.findings ?? []).filter((f) => {
        const key = `${f.file}:${f.line ?? ''}:${f.line ? '' : f.text ?? ''}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
      checks.push({
        ...base,
        status: result.status,
        message: result.message ?? '',
        findings: findings.slice(0, FINDINGS_LIMIT),
        findingsTotal: findings.length,
      });
    }

    results.push({
      id: checklist.id,
      title: checklist.title,
      description: checklist.description,
      score: computeScore(checks),
      counts: tally(checks),
      checks,
    });
  }

  const everyCheck = results.flatMap((r) => r.checks);
  return {
    tool: 'devkai-readiness',
    generatedAt: new Date().toISOString(),
    mode: review ? 'review' : 'quick',
    reviewChecksSkipped: reviewOnly,
    project: ctx.name,
    root: ctx.root,
    stack: ctx.stack,
    apps: ctx.apps.map((a) => ({ name: a.name, dir: a.dir })),
    score: computeScore(everyCheck),
    counts: tally(everyCheck),
    checklists: results,
  };
}

/** Highest failing severity rank in the report, or -1. */
export function worstFailure(report) {
  let worst = -1;
  for (const cl of report.checklists) {
    for (const c of cl.checks) {
      if (c.status === 'fail') worst = Math.max(worst, SEVERITY_RANK[c.severity] ?? 0);
    }
  }
  return worst;
}
