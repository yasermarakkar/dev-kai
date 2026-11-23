/**
 * Deep security checks — only run with `devkai scan --review`.
 */
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { defineCheck, pass, fail, warn, skip } from '../core/check.js';
import { findTaintedSinks, findRoutes, PUBLIC_PATH_RE } from '../core/analysis.js';

const OWASP = 'https://cheatsheetseries.owasp.org/cheatsheets';

export const unauthenticatedRoutes = defineCheck({
  id: 'SEC-R01',
  review: true,
  title: 'State-changing routes require authentication',
  severity: 'critical',
  tags: ['auth', 'routes'],
  why: 'A POST/PUT/PATCH/DELETE route without an auth guard lets anyone change data.',
  fix: 'Attach auth middleware/guards to every mutating route (or mount the router behind one). Mark intentionally public routes explicitly (e.g. @Public()).',
  docs: [`${OWASP}/Authorization_Cheat_Sheet.html`],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const routes = ctx.appCodeFiles.flatMap((f) => findRoutes(f, ctx.code(f) ?? '').map((r) => ({ ...r, file: f })));
    if (!routes.length) return skip('No state-changing routes found.');
    const open = routes.filter((r) => !r.protected && !PUBLIC_PATH_RE.test(r.path));
    const findings = open.map((r) => ctx.at(r.file, r.line, `${r.method} ${r.path || '(dynamic)'} — no auth guard seen`));
    if (!open.length) return pass(`${routes.length} mutating route(s); all guarded or intentionally public.`);
    // Auth may be applied where routers are mounted, in another file.
    const mountedAuth = ctx.contains(/\.use\s*\([^)]*(auth|protect|guard|jwt|passport|requireAuth|clerk)/i) || ctx.contains(/APP_GUARD/);
    const msg = `${open.length} of ${routes.length} mutating route(s) have no auth guard in the same file.`;
    return mountedAuth
      ? warn(`${msg} Global/mount-level auth exists — confirm these routers are mounted behind it.`, findings)
      : fail(msg, findings);
  },
});

export const taintedSinks = defineCheck({
  id: 'SEC-R02',
  review: true,
  title: 'Request input does not reach dangerous sinks',
  severity: 'critical',
  tags: ['injection'],
  why: 'Tracing req.body/query/params into SQL, shell, file paths, redirects or outbound URLs finds injection bugs that single-line patterns miss.',
  fix: 'Parameterize queries, use execFile with arg arrays, resolve paths against an allow-listed base dir, allow-list redirect targets and outbound hosts, escape HTML output.',
  docs: [`${OWASP}/Injection_Prevention_Cheat_Sheet.html`, `${OWASP}/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html`],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const findings = [];
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code) continue;
      for (const h of findTaintedSinks(code)) findings.push(ctx.at(f, h.line, `${h.kind}: ${h.arg}`));
    }
    if (!findings.length) return pass('No request input traced into SQL, shell, fs, redirect, fetch or HTML sinks.');
    const kinds = [...new Set(findings.map((x) => x.text.split(':')[0]))];
    return fail(`${findings.length} tainted flow(s): ${kinds.join(', ')}.`, findings);
  },
});

export const massAssignment = defineCheck({
  id: 'SEC-R03',
  review: true,
  title: 'No mass assignment of request bodies into models',
  severity: 'high',
  tags: ['input', 'database'],
  why: 'Passing req.body straight to create/update lets attackers set fields like role, isAdmin or ownerId.',
  fix: 'Pick allowed fields explicitly or parse with a strict schema (`z.object({...}).strict()`) before writing.',
  docs: [`${OWASP}/Mass_Assignment_Cheat_Sheet.html`],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const findings = [
      ...ctx.grep(/\.(create|update|insert|insertOne|insertMany|updateOne|updateMany|upsert|build|bulkCreate|findByIdAndUpdate|findOneAndUpdate|save|merge)\s*\(\s*(\{\s*)?(data\s*:\s*)?(\.\.\.)?(req|request|ctx\.request)\.body\s*[,)}]/),
      ...ctx.grep(/Object\.assign\s*\(\s*\w+\s*,\s*(req|request|ctx\.request)\.body\s*\)/),
      ...ctx.grep(/new\s+[A-Z]\w*\s*\(\s*(req|request)\.body\s*\)/),
    ];
    return findings.length ? fail('Request body written to the database unfiltered.', findings) : pass('No direct req.body → model writes found.');
  },
});

function runAudit(cwd, tool) {
  const args = tool === 'pnpm' ? ['audit', '--json', '--prod'] : ['audit', '--json', '--omit=dev'];
  const r = spawnSync(tool, args, { cwd, encoding: 'utf8', timeout: 90_000, maxBuffer: 64 * 1024 * 1024 });
  if (r.error) return { error: r.error.code === 'ENOENT' ? `${tool} not installed` : r.error.message };
  try {
    return { data: JSON.parse(r.stdout) };
  } catch {
    return { error: (r.stderr || r.stdout || 'no output').split('\n').find(Boolean)?.slice(0, 160) };
  }
}

export const knownVulnerabilities = defineCheck({
  id: 'SEC-R04',
  review: true,
  title: 'No known-vulnerable production dependencies',
  severity: 'high',
  tags: ['supply-chain'],
  why: 'Dependencies with published CVEs are the easiest way in — exploits are public.',
  fix: 'Run `npm audit fix`, bump the listed packages, or replace abandoned ones. Use overrides for transitive deps.',
  docs: ['https://docs.npmjs.com/cli/commands/npm-audit'],
  run(ctx) {
    if (ctx.offline) return skip('Skipped (--offline).');
    const locks = ctx.findFiles(/(^|\/)(package-lock\.json|pnpm-lock\.yaml)$/);
    if (!locks.length) return skip('No npm/pnpm lockfile to audit.');
    const findings = [];
    const errors = [];
    const totals = { critical: 0, high: 0, moderate: 0, low: 0 };
    for (const lock of locks) {
      const dir = path.join(ctx.root, path.posix.dirname(lock));
      const tool = lock.endsWith('pnpm-lock.yaml') ? 'pnpm' : 'npm';
      const { data, error } = runAudit(dir, tool);
      if (error || data?.error) {
        errors.push(`${lock}: ${error ?? data.error?.summary ?? 'audit failed'}`);
        continue;
      }
      const meta = data.metadata?.vulnerabilities ?? {};
      for (const k of Object.keys(totals)) totals[k] += meta[k] ?? 0;
      for (const [name, v] of Object.entries(data.vulnerabilities ?? data.advisories ?? {})) {
        const sev = v.severity;
        if (sev !== 'critical' && sev !== 'high') continue;
        const title = Array.isArray(v.via) ? v.via.find((x) => typeof x === 'object')?.title : v.title;
        findings.push({ file: lock, text: `${v.name ?? name} (${sev})${title ? ` — ${title}` : ''}${v.fixAvailable ? ' · fix available' : ''}` });
      }
    }
    if (errors.length && !findings.length && totals.critical + totals.high + totals.moderate + totals.low === 0) {
      return skip(`Audit could not run: ${errors.join('; ')}`);
    }
    const summary = `critical ${totals.critical} · high ${totals.high} · moderate ${totals.moderate} · low ${totals.low}`;
    if (totals.critical || totals.high) return fail(summary, findings);
    if (totals.moderate) return warn(summary);
    return pass(`No known vulnerabilities (${summary}).`);
  },
});

export const reviewChecks = [unauthenticatedRoutes, taintedSinks, massAssignment, knownVulnerabilities];
