/**
 * Check result helpers. A check's `run(ctx)` returns one of these.
 *
 * Statuses:
 *   pass   – requirement met
 *   fail   – requirement missing / violated
 *   warn   – partially met or needs a look
 *   skip   – not applicable to this project
 *   manual – cannot be verified from code; a human must tick it
 *   error  – the check itself crashed
 */

export const pass = (message) => ({ status: 'pass', message });
export const fail = (message, findings = []) => ({ status: 'fail', message, findings });
export const warn = (message, findings = []) => ({ status: 'warn', message, findings });
export const skip = (message) => ({ status: 'skip', message });

/** Drop findings that point at the same file:line (several patterns can hit one line). */
export function unique(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const key = `${f.file}:${f.line ?? f.text}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Define a check with defaults filled in.
 * @param {{
 *   id: string, title: string, severity: 'critical'|'high'|'medium'|'low'|'info',
 *   why: string, fix: string, docs?: string[], tags?: string[],
 *   manual?: boolean, run?: (ctx: any) => any
 * }} def
 */
export function defineCheck(def) {
  if (!def.id || !def.title || !def.severity) throw new Error(`Invalid check definition: ${JSON.stringify(def)}`);
  if (!def.manual && typeof def.run !== 'function') throw new Error(`Check ${def.id} needs run() or manual: true`);
  return { docs: [], tags: [], manual: false, ...def };
}

/**
 * Define a checklist (one category, one output file).
 * @param {{ id: string, title: string, description: string, checks: any[] }} def
 */
export function defineChecklist(def) {
  const ids = new Set();
  for (const c of def.checks) {
    if (ids.has(c.id)) throw new Error(`Duplicate check id ${c.id} in ${def.id}`);
    ids.add(c.id);
  }
  return def;
}
