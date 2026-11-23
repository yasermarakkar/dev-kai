import fs from 'node:fs';
import path from 'node:path';

/**
 * Self-contained HTML dashboard (no external requests, works from file://).
 *
 * Report content comes from scanned source code, so it is treated as untrusted:
 *  - data is embedded as JSON with `<`, `>`, `&`, U+2028/2029 escaped (no </script> breakout)
 *  - the page builds DOM with textContent / createElement only — never innerHTML with data
 *  - links are only rendered for http(s) URLs
 */

/** Normalise single and per-app reports to one shape for the page. */
function toModel(report) {
  const reports = report.perApp ? report.reports : [{ ...report, app: { name: report.project, dir: '.', slug: 'root' } }];
  return {
    project: report.project,
    generatedAt: report.generatedAt,
    mode: report.mode,
    perApp: Boolean(report.perApp),
    score: report.score,
    counts: report.counts,
    reviewChecksSkipped: report.perApp ? report.reports[0]?.reviewChecksSkipped ?? 0 : report.reviewChecksSkipped ?? 0,
    apps: reports.map((r) => ({
      name: r.app.name,
      dir: r.app.dir,
      slug: r.app.slug,
      score: r.score,
      stack: r.stack,
      checklists: r.checklists.map((cl) => ({
        id: cl.id,
        title: cl.title,
        description: cl.description,
        score: cl.score,
        counts: cl.counts,
        checks: cl.checks.map((c) => ({
          id: c.id,
          title: c.title,
          severity: c.severity,
          status: c.status,
          confirmed: Boolean(c.confirmed),
          manual: Boolean(c.manual),
          review: Boolean(c.review),
          message: c.message ?? '',
          why: c.why ?? '',
          fix: c.fix ?? '',
          docs: (c.docs ?? []).filter((d) => /^https?:\/\//.test(d)),
          findings: (c.findings ?? []).map((f) => ({ file: f.file, line: f.line ?? null, text: f.text ?? '', context: f.context ?? null })),
          findingsTotal: c.findingsTotal ?? 0,
        })),
      })),
    })),
  };
}

/** JSON that is safe to place inside a <script> element. */
export function safeJson(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

const escapeText = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const CSS = String.raw`
:root {
  --bg: #f7f7f5; --surface: #ffffff; --surface-2: #f1f1ee; --border: #e3e2dd; --text: #1d1d1b; --muted: #6b6a64;
  --accent: #2f5bd3; --good: #1f7a4d; --fair: #a26300; --bad: #b42318;
  --sev-critical: #9f1239; --sev-high: #c2410c; --sev-medium: #a16207; --sev-low: #1d4ed8; --sev-info: #6b7280;
  --good-bg: #e7f4ec; --fair-bg: #fdf1dc; --bad-bg: #fbe7e5; --na-bg: #efefec;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #141413; --surface: #1d1d1b; --surface-2: #262624; --border: #34342f; --text: #ecebe6; --muted: #a09e96;
    --accent: #8aa8ff; --good: #5cc98e; --fair: #f0b357; --bad: #ff8a80;
    --sev-critical: #fb7185; --sev-high: #fb923c; --sev-medium: #facc15; --sev-low: #93c5fd; --sev-info: #a1a1aa;
    --good-bg: #173326; --fair-bg: #3a2b10; --bad-bg: #3d1917; --na-bg: #2a2a27;
  }
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--bg); color: var(--text); }
body { font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
a { color: var(--accent); }
.wrap { max-width: 1180px; margin: 0 auto; padding: 24px 16px 64px; }
header { display: flex; flex-wrap: wrap; gap: 16px 32px; align-items: flex-end; justify-content: space-between; margin-bottom: 24px; }
h1 { font-size: 24px; line-height: 1.2; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 32px 0 12px; font-weight: 600; }
.meta { color: var(--muted); font-size: 13px; }
.mode { display: inline-block; padding: 1px 8px; border-radius: 99px; background: var(--surface-2); border: 1px solid var(--border); font-size: 12px; margin-left: 6px; }
.overall { display: flex; gap: 20px; align-items: center; }
.big { font-size: 44px; font-weight: 700; line-height: 1; font-variant-numeric: tabular-nums; }
.big small { font-size: 16px; color: var(--muted); font-weight: 500; }
.stats { display: grid; grid-template-columns: repeat(4, auto); gap: 2px 16px; font-size: 13px; }
.stats b { font-variant-numeric: tabular-nums; font-size: 16px; display: block; }
.good { color: var(--good); } .fair { color: var(--fair); } .bad { color: var(--bad); } .na { color: var(--muted); }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; }
.matrix { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { padding: 8px 10px; text-align: center; border-bottom: 1px solid var(--border); white-space: nowrap; }
th { font-weight: 600; color: var(--muted); font-size: 12px; }
th:first-child, td:first-child { text-align: left; position: sticky; left: 0; background: var(--surface); }
tr:last-child td { border-bottom: 0; }
td.cell { cursor: pointer; font-variant-numeric: tabular-nums; font-weight: 600; }
td.cell span { display: inline-block; min-width: 38px; padding: 2px 6px; border-radius: 6px; }
.s-good { background: var(--good-bg); color: var(--good); } .s-fair { background: var(--fair-bg); color: var(--fair); }
.s-bad { background: var(--bad-bg); color: var(--bad); } .s-na { background: var(--na-bg); color: var(--muted); font-weight: 400; }
tr.sel td { background: var(--surface-2); }
.appname { cursor: pointer; font-weight: 600; } .appname small { color: var(--muted); font-weight: 400; margin-left: 6px; font-family: var(--mono); font-size: 11px; }
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 12px; }
.card { padding: 14px; cursor: pointer; text-align: left; font: inherit; color: inherit; transition: border-color .15s; }
.card:hover, .card.active { border-color: var(--accent); }
.card .top { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
.card .t { font-weight: 600; } .card .sc { font-size: 22px; font-weight: 700; font-variant-numeric: tabular-nums; }
.bar { height: 6px; background: var(--surface-2); border-radius: 99px; margin: 10px 0 8px; overflow: hidden; }
.bar i { display: block; height: 100%; border-radius: 99px; }
.card .c { font-size: 12px; color: var(--muted); }
.filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 12px; margin-bottom: 12px; }
select, input[type=search] { font: inherit; font-size: 13px; padding: 6px 8px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface); color: var(--text); }
input[type=search] { flex: 1 1 200px; min-width: 0; }
.chip { font: inherit; font-size: 12px; padding: 4px 10px; border-radius: 99px; border: 1px solid var(--border); background: var(--surface); color: var(--muted); cursor: pointer; }
.chip[aria-pressed=true] { background: var(--text); color: var(--surface); border-color: var(--text); }
.count { color: var(--muted); font-size: 13px; margin: 0 0 8px; }
.issue { border-bottom: 1px solid var(--border); }
.issue:last-child { border-bottom: 0; }
.issue > button { all: unset; box-sizing: border-box; display: grid; grid-template-columns: 78px 1fr auto; gap: 4px 12px; width: 100%; padding: 12px 14px; cursor: pointer; align-items: baseline; }
.issue > button:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
.sev { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
.sev-critical { color: var(--sev-critical); } .sev-high { color: var(--sev-high); } .sev-medium { color: var(--sev-medium); } .sev-low { color: var(--sev-low); } .sev-info { color: var(--sev-info); }
.it { font-weight: 600; } .it .id { font-family: var(--mono); font-size: 11px; color: var(--muted); font-weight: 400; margin-left: 6px; }
.tags { font-size: 12px; color: var(--muted); text-align: right; }
.st { display: inline-block; font-size: 11px; padding: 1px 7px; border-radius: 99px; margin-left: 6px; border: 1px solid var(--border); }
.st-fail { color: var(--bad); border-color: currentColor; } .st-warn { color: var(--fair); border-color: currentColor; }
.st-pass { color: var(--good); border-color: currentColor; } .st-manual { color: var(--accent); border-color: currentColor; }
.msg { grid-column: 2 / 4; color: var(--muted); font-size: 13px; }
.detail { padding: 0 14px 16px 104px; font-size: 14px; }
.detail p { margin: 6px 0; } .detail b { font-weight: 600; }
.loc { font-family: var(--mono); font-size: 12px; margin: 8px 0 2px; word-break: break-all; }
.loc span { color: var(--muted); }
pre { font-family: var(--mono); font-size: 12px; background: var(--surface-2); border-radius: 6px; padding: 8px 10px; margin: 4px 0 8px; overflow-x: auto; }
pre .hl { background: var(--fair-bg); display: block; }
.empty { padding: 32px; text-align: center; color: var(--muted); }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; }
@media (max-width: 640px) {
  .issue > button { grid-template-columns: 1fr; }
  .tags { text-align: left; } .msg { grid-column: 1; }
  .detail { padding-left: 14px; }
  .stats { grid-template-columns: repeat(2, auto); }
}
`;

const SCRIPT = String.raw`
(() => {
  const data = JSON.parse(document.getElementById('devkai-data').textContent);
  const SEV = ['critical', 'high', 'medium', 'low', 'info'];
  const STATUS = { fail: 'Missing', warn: 'Review', manual: 'Manual', pass: 'Pass', skip: 'N/A', error: 'Error' };
  const state = { app: 'all', checklist: 'all', sev: new Set(['critical', 'high', 'medium', 'low', 'info']), status: new Set(['fail', 'warn', 'error']), q: '' };

  const el = (tag, attrs = {}, ...children) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? '' : v);
    }
    n.append(...nodes(children));
    return n;
  };
  // Deep-flatten children (arrays of arrays from .map) and turn values into text nodes.
  function nodes(children) {
    return children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false && c !== '')
      .map((c) => (c instanceof Node ? c : document.createTextNode(String(c))));
  }
  const put = (box, ...children) => box.replaceChildren(...nodes(children));
  const tone = (s) => (s === null || s === undefined ? 'na' : s >= 90 ? 'good' : s >= 70 ? 'fair' : 'bad');
  const scoreText = (s) => (s === null || s === undefined ? '–' : String(s));

  // ---------- header ----------
  const headerStats = () => {
    const c = data.counts;
    return el('div', { class: 'overall' },
      el('div', { class: 'big ' + tone(data.score) }, scoreText(data.score), el('small', {}, ' /100')),
      el('div', { class: 'stats' },
        el('div', {}, el('b', { class: 'bad' }, c.fail), 'missing'),
        el('div', {}, el('b', { class: 'fair' }, c.warn), 'to review'),
        el('div', {}, el('b', {}, c.manual - c.confirmed), 'manual pending'),
        el('div', {}, el('b', { class: 'good' }, c.pass + c.confirmed), 'passing')));
  };
  put(document.getElementById('summary'), headerStats());

  // ---------- app matrix ----------
  const lists = data.apps[0]?.checklists ?? [];
  const renderMatrix = () => {
    const box = document.getElementById('apps');
    if (!data.perApp) { box.closest('section').hidden = true; return; }
    const head = el('tr', {}, el('th', {}, 'App'), el('th', {}, 'Overall'), lists.map((cl) => el('th', { title: cl.title }, cl.title)));
    const rows = data.apps.map((a) => el('tr', { class: state.app === a.slug ? 'sel' : '' },
      el('td', { class: 'appname', onclick: () => setFilter({ app: state.app === a.slug ? 'all' : a.slug, checklist: 'all' }) }, a.name, el('small', {}, a.dir)),
      el('td', { class: 'cell', onclick: () => setFilter({ app: a.slug, checklist: 'all' }) }, el('span', { class: 's-' + tone(a.score) }, scoreText(a.score))),
      a.checklists.map((cl) => el('td', { class: 'cell', title: a.name + ' · ' + cl.title, onclick: () => setFilter({ app: a.slug, checklist: cl.id }) },
        el('span', { class: 's-' + tone(cl.score) }, scoreText(cl.score))))));
    put(box, el('table', {}, el('thead', {}, head), el('tbody', {}, rows)));
  };

  // ---------- checklist cards (aggregated over selected app / all apps) ----------
  const appsInScope = () => data.apps.filter((a) => state.app === 'all' || a.slug === state.app);
  const renderCards = () => {
    const cards = lists.map((cl0) => {
      const per = appsInScope().map((a) => a.checklists.find((c) => c.id === cl0.id));
      const scores = per.map((c) => c.score).filter((s) => s !== null);
      const score = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;
      const sum = (k) => per.reduce((n, c) => n + (c.counts[k] ?? 0), 0);
      return el('button', { class: 'panel card' + (state.checklist === cl0.id ? ' active' : ''), title: cl0.description, onclick: () => setFilter({ checklist: state.checklist === cl0.id ? 'all' : cl0.id }) },
        el('div', { class: 'top' }, el('span', { class: 't' }, cl0.title), el('span', { class: 'sc ' + tone(score) }, scoreText(score))),
        el('div', { class: 'bar' }, el('i', { style: 'width:' + (score ?? 0) + '%;background:var(--' + (tone(score) === 'na' ? 'border' : tone(score)) + ')' })),
        el('div', { class: 'c' }, score === null ? 'not applicable' : sum('fail') + ' missing · ' + sum('warn') + ' review · ' + (sum('manual') - sum('confirmed')) + ' manual'));
    });
    put(document.getElementById('cards'), cards);
  };

  // ---------- filters ----------
  const renderFilters = () => {
    const appSel = el('select', { 'aria-label': 'App', onchange: (e) => setFilter({ app: e.target.value }) },
      el('option', { value: 'all' }, 'All apps'), data.apps.map((a) => el('option', { value: a.slug, selected: state.app === a.slug }, a.name)));
    const clSel = el('select', { 'aria-label': 'Checklist', onchange: (e) => setFilter({ checklist: e.target.value }) },
      el('option', { value: 'all' }, 'All checklists'), lists.map((cl) => el('option', { value: cl.id, selected: state.checklist === cl.id }, cl.title)));
    const chip = (set, key, label) => el('button', { class: 'chip', 'aria-pressed': String(set.has(key)), onclick: () => { set.has(key) ? set.delete(key) : set.add(key); render(); } }, label);
    const search = el('input', { type: 'search', placeholder: 'Search title, id, file…', value: state.q, 'aria-label': 'Search', oninput: (e) => { state.q = e.target.value; renderIssues(); } });
    const box = document.getElementById('filters');
    put(box,
      data.perApp ? appSel : '', clSel,
      SEV.map((s) => chip(state.sev, s, s)),
      ['fail', 'warn', 'manual', 'pass', 'skip'].map((s) => chip(state.status, s, STATUS[s])),
      search);
  };

  // ---------- issues ----------
  const matches = (c, a, cl) => {
    if (!state.sev.has(c.severity) || !state.status.has(c.status === 'manual' && c.confirmed ? 'pass' : c.status)) return false;
    if (!state.q) return true;
    const q = state.q.toLowerCase();
    return [c.title, c.id, c.message, a.name, cl.title, ...c.findings.map((f) => f.file + ' ' + f.text)].some((s) => String(s).toLowerCase().includes(q));
  };
  const detail = (c) => el('div', { class: 'detail' },
    c.why ? el('p', {}, el('b', {}, 'Why: '), c.why) : '',
    c.fix ? el('p', {}, el('b', {}, 'Fix: '), c.fix) : '',
    c.findings.length ? el('div', {}, el('p', {}, el('b', {}, 'Where:')), c.findings.map((f) => [
      el('div', { class: 'loc' }, f.file + (f.line ? ':' + f.line : ''), f.text ? el('span', {}, ' — ' + f.text) : ''),
      f.context ? el('pre', {}, f.context.map((l) => el('span', { class: l.line === f.line ? 'hl' : '' }, String(l.line).padStart(4) + ' │ ' + l.text + '\n'))) : '',
    ]), c.findingsTotal > c.findings.length ? el('p', { class: 'meta' }, '…and ' + (c.findingsTotal - c.findings.length) + ' more') : '') : '',
    c.docs.length ? el('p', {}, el('b', {}, 'Docs: '), c.docs.map((d, i) => [i ? ' · ' : '', el('a', { href: d, target: '_blank', rel: 'noopener noreferrer' }, new URL(d).hostname)])) : '');
  const renderIssues = () => {
    const rows = [];
    for (const a of appsInScope()) for (const cl of a.checklists) {
      if (state.checklist !== 'all' && cl.id !== state.checklist) continue;
      for (const c of cl.checks) if (matches(c, a, cl)) rows.push({ c, a, cl });
    }
    rows.sort((x, y) => SEV.indexOf(x.c.severity) - SEV.indexOf(y.c.severity) || x.cl.id.localeCompare(y.cl.id) || x.a.name.localeCompare(y.a.name));
    const list = rows.map(({ c, a, cl }) => {
      const status = c.status === 'manual' && c.confirmed ? 'pass' : c.status;
      const item = el('div', { class: 'issue' });
      const btn = el('button', { 'aria-expanded': 'false', onclick: () => {
        const open = btn.getAttribute('aria-expanded') === 'true';
        btn.setAttribute('aria-expanded', String(!open));
        if (open) item.querySelector('.detail')?.remove(); else item.append(detail(c));
      } },
        el('span', { class: 'sev sev-' + c.severity }, c.severity),
        el('span', { class: 'it' }, c.title, el('span', { class: 'id' }, c.id), el('span', { class: 'st st-' + status }, c.status === 'manual' && c.confirmed ? 'Confirmed' : STATUS[c.status] ?? c.status), c.review ? el('span', { class: 'st' }, 'in-depth') : ''),
        el('span', { class: 'tags' }, (data.perApp ? a.name + ' · ' : '') + cl.title),
        c.message ? el('span', { class: 'msg' }, c.message) : '');
      item.append(btn);
      return item;
    });
    document.getElementById('count').textContent = rows.length + ' item' + (rows.length === 1 ? '' : 's');
    put(document.getElementById('issues'), list.length ? list : el('div', { class: 'empty' }, 'Nothing matches these filters.'));
  };

  const setFilter = (patch) => { Object.assign(state, patch); render(); };
  const render = () => { renderMatrix(); renderCards(); renderFilters(); renderIssues(); };
  render();
})();
`;

export function renderHtml(report) {
  const model = toModel(report);
  const title = `Readiness — ${model.project}`;
  const when = new Date(model.generatedAt).toISOString().replace('T', ' ').slice(0, 16);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${escapeText(title)}</title>
<style>${CSS}</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>Production readiness — ${escapeText(model.project)}</h1>
      <div class="meta">Generated ${escapeText(when)} UTC · ${model.apps.length} app${model.apps.length === 1 ? '' : 's'} · devkai-readiness<span class="mode">${model.mode === 'review' ? 'in-depth review' : 'quick scan'}</span></div>
      ${model.mode === 'quick' && model.reviewChecksSkipped ? `<div class="meta">${model.reviewChecksSkipped} in-depth checks not run — use <code>devkai scan --review</code> for taint tracing, route auth, index and contrast analysis.</div>` : ''}
    </div>
    <div id="summary"></div>
  </header>
  <section><h2>Apps</h2><div class="panel matrix" id="apps"></div></section>
  <section><h2>Checklists</h2><div class="cards" id="cards"></div></section>
  <section>
    <h2>Checks</h2>
    <div class="panel filters" id="filters"></div>
    <p class="count" id="count" aria-live="polite"></p>
    <div class="panel" id="issues"></div>
  </section>
  <footer>Manual checks are confirmed by ticking them in the Markdown checklists; re-run the scan to refresh this page.</footer>
</div>
<script type="application/json" id="devkai-data">${safeJson(model)}</script>
<script>${SCRIPT}</script>
<noscript><p style="padding:16px">This dashboard needs JavaScript. The same results are in the Markdown checklists next to this file.</p></noscript>
</body>
</html>
`;
}

export function writeHtml(report, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, 'index.html');
  fs.writeFileSync(file, renderHtml(report));
  return [file];
}
