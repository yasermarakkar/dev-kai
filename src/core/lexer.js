/**
 * Tiny JS/TS lexer helpers used by --review mode. No dependencies, no full AST:
 * just enough structure to stop matching inside comments, follow statements
 * across lines and pull out call arguments.
 */

const REGEX_PREFIX = /[(,=:[!&|?{};+\-*%<>~^]$|(^|[^\w$])(return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/;

/**
 * Replace comments with spaces (newlines kept) so offsets and line numbers
 * stay identical to the original source. Strings, templates and regex
 * literals are left intact.
 */
export function stripComments(src) {
  const out = src.split('');
  const n = src.length;
  const templateDepth = []; // brace depth at which each open `${` returns to template
  let braces = 0;
  let i = 0;
  let lastSignificant = '';

  const blank = (from, to) => {
    for (let k = from; k < to; k++) if (out[k] !== '\n' && out[k] !== '\r') out[k] = ' ';
  };

  const skipString = (quote) => {
    i++;
    while (i < n) {
      const ch = src[i];
      if (ch === '\\') { i += 2; continue; }
      if (ch === quote) { i++; return; }
      if (ch === '\n') return; // unterminated — recover
      i++;
    }
  };

  // Scan template body starting after the opening ` (or after a closing } of ${…}).
  const skipTemplate = () => {
    while (i < n) {
      const ch = src[i];
      if (ch === '\\') { i += 2; continue; }
      if (ch === '`') { i++; return 'end'; }
      if (ch === '$' && src[i + 1] === '{') { i += 2; templateDepth.push(braces); braces++; return 'expr'; }
      i++;
    }
    return 'end';
  };

  while (i < n) {
    const ch = src[i];
    const next = src[i + 1];

    if (ch === '/' && next === '/') {
      const start = i;
      while (i < n && src[i] !== '\n') i++;
      blank(start, i);
      continue;
    }
    if (ch === '/' && next === '*') {
      const start = i;
      const end = src.indexOf('*/', i + 2);
      i = end === -1 ? n : end + 2;
      blank(start, i);
      continue;
    }
    if (ch === '"' || ch === "'") { skipString(ch); lastSignificant = 'a'; continue; }
    if (ch === '`') { i++; skipTemplate(); lastSignificant = 'a'; continue; }
    if (ch === '/' && REGEX_PREFIX.test(lastSignificant || '(')) {
      // regex literal
      i++;
      let inClass = false;
      while (i < n && src[i] !== '\n') {
        const c = src[i];
        if (c === '\\') { i += 2; continue; }
        if (c === '[') inClass = true;
        else if (c === ']') inClass = false;
        else if (c === '/' && !inClass) { i++; break; }
        i++;
      }
      while (i < n && /[a-z]/i.test(src[i])) i++;
      lastSignificant = 'a';
      continue;
    }
    if (ch === '{') braces++;
    if (ch === '}') {
      braces--;
      if (templateDepth.length && braces === templateDepth[templateDepth.length - 1]) {
        templateDepth.pop();
        i++;
        skipTemplate();
        lastSignificant = 'a';
        continue;
      }
    }
    if (!/\s/.test(ch)) {
      // Track the trailing token to decide whether a following "/" starts a regex.
      if (/[\w$]/.test(ch)) {
        let j = i;
        while (j < n && /[\w$]/.test(src[j])) j++;
        const word = src.slice(i, j);
        // keywords may be followed by a regex literal; identifiers/numbers by division
        lastSignificant = /^(return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/.test(word) ? ` ${word}` : 'a';
        i = j;
        continue;
      }
      lastSignificant = ch;
    }
    i++;
  }
  return out.join('');
}

/** Precompute line start offsets for fast offset → line lookups. */
export function lineIndex(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1; // 1-based
  };
}

/**
 * Given the index of an opening "(", return the top-level comma separated
 * arguments as strings plus the index just after the closing ")".
 */
export function extractArgs(text, openIdx) {
  const args = [];
  let depth = 0;
  let start = openIdx + 1;
  let i = openIdx;
  const n = text.length;
  const tmpl = [];
  while (i < n) {
    const ch = text[i];
    if (ch === '"' || ch === "'") {
      i++;
      while (i < n && text[i] !== ch && text[i] !== '\n') i += text[i] === '\\' ? 2 : 1;
      i++;
      continue;
    }
    if (ch === '`') {
      i++;
      // walk the template, recursing into ${ } by depth counting
      let d = 0;
      while (i < n) {
        if (text[i] === '\\') { i += 2; continue; }
        if (d === 0 && text[i] === '`') break;
        if (text[i] === '$' && text[i + 1] === '{') { d++; i += 2; continue; }
        if (d > 0 && text[i] === '{') d++;
        if (d > 0 && text[i] === '}') d--;
        i++;
      }
      i++;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') {
      depth++;
      tmpl.push(ch);
    } else if (ch === ')' || ch === ']' || ch === '}') {
      depth--;
      tmpl.pop();
      if (depth === 0) {
        const last = text.slice(start, i).trim();
        if (last || args.length) args.push(last);
        return { args, end: i + 1 };
      }
    } else if (ch === ',' && depth === 1) {
      args.push(text.slice(start, i).trim());
      start = i + 1;
    }
    i++;
    if (i - openIdx > 20000) break; // runaway guard
  }
  return { args, end: i };
}

/**
 * Find `{ … }` bodies following a regex match (e.g. catch blocks).
 * Returns [{ start, end, body }] where start is the match index.
 */
export function blocksAfter(text, regex) {
  const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : `${regex.flags}g`);
  const blocks = [];
  let m;
  while ((m = re.exec(text))) {
    const open = text.indexOf('{', m.index + m[0].length - 1);
    if (open === -1) break;
    const { end } = extractArgs(text, open);
    blocks.push({ start: m.index, open, end, body: text.slice(open + 1, end - 1) });
  }
  return blocks;
}
