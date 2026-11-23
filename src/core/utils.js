export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Weight of a check when computing a checklist score. */
export const SEVERITY_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1, info: 1 };

const useColor = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
const wrap = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));

export const color = {
  bold: wrap(1),
  dim: wrap(2),
  red: wrap(31),
  green: wrap(32),
  yellow: wrap(33),
  blue: wrap(34),
  magenta: wrap(35),
  cyan: wrap(36),
  gray: wrap(90),
};

export function toPosix(p) {
  return p.split('\\').join('/');
}

/**
 * Hide most of a secret so reports can be committed safely.
 * Keeps the first 4 characters for recognition.
 */
export function maskSecret(value) {
  if (!value) return value;
  if (value.length <= 6) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}${'*'.repeat(Math.min(value.length - 4, 12))}`;
}

export function truncate(text, max = 140) {
  const t = text.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}
