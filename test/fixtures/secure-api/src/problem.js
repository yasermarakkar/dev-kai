/** Send an RFC 9457 problem details response. */
export function problem(res, status, title, extra = {}) {
  if (status === 429 || status === 503) res.set('Retry-After', String(extra.retryAfter ?? 30));
  return res
    .status(status)
    .type('application/problem+json')
    .json({ type: `https://errors.example.com/${status}`, title, status, ...extra });
}
