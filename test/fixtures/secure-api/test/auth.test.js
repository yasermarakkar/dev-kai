import { describe, it, expect, vi } from 'vitest';
import { requireAuth } from '../src/auth.js';

describe('requireAuth', () => {
  it('rejects a request without a bearer token', () => {
    const res = { status: vi.fn(() => res), end: vi.fn() };
    requireAuth({ headers: {}, log: { warn: vi.fn() } }, res, vi.fn());
    expect(res.status).toHaveBeenCalledWith(401);
  });
});
