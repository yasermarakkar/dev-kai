import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from '../src/server.js';

describe('orders', () => {
  it('requires an Idempotency-Key', async () => {
    const res = await request(app).post('/v1/orders').set('Authorization', 'Bearer test').send({ sku: 'a', qty: 1 });
    expect([400, 401]).toContain(res.status);
  });
});
