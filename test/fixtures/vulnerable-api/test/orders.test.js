const router = require('../src/orders');

describe('orders', () => {
  it.only('loads', () => {
    expect(router).toBeDefined();
  });
  it.skip('creates an order', () => {});
});
