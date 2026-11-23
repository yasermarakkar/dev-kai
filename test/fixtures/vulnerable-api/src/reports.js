const db = require('./db');

async function openOrdersForCustomer(customerId) {
  return db.Order.findAll({ where: { status: 'open', customerId } });
}

async function findUserByEmail(email) {
  return db.User.findOne({ where: { email } });
}

async function ordersWithCustomers() {
  const orders = await db.Order.findAll({ where: { status: 'shipped' }, limit: 100 });
  for (const order of orders) {
    order.customer = await db.User.findByPk(order.customerId);
  }
  return orders;
}

async function refund(orderId, amount) {
  await db.Order.update({ status: 'refunded' }, { where: { id: orderId } });
  await db.Payment.create({ orderId, amount: -amount });
}

module.exports = { openOrdersForCustomer, findUserByEmail, ordersWithCustomers, refund };
