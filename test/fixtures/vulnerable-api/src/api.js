const express = require('express');
const db = require('./db');

const router = express.Router();

router.get('/getUserOrders', async (req, res) => {
  const orders = await db.Order.findAll({ where: { customerId: req.query.userId } });
  res.json(orders);
});

router.get('/user_profile/:id', async (req, res) => {
  const user = await db.User.findByPk(req.params.id);
  if (!user) return res.status(404).json({ error: 'not found' });
  res.json(user);
});

router.post('/createOrder', async (req, res) => {
  if (!req.body.sku) return res.status(400).send({ msg: 'sku required', code: 'E_SKU' });
  const order = await db.Order.create({ sku: req.body.sku });
  if (!order) return res.json({ error: 'could not create order' });
  res.json(order);
});

module.exports = router;
