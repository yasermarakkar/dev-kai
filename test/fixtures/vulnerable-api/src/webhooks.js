const express = require('express');
const db = require('./db');

const router = express.Router();

router.post('/webhooks/stripe', express.json(), async (req, res) => {
  const event = req.body;
  if (event.type === 'checkout.session.completed') {
    await db.Order.update({ status: 'paid' }, { where: { id: event.data.object.metadata.orderId } });
  }
  res.json({ received: true });
});

router.post('/subscriptions', async (req, res) => {
  try {
    await db.Subscription.create({ userId: req.user.id, plan: req.body.plan });
    sendWelcomeEmail(req.user.email).then(() => track('welcome_sent'));
  } catch (err) {
    res.json({ ok: true });
  }
});

module.exports = router;
