const stripe = require('./stripe');

async function charge(req, res) {
  const { email, password, cardNumber } = req.body;
  console.log('charging', email, cardNumber);
  console.log(req.body);
  try {
    await stripe.charge(cardNumber);
  } catch (err) {
  }
  try {
    await stripe.refund(email);
  } catch (err) {
    console.log('refund failed', err);
  }
  stripe.notify(email).catch(() => {});
  res.json({ ok: true, password: undefined });
}

module.exports = { charge };
