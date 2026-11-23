const express = require('express');
const fs = require('fs');
const path = require('path');
const db = require('./db');

const router = express.Router();

// Old code kept for reference: eval(req.body.expr)

router.post('/orders', async (req, res) => {
  const { customerId, note } = req.body;
  const filter = req.query.status;
  // Multi-line query: single-line pattern matching misses this
  const rows = await db.query(
    `SELECT * FROM orders
     WHERE customer_id = ${customerId} AND status = '${filter}'`
  );
  const order = await db.Order.create(req.body);
  res.json({ rows, order, note });
});

router.delete('/orders/:id', async (req, res) => {
  await db.Order.destroy({ where: { id: req.params.id } });
  res.status(204).end();
});

router.get('/invoice', (req, res) => {
  const name = req.query.file;
  res.sendFile(path.join(__dirname, 'invoices', name));
});

router.get('/go', (req, res) => {
  const target = req.query.next;
  res.redirect(target);
});

router.post('/preview', async (req, res) => {
  const url = req.body.url;
  const page = await fetch(url);
  res.send(`<h1>${req.body.title}</h1>` + (await page.text()));
});

router.get('/orders/:id', async (req, res) => {
  try {
    res.json(await db.Order.findByPk(req.params.id));
  } catch (err) {
    res.status(500).json({ message: 'Something went wrong' });
  }
});

module.exports = router;
