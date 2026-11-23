const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { exec } = require('child_process');
const { Pool } = require('pg');
const session = require('express-session');

const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const apiKey = "k3y-9f8a7b6c5d4e3f2a1b";
const pool = new Pool();
const app = express();

app.use(cors());
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { httpOnly: false, secure: false } }));

app.get('/users', async (req, res) => {
  const rows = await pool.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  res.json(rows);
});

app.post('/login', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
  const token = jwt.sign({ hash }, 'mysecret');
  res.json({ token });
});

app.get('/me', (req, res) => {
  const user = jwt.decode(req.headers.authorization);
  res.json(user);
});

app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out));
});

app.use((err, req, res, next) => {
  res.status(500).json({ message: err.message, stack: err.stack });
});

const client = require('prom-client');
client.collectDefaultMetrics();
app.get('/health', (req, res) => res.send('ok'));
app.get('/metrics', async (req, res) => res.send(await client.register.metrics()));

app.listen(3000);
