const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());

app.post('/users/:id/role', (req, res) => {
  console.log('role change', req.body);
  res.json({ ok: true });
});

app.listen(4000);
