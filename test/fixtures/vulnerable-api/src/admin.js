const express = require('express');
const db = require('./db');
const AuditLog = require('./models/audit');

const router = express.Router();

router.put('/admin/users/:id/role', async (req, res) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden' });
  }
  await db.User.update({ role: req.body.role }, { where: { id: req.params.id } });
  res.json({ ok: true });
});

router.post('/reports/export', async (req, res) => {
  await AuditLog.create({ action: 'export', message: `by ${req.body.userId}` });
  auditLog.create({ userId: req.body.userId, action: 'report.export', password: req.body.password });
  res.json(await db.Report.findAll());
});

// nightly cleanup
async function cleanup() {
  await AuditLog.destroy({ where: {} });
}

module.exports = { router, cleanup };
