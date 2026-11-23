const express = require('express');
const multer = require('multer');
const fs = require('fs');
const cron = require('node-cron');

const router = express.Router();
const upload = multer({ dest: 'uploads/' });
const recentUploads = [];
let uploadCount = 0;

router.post('/avatar', upload.single('file'), (req, res) => {
  recentUploads.push({ user: req.user, file: req.file.filename });
  uploadCount++;
  res.json({ ok: true, uploadCount });
});

router.get('/terms', (req, res) => {
  const text = fs.readFileSync('./terms.html', 'utf8');
  res.send(text);
});

// Send the daily digest at 08:00
cron.schedule('0 8 * * *', async () => {
  await sendDigest(recentUploads);
});

module.exports = router;
