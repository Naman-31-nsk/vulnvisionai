require('dotenv').config();
const express = require('express');
const cors = require('cors');
const scanRoutes = require('./routes/scan');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '2mb' }));

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    aiEnabled: Boolean(process.env.OPENROUTER_API_KEY),
  });
});

app.use('/api', scanRoutes);

app.listen(PORT, () => {
  console.log(`VulnVision AI backend running on http://localhost:${PORT}`);
  if (!process.env.OPENROUTER_API_KEY) {
    console.warn('WARNING: OPENROUTER_API_KEY not set — AI features will be disabled.');
  }
});
