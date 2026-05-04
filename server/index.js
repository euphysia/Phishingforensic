import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import analysisRouter from './routes/analysis.js';
import historyRouter from './routes/history.js';

const app = express();
const PORT = process.env.PORT || 3001;

// ── Middleware ────────────────────────────────────────────────────────────────

app.use(cors({ origin: ['http://localhost:5173', 'http://localhost:4173'] }));
app.use(express.json({ limit: '10mb' }));
app.use(express.text({ type: 'message/rfc822', limit: '10mb' }));

// Multer for .eml file uploads (memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.eml', '.txt', '.msg'];
    const ext = file.originalname.toLowerCase().slice(file.originalname.lastIndexOf('.'));
    if (allowed.includes(ext) || file.mimetype.includes('text')) {
      cb(null, true);
    } else {
      cb(new Error('Only .eml, .txt, or .msg files are allowed'));
    }
  },
});

// ── Routes ────────────────────────────────────────────────────────────────────

app.use('/api/analyze', upload.single('email'), analysisRouter);
app.use('/api/history', historyRouter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    demoMode: {
      virusTotal: !process.env.VIRUSTOTAL_API_KEY || process.env.VIRUSTOTAL_API_KEY === 'YOUR_VIRUSTOTAL_API_KEY',
      urlScan: !process.env.URLSCAN_API_KEY || process.env.URLSCAN_API_KEY === 'YOUR_URLSCAN_API_KEY',
    },
  });
});

// ── Error handler ─────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error('[Server Error]', err.message);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
  });
});

app.listen(PORT, () => {
  console.log(`\n🔬 Phishing Forensic API running at http://localhost:${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/api/health`);
  console.log(`   VirusTotal: ${process.env.VIRUSTOTAL_API_KEY ? '✅ API key set' : '⚠️  Demo mode'}`);
  console.log(`   URLScan:    ${process.env.URLSCAN_API_KEY    ? '✅ API key set' : '⚠️  Demo mode'}\n`);
});
