import express      from 'express';
import { hasApiKey } from './utils/apiKeys.js';
import cors         from 'cors';
import multer       from 'multer';
import cookieParser from 'cookie-parser';
import analysisRouter from './routes/analysis.js';
import historyRouter  from './routes/history.js';
import smtpRouter     from './routes/smtp.js';
import authRouter     from './routes/auth.js';
import auditRouter    from './routes/audit.js';
import { COOKIE_SECRET } from './middleware/auth.js';
import { IS_SERVERLESS } from './runtime.js';

/**
 * Express application shared by the local dev server (server/index.js)
 * and the Netlify Function (netlify/functions/api.mjs).
 */
const app  = express();
// ── Middleware ────────────────────────────────────────────────────────────────

app.set('trust proxy', 1);

// When invoked through the Netlify Function the path may arrive prefixed with
// the function route — normalise it so the /api/* routers match.
app.use((req, res, next) => {
  const prefix = '/.netlify/functions/api';
  if (req.url.startsWith(prefix)) req.url = '/api' + (req.url.slice(prefix.length) || '/');
  next();
});

app.use(cors({ origin: ['http://localhost:5173', 'http://localhost:4173'], credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.text({ type: 'message/rfc822', limit: '10mb' }));
app.use(cookieParser(COOKIE_SECRET));

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

app.use('/api/auth',    authRouter);
app.use('/api/analyze', upload.single('email'), analysisRouter);
app.use('/api/history', historyRouter);
app.use('/api/audit',   auditRouter);
app.use('/api/smtp',    smtpRouter);

// Health check
app.get('/api/health', (req, res) => {
  const smtpPort = process.env.SMTP_PORT || 2525;
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    demoMode: {
      virusTotal:  !hasApiKey('VIRUSTOTAL_API_KEY'),
      urlScan:     !hasApiKey('URLSCAN_API_KEY'),
      gemini:      !process.env.GEMINI_API_KEY     || process.env.GEMINI_API_KEY     === 'your-gemini-api-key-here',
      abuseIpDb:   !hasApiKey('ABUSEIPDB_API_KEY'),
      phishTank:   !hasApiKey('PHISHTANK_API_KEY'),
    },
    smtp: { port: smtpPort, available: !IS_SERVERLESS },
    runtime: IS_SERVERLESS ? 'netlify-functions' : 'node',
  });
});

// ── Error handler ─────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error('[Server Error]', err.message);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
  });
});

export default app;
