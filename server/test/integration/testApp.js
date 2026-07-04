import 'dotenv/config';
import express      from 'express';
import cors         from 'cors';
import multer       from 'multer';
import cookieParser from 'cookie-parser';
import analysisRouter from '../../routes/analysis.js';
import historyRouter  from '../../routes/history.js';
import smtpRouter     from '../../routes/smtp.js';
import authRouter     from '../../routes/auth.js';
import auditRouter    from '../../routes/audit.js';
import { COOKIE_SECRET } from '../../middleware/auth.js';

// Mirrors the middleware/route wiring in server/index.js, without starting
// the HTTP listener or the SMTP listener, so it can be driven by supertest.
export function buildTestApp() {
  const app = express();

  app.use(cors({ origin: ['http://localhost:5173', 'http://localhost:4173'], credentials: true }));
  app.use(express.json({ limit: '10mb' }));
  app.use(express.text({ type: 'message/rfc822', limit: '10mb' }));
  app.use(cookieParser(COOKIE_SECRET));

  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

  app.use('/api/auth',    authRouter);
  app.use('/api/analyze', upload.single('email'), analysisRouter);
  app.use('/api/history', historyRouter);
  app.use('/api/audit',   auditRouter);
  app.use('/api/smtp',    smtpRouter);

  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  app.use((err, req, res, next) => {
    res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
  });

  return app;
}
