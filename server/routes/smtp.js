/**
 * SMTP Status Route
 * GET  /api/smtp/status  — returns SMTP server status + recent forwards
 * GET  /api/smtp/events  — SSE stream for real-time forward notifications
 */

import express from 'express';
import { getSmtpStatus, smtpEvents } from '../smtp/smtpListener.js';

const router = express.Router();

// ── GET /api/smtp/status ──────────────────────────────────────────────────────
router.get('/status', (req, res) => {
  res.json(getSmtpStatus());
});

// ── GET /api/smtp/events  (Server-Sent Events) ────────────────────────────────
// Frontend listens on this to get real-time notifications when a forwarded
// email has been analysed.
router.get('/events', (req, res) => {
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.flushHeaders();

  // Send initial status
  const status = getSmtpStatus();
  res.write(`data: ${JSON.stringify({ type: 'status', ...status })}\n\n`);

  // Relay events to this SSE client
  const onReceived = (entry) => {
    res.write(`data: ${JSON.stringify({ type: 'email-received', ...entry })}\n\n`);
  };
  const onComplete = (entry) => {
    res.write(`data: ${JSON.stringify({ type: 'analysis-complete', ...entry })}\n\n`);
  };
  const onError = (entry) => {
    res.write(`data: ${JSON.stringify({ type: 'analysis-error', ...entry })}\n\n`);
  };

  smtpEvents.on('email-received',    onReceived);
  smtpEvents.on('analysis-complete', onComplete);
  smtpEvents.on('analysis-error',    onError);

  // Heartbeat every 25s to keep connection alive
  const heartbeat = setInterval(() => {
    res.write(`: heartbeat\n\n`);
  }, 25000);

  req.on('close', () => {
    clearInterval(heartbeat);
    smtpEvents.off('email-received',    onReceived);
    smtpEvents.off('analysis-complete', onComplete);
    smtpEvents.off('analysis-error',    onError);
  });
});

export default router;
