/**
 * Netlify Function that serves the whole Express API (/api/*).
 * Requests to /api/* are rewritten here by netlify.toml.
 */
import serverless from 'serverless-http';
import app from '../../server/app.js';

export const handler = serverless(app, {
  binary: ['multipart/form-data', 'application/octet-stream', 'message/rfc822'],
  // serverless-http hands Express an already-"complete" request, which makes
  // Express 5's body parsers skip it. Pre-parse JSON and text bodies here;
  // multipart uploads are still streamed through multer as usual.
  request(req) {
    if (!Buffer.isBuffer(req.body)) return;
    const type = String(req.headers['content-type'] || '').toLowerCase();
    if (type.includes('application/json')) {
      try { req.body = req.body.length ? JSON.parse(req.body.toString('utf8')) : {}; }
      catch { req.body = {}; }
    } else if (type.startsWith('text/') || type.includes('message/rfc822')) {
      req.body = req.body.toString('utf8');
    } else if (!type.includes('multipart/form-data')) {
      req.body = {};
    }
  },
});
