import express from 'express';
import bcrypt  from 'bcryptjs';
import jwt     from 'jsonwebtoken';
import supabase from '../db.js';
import { JWT_SECRET, COOKIE_SECRET } from '../middleware/auth.js';
import { IS_SERVERLESS } from '../runtime.js';

const router = express.Router();

const TOKEN_COOKIE_OPTS = {
  httpOnly: true,
  sameSite: 'strict',
  maxAge:   7 * 24 * 60 * 60 * 1000, // 7 days
  secure:   process.env.NODE_ENV === 'production' || IS_SERVERLESS,
};

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const { data: user, error } = await supabase
    .from('users')
    .select('id, email, password_hash, role')
    .eq('email', email.toLowerCase().trim())
    .single();

  if (error || !user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.cookie('phishscan_token', token, TOKEN_COOKIE_OPTS);
  res.clearCookie('phishscan_trial'); // clear guest trial on login

  return res.json({ user: { id: user.id, email: user.email, role: user.role } });
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
  res.clearCookie('phishscan_token');
  return res.json({ ok: true });
});

// GET /api/auth/me — returns logged-in user OR guest trial state
router.get('/me', (req, res) => {
  const token = req.cookies?.phishscan_token;
  if (token) {
    try {
      const user = jwt.verify(token, JWT_SECRET);
      return res.json({ user: { id: user.id, email: user.email, role: user.role } });
    } catch {
      res.clearCookie('phishscan_token');
    }
  }

  const raw = req.signedCookies?.phishscan_trial;
  let count = 0;
  if (raw) {
    try { count = JSON.parse(raw).count ?? 0; } catch {}
  }

  return res.json({
    user:  null,
    trial: { count, remaining: Math.max(0, 3 - count) },
  });
});

export default router;
