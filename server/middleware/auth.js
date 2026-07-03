import jwt from 'jsonwebtoken';

const JWT_SECRET   = process.env.JWT_SECRET || 'dev-secret-change-in-prod';
const TRIAL_LIMIT  = 3;
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'cookie-secret-change-in-prod';

export { JWT_SECRET, COOKIE_SECRET };

/** Attach req.user if a valid JWT cookie is present. Always calls next(). */
export function optionalAuth(req, res, next) {
  const token = req.cookies?.phishscan_token;
  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
    } catch {
      // Invalid/expired token — treat as guest
    }
  }
  next();
}

/** Require a valid JWT. Optionally restrict to specific roles. */
export function requireAuth(...roles) {
  return (req, res, next) => {
    const token = req.cookies?.phishscan_token;
    if (!token) {
      return res.status(401).json({ error: 'Login required', code: 'UNAUTHENTICATED' });
    }
    try {
      const user = jwt.verify(token, JWT_SECRET);
      if (roles.length > 0 && !roles.includes(user.role)) {
        return res.status(403).json({ error: 'Access denied for your role', code: 'FORBIDDEN' });
      }
      req.user = user;
      next();
    } catch {
      return res.status(401).json({ error: 'Session expired — please log in again', code: 'UNAUTHENTICATED' });
    }
  };
}

/** Block if guest trial limit reached. Must run after optionalAuth. */
export function checkGuestLimit(req, res, next) {
  if (req.user) return next(); // logged-in users skip

  const raw = req.signedCookies?.phishscan_trial;
  let trial = { count: 0 };
  if (raw) {
    try { trial = JSON.parse(raw); } catch {}
  }

  if (trial.count >= TRIAL_LIMIT) {
    return res.status(403).json({
      error: "You've used your 3 free analyses. Create an account or log in to continue.",
      code:  'TRIAL_LIMIT',
      trialCount:     trial.count,
      trialRemaining: 0,
    });
  }

  req.trial = trial;
  next();
}

/** Write the incremented trial cookie onto the response and return new count. */
export function incrementGuestTrial(req, res) {
  const newCount = (req.trial?.count ?? 0) + 1;
  res.cookie('phishscan_trial', JSON.stringify({ count: newCount }), {
    signed:   true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge:   24 * 60 * 60 * 1000, // 24 h
  });
  return newCount;
}
