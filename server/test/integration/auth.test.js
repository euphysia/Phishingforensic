import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { buildTestApp } from './testApp.js';

const app = buildTestApp();

const DEMO_USERS = {
  admin:   { email: 'admin@phishscan.com',   password: 'Admin123!' },
  analyst: { email: 'analyst@phishscan.com', password: 'Analyst123!' },
  auditor: { email: 'auditor@phishscan.com', password: 'Auditor123!' },
};

describe('POST /api/auth/login', () => {
  it('logs in each seeded demo role and returns its correct role', async () => {
    for (const [role, creds] of Object.entries(DEMO_USERS)) {
      const res = await request(app).post('/api/auth/login').send(creds);
      expect(res.status).toBe(200);
      expect(res.body.user.role).toBe(role);
      expect(res.headers['set-cookie'].some(c => c.startsWith('phishscan_token='))).toBe(true);
    }
  });

  it('rejects an incorrect password with 401 and no session cookie', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: 'analyst@phishscan.com',
      password: 'wrong-password',
    });
    expect(res.status).toBe(401);
    expect(res.body.user).toBeUndefined();
  });

  it('rejects a login attempt for a non-existent account with 401 (not a 500 / stack trace)', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: 'does-not-exist@phishscan.com',
      password: 'whatever123',
    });
    expect(res.status).toBe(401);
  });

  it('rejects a request missing email/password with 400', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'analyst@phishscan.com' });
    expect(res.status).toBe(400);
  });
});

describe('GET /api/auth/me', () => {
  it('returns the authenticated user when a valid session cookie is presented', async () => {
    const agent = request.agent(app);
    await agent.post('/api/auth/login').send(DEMO_USERS.analyst);
    const res = await agent.get('/api/auth/me');
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe(DEMO_USERS.analyst.email);
  });

  it('returns guest/trial state (no user) when no session cookie is presented', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(200);
    expect(res.body.user).toBeNull();
    expect(res.body.trial).toBeDefined();
  });

  it('treats a tampered JWT cookie as unauthenticated rather than crashing', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Cookie', ['phishscan_token=not.a.validjwt']);
    expect(res.status).toBe(200);
    expect(res.body.user).toBeNull();
  });
});

describe('POST /api/auth/logout', () => {
  it('clears the session cookie', async () => {
    const agent = request.agent(app);
    await agent.post('/api/auth/login').send(DEMO_USERS.analyst);
    const res = await agent.post('/api/auth/logout');
    expect(res.status).toBe(200);
    const me = await agent.get('/api/auth/me');
    expect(me.body.user).toBeNull();
  });
});
