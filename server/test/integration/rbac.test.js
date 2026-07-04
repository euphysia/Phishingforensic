import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { buildTestApp } from './testApp.js';

const app = buildTestApp();

const DEMO_USERS = {
  admin:   { email: 'admin@phishscan.com',   password: 'Admin123!' },
  analyst: { email: 'analyst@phishscan.com', password: 'Analyst123!' },
  auditor: { email: 'auditor@phishscan.com', password: 'Auditor123!' },
};

async function loginAs(role) {
  const agent = request.agent(app);
  await agent.post('/api/auth/login').send(DEMO_USERS[role]);
  return agent;
}

describe('Role-based access control — /api/history', () => {
  it('rejects an unauthenticated request with 401', async () => {
    const res = await request(app).get('/api/history');
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('UNAUTHENTICATED');
  });

  it('allows an analyst to read their own history', async () => {
    const agent = await loginAs('analyst');
    const res = await agent.get('/api/history');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('analyses');
    expect(res.body).toHaveProperty('pagination');
  });

  it('allows an admin to read history', async () => {
    const agent = await loginAs('admin');
    const res = await agent.get('/api/history');
    expect(res.status).toBe(200);
  });

  it('denies an auditor access to /api/history with 403 (separation of duties)', async () => {
    const agent = await loginAs('auditor');
    const res = await agent.get('/api/history');
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('FORBIDDEN');
  });
});

describe('Role-based access control — /api/audit/logs', () => {
  it('rejects an unauthenticated request with 401', async () => {
    const res = await request(app).get('/api/audit/logs');
    expect(res.status).toBe(401);
  });

  it('allows an auditor to read the chain-of-custody audit log', async () => {
    const agent = await loginAs('auditor');
    const res = await agent.get('/api/audit/logs');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('logs');
  });

  it('allows an admin to read the audit log', async () => {
    const agent = await loginAs('admin');
    const res = await agent.get('/api/audit/logs');
    expect(res.status).toBe(200);
  });

  it('denies an analyst access to /api/audit/logs with 403 (analysts cannot verify their own evidence trail)', async () => {
    const agent = await loginAs('analyst');
    const res = await agent.get('/api/audit/logs');
    expect(res.status).toBe(403);
  });
});

describe('JWT tampering', () => {
  it('rejects a forged/tampered role claim rather than trusting an unsigned token', async () => {
    // Forged token with an "admin" payload but no valid signature — must be rejected outright.
    const forgedPayload = Buffer.from(JSON.stringify({ id: '00000000-0000-0000-0000-000000000000', role: 'admin' })).toString('base64url');
    const forgedToken = `eyJhbGciOiJub25lIn0.${forgedPayload}.`;

    const res = await request(app)
      .get('/api/audit/logs')
      .set('Cookie', [`phishscan_token=${forgedToken}`]);

    expect(res.status).toBe(401); // jwt.verify must reject the unsigned/invalid token
  });
});
