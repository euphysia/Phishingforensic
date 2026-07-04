import { describe, it, expect } from 'vitest';
import { checkDomainAge } from '../../analyzers/domainAge.js';

// Regression test for a real defect found during Sprint testing: domainAge.js was calling
// the whoiser package as a default-exported function, but whoiser@2.x only exports named
// functions (whoisDomain, whoisIp, ...), so every WHOIS lookup silently failed and the
// "newly-registered domain" risk signal never fired in production.
describe('checkDomainAge (WHOIS integration)', () => {
  it('resolves a real, long-registered domain to a non-null registration date', async () => {
    const result = await checkDomainAge('google.com');
    expect(result.registeredAt).not.toBeNull();
    expect(result.ageDays).toBeGreaterThan(365 * 10); // registered in 1997
    expect(result.ageRisk).toBeNull(); // long-registered → not a risk signal
  });

  it('returns a null result rather than throwing for a non-existent TLD/domain', async () => {
    const result = await checkDomainAge('this-domain-should-not-exist-1234567.invalidtld');
    expect(result).toEqual({ registeredAt: null, ageDays: null, ageRisk: null });
  });
});
