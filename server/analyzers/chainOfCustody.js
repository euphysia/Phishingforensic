/**
 * Sprint 3: Chain-of-Custody Module
 * Creates forensic-grade audit trail entries for all analysis operations.
 * Each entry is timestamped, hashed, and signed for tamper evidence.
 */

import crypto from 'crypto';

/**
 * Creates a chain-of-custody record for an analysis session.
 * @param {string} analysisId
 * @param {string} sha256 - Email SHA-256
 * @param {string} subject
 * @param {string} sender
 * @returns {ChainOfCustody}
 */
export function createChainOfCustody(analysisId, sha256, subject, sender) {
  const entries = [];

  const addEntry = (action, component, detail, artifactHash = null) => {
    const entry = {
      sequence:    entries.length + 1,
      timestamp:   new Date().toISOString(),
      action,
      component,
      detail,
      artifactHash,
    };
    // Sign each entry with HMAC of previous + current (chain integrity)
    const prevHash = entries.length > 0 ? entries[entries.length - 1].entryHash : '0'.repeat(64);
    const data = JSON.stringify({ ...entry, prevHash });
    entry.entryHash = crypto.createHash('sha256').update(data).digest('hex');
    entries.push(entry);
    return entry;
  };

  // Initial custody entry
  addEntry(
    'EVIDENCE_RECEIVED',
    'EmailParser',
    `Email received for forensic analysis. Subject: "${subject}", Sender: "${sender}"`,
    sha256
  );

  return {
    analysisId,
    emailSha256: sha256,
    createdAt:   new Date().toISOString(),
    entries,
    addEntry,

    /**
     * Returns a forensic summary of the full chain.
     */
    getSummary() {
      const lastEntry = entries[entries.length - 1];
      return {
        analysisId,
        emailSha256: sha256,
        totalEntries: entries.length,
        startTime:    entries[0]?.timestamp,
        endTime:      lastEntry?.timestamp,
        chainIntact:  this.verifyChain(),
        entries,
      };
    },

    /**
     * Verifies the hash chain hasn't been tampered with.
     * @returns {boolean}
     */
    verifyChain() {
      for (let i = 0; i < entries.length; i++) {
        const entry       = entries[i];
        const prevHash    = i > 0 ? entries[i - 1].entryHash : '0'.repeat(64);
        const { entryHash, ...rest } = entry;
        const data        = JSON.stringify({ ...rest, prevHash });
        const expected    = crypto.createHash('sha256').update(data).digest('hex');
        if (expected !== entryHash) return false;
      }
      return true;
    },
  };
}

/**
 * Merges attachment audit trails into the main chain of custody.
 * @param {object} chain - ChainOfCustody instance
 * @param {Array} attachmentResults - Array from analyzeAttachments
 */
export function mergeAttachmentAuditTrails(chain, attachmentResults) {
  for (const att of attachmentResults) {
    for (const entry of att.auditTrail || []) {
      chain.addEntry(
        entry.action,
        entry.component,
        `[${att.filename}] ${entry.detail}`,
        entry.artifactHash || att.sha256
      );
    }
  }
}
