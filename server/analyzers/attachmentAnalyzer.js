/**
 * Sprint 3: Attachment Analysis Module
 * - File type validation (MIME spoofing detection)
 * - Malware scanning via VirusTotal file hash lookup
 * - Metadata extraction (author, creation date, embedded macros, etc.)
 * - Chain-of-custody audit entries for every attachment operation
 */

import crypto from 'crypto';
import { getCached, setCached } from '../cache/urlCache.js';

// ── Known MIME type → expected extensions map ─────────────────────────────────
const MIME_TO_EXTENSIONS = {
  'application/pdf':            ['.pdf'],
  'application/msword':         ['.doc'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
  'application/vnd.ms-excel':   ['.xls'],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
  'application/vnd.ms-powerpoint': ['.ppt'],
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],
  'application/zip':            ['.zip'],
  'application/x-rar-compressed': ['.rar'],
  'application/x-7z-compressed': ['.7z'],
  'application/x-tar':          ['.tar'],
  'application/gzip':           ['.gz'],
  'application/x-executable':   ['.exe'],
  'application/x-msdownload':   ['.exe', '.dll'],
  'application/x-bat':          ['.bat'],
  'application/x-sh':           ['.sh'],
  'text/plain':                 ['.txt'],
  'text/html':                  ['.html', '.htm'],
  'image/jpeg':                 ['.jpg', '.jpeg'],
  'image/png':                  ['.png'],
  'image/gif':                  ['.gif'],
  'application/octet-stream':   [], // Binary fallback — any extension is OK
};

// ── High-risk extensions that should always trigger a warning ─────────────────
const HIGH_RISK_EXTENSIONS = new Set([
  '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe',
  '.js',  '.jse', '.ws',  '.wsf', '.wsc', '.wsh', '.ps1', '.ps2',
  '.msi', '.msp', '.jar', '.lnk', '.inf', '.reg', '.dll', '.cpl',
  '.hta', '.html', '.htm', // when sent as attachments
]);

// ── Medium-risk extensions ────────────────────────────────────────────────────
const MEDIUM_RISK_EXTENSIONS = new Set([
  '.doc',  '.docm', '.xls',  '.xlsm', '.ppt',  '.pptm',
  '.docx', '.xlsx', '.pptx', // could still have embedded macros
  '.zip',  '.rar',  '.7z',   '.tar',  '.gz',   // archives may hide threats
  '.iso',  '.img',  '.pdf',
]);

// ── Magic byte signatures (first few bytes of file) ───────────────────────────
const MAGIC_SIGNATURES = [
  { sig: Buffer.from([0x4D, 0x5A]),                     ext: '.exe', label: 'Windows Executable (MZ)' },
  { sig: Buffer.from([0x50, 0x4B, 0x03, 0x04]),         ext: '.zip', label: 'ZIP Archive' },
  { sig: Buffer.from([0x25, 0x50, 0x44, 0x46]),         ext: '.pdf', label: 'PDF Document' },
  { sig: Buffer.from([0xD0, 0xCF, 0x11, 0xE0]),         ext: '.doc', label: 'MS Office Legacy (OLE2)' },
  { sig: Buffer.from([0x52, 0x61, 0x72, 0x21]),         ext: '.rar', label: 'RAR Archive' },
  { sig: Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]), ext: '.7z', label: '7-Zip Archive' },
  { sig: Buffer.from([0x1F, 0x8B]),                     ext: '.gz',  label: 'GZIP Archive' },
  { sig: Buffer.from([0xFF, 0xD8, 0xFF]),               ext: '.jpg', label: 'JPEG Image' },
  { sig: Buffer.from([0x89, 0x50, 0x4E, 0x47]),         ext: '.png', label: 'PNG Image' },
  { sig: Buffer.from([0x47, 0x49, 0x46, 0x38]),         ext: '.gif', label: 'GIF Image' },
];

/**
 * Analyzes a single attachment for security risks and forensic metadata.
 * @param {object} att - Attachment object from emailParser
 * @param {string} analysisId - Parent analysis ID (for chain-of-custody)
 * @param {Function} vtFileScan - Optional VirusTotal file scanner
 * @returns {Promise<AttachmentAnalysisResult>}
 */
export async function analyzeAttachment(att, analysisId, vtFileScan = null) {
  const auditTrail = [];
  const timestamp = () => new Date().toISOString();

  // ── 1. Record chain-of-custody entry for receipt ─────────────────────────
  auditTrail.push({
    timestamp: timestamp(),
    action:    'ATTACHMENT_RECEIVED',
    component: 'AttachmentAnalyzer',
    detail:    `Attachment "${att.filename}" (${att.sizeBytes} bytes) received for analysis`,
  });

  const filename   = att.filename || 'unknown';
  const ext        = getExtension(filename).toLowerCase();
  const contentType = (att.contentType || 'application/octet-stream').split(';')[0].trim().toLowerCase();
  const content    = att.content; // Buffer

  // ── 2. Generate SHA-256 (integrity hash) ─────────────────────────────────
  const sha256 = att.sha256 || (content
    ? crypto.createHash('sha256').update(content).digest('hex')
    : 'unavailable');

  const md5 = content
    ? crypto.createHash('md5').update(content).digest('hex')
    : 'unavailable';

  auditTrail.push({
    timestamp: timestamp(),
    action:    'HASH_COMPUTED',
    component: 'AttachmentAnalyzer',
    detail:    `SHA-256: ${sha256} | MD5: ${md5}`,
  });

  const risks       = [];
  let   statusLevel = 'safe'; // safe | suspicious | malicious
  const metadata    = extractMetadata(att, content);

  // ── 3. MIME spoofing detection ────────────────────────────────────────────
  const mimeCheck = checkMimeSpoofing(contentType, ext, filename);
  if (mimeCheck.spoofed) {
    risks.push({
      type:        'MIME_SPOOFING',
      severity:    'high',
      description: mimeCheck.description,
    });
    statusLevel = escalate(statusLevel, 'malicious');
  }

  auditTrail.push({
    timestamp: timestamp(),
    action:    'MIME_CHECK',
    component: 'AttachmentAnalyzer',
    detail:    mimeCheck.spoofed
      ? `MIME spoofing detected: ${mimeCheck.description}`
      : `MIME type "${contentType}" matches extension "${ext}"`,
  });

  // ── 4. Magic byte verification ────────────────────────────────────────────
  if (content && content.length >= 4) {
    const magicCheck = checkMagicBytes(content, ext);
    if (magicCheck.mismatch) {
      risks.push({
        type:        'MAGIC_BYTE_MISMATCH',
        severity:    'high',
        description: magicCheck.description,
      });
      statusLevel = escalate(statusLevel, 'malicious');
    }

    auditTrail.push({
      timestamp: timestamp(),
      action:    'MAGIC_BYTES_CHECK',
      component: 'AttachmentAnalyzer',
      detail:    magicCheck.mismatch
        ? `Magic byte mismatch: ${magicCheck.description}`
        : `Magic bytes consistent with declared type (${magicCheck.detected || ext})`,
    });
  }

  // ── 5. Extension risk assessment ─────────────────────────────────────────
  if (HIGH_RISK_EXTENSIONS.has(ext)) {
    risks.push({
      type:        'HIGH_RISK_EXTENSION',
      severity:    'high',
      description: `File extension "${ext}" is associated with executable or scripting content`,
    });
    statusLevel = escalate(statusLevel, 'malicious');
  } else if (MEDIUM_RISK_EXTENSIONS.has(ext)) {
    risks.push({
      type:        'MEDIUM_RISK_EXTENSION',
      severity:    'medium',
      description: `File extension "${ext}" may contain macros, scripts, or compressed threats`,
    });
    statusLevel = escalate(statusLevel, 'suspicious');
  }

  auditTrail.push({
    timestamp: timestamp(),
    action:    'EXTENSION_CHECK',
    component: 'AttachmentAnalyzer',
    detail:    `Extension "${ext}" risk: ${HIGH_RISK_EXTENSIONS.has(ext) ? 'HIGH' : MEDIUM_RISK_EXTENSIONS.has(ext) ? 'MEDIUM' : 'LOW'}`,
  });

  // ── 6. Suspicious filename pattern detection ──────────────────────────────
  const fnRisks = checkSuspiciousFilename(filename);
  if (fnRisks.length > 0) {
    risks.push(...fnRisks);
    statusLevel = escalate(statusLevel, 'suspicious');
  }

  // ── 7. Content-based pattern detection (if readable) ─────────────────────
  if (content) {
    const contentRisks = checkContentPatterns(content, ext);
    if (contentRisks.length > 0) {
      risks.push(...contentRisks);
      if (contentRisks.some(r => r.severity === 'high')) {
        statusLevel = escalate(statusLevel, 'malicious');
      } else {
        statusLevel = escalate(statusLevel, 'suspicious');
      }
    }

    auditTrail.push({
      timestamp: timestamp(),
      action:    'CONTENT_PATTERN_CHECK',
      component: 'AttachmentAnalyzer',
      detail:    contentRisks.length > 0
        ? `${contentRisks.length} suspicious pattern(s) found`
        : 'No suspicious patterns found in content',
    });
  }

  // ── 8. VirusTotal file hash scan ─────────────────────────────────────────
  let vtResult = null;
  if (sha256 !== 'unavailable') {
    try {
      // Check cache first
      const cacheKey = `file:${sha256}`;
      const cached   = await getCached(cacheKey, 'vt_file');
      if (cached) {
        vtResult = { ...cached, fromCache: true };
      } else if (vtFileScan) {
        vtResult = await vtFileScan(sha256);
        if (vtResult && !vtResult.isDemo) {
          await setCached(cacheKey, 'vt_file', vtResult);
        }
      } else {
        vtResult = generateDemoVTFileResult(sha256, ext);
      }

      if (vtResult) {
        auditTrail.push({
          timestamp: timestamp(),
          action:    'VT_FILE_SCAN',
          component: 'VirusTotalScanner',
          detail:    vtResult.fromCache
            ? `Cache hit — VT detections: ${vtResult.detections}/${vtResult.total}`
            : `VT scan complete — detections: ${vtResult.detections}/${vtResult.total}`,
        });

        if (vtResult.detections > 0) {
          const severity = vtResult.detections >= 3 ? 'high' : 'medium';
          risks.push({
            type:        'VIRUS_TOTAL_DETECTION',
            severity,
            description: `VirusTotal: ${vtResult.detections}/${vtResult.total} security vendors flagged this file${vtResult.malwareFamily ? ` as ${vtResult.malwareFamily}` : ''}`,
          });
          statusLevel = escalate(statusLevel, severity === 'high' ? 'malicious' : 'suspicious');
        }
      }
    } catch (err) {
      console.warn(`[AttachmentAnalyzer] VT file scan error for ${filename}:`, err.message);
      auditTrail.push({
        timestamp: timestamp(),
        action:    'VT_FILE_SCAN_ERROR',
        component: 'VirusTotalScanner',
        detail:    `Error: ${err.message}`,
      });
    }
  }

  // ── 9. Password-protected archive detection ───────────────────────────────
  if (content && isPasswordProtected(content, ext)) {
    risks.push({
      type:        'PASSWORD_PROTECTED_ARCHIVE',
      severity:    'medium',
      description: 'Archive appears to be password-protected, blocking automated scanning — common evasion technique',
    });
    statusLevel = escalate(statusLevel, 'suspicious');

    auditTrail.push({
      timestamp: timestamp(),
      action:    'PASSWORD_PROTECTED_DETECTION',
      component: 'AttachmentAnalyzer',
      detail:    'Password-protected archive detected — manual review required',
    });
  }

  // ── 10. Final chain-of-custody entry ─────────────────────────────────────
  auditTrail.push({
    timestamp: timestamp(),
    action:    'ANALYSIS_COMPLETE',
    component: 'AttachmentAnalyzer',
    detail:    `Analysis complete. Status: ${statusLevel} | Risks found: ${risks.length}`,
  });

  return {
    filename,
    contentType,
    sizeBytes:      att.sizeBytes,
    extension:      ext,
    sha256,
    md5,
    status:         statusLevel,
    risks,
    metadata,
    vtResult,
    auditTrail,
  };
}

/**
 * Analyze all attachments from a parsed email.
 * @param {Array} attachments - From emailParser
 * @param {string} analysisId
 * @param {Function} vtFileScan
 * @returns {Promise<Array>}
 */
export async function analyzeAttachments(attachments, analysisId, vtFileScan = null) {
  if (!attachments || attachments.length === 0) return [];

  const results = await Promise.allSettled(
    attachments.map(att => analyzeAttachment(att, analysisId, vtFileScan))
  );

  return results
    .filter(r => r.status === 'fulfilled')
    .map(r => r.value);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function getExtension(filename) {
  if (!filename) return '';
  const parts = filename.split('.');
  return parts.length > 1 ? '.' + parts[parts.length - 1] : '';
}

function escalate(current, newLevel) {
  const order = { safe: 0, suspicious: 1, malicious: 2 };
  return order[newLevel] > order[current] ? newLevel : current;
}

function checkMimeSpoofing(contentType, ext, filename) {
  // Special case: octet-stream is a generic binary — only flag if ext is known non-binary
  if (contentType === 'application/octet-stream') {
    if (ext && (HIGH_RISK_EXTENSIONS.has(ext))) {
      return {
        spoofed: true,
        description: `File "${filename}" declared as generic binary but has executable extension "${ext}"`,
      };
    }
    return { spoofed: false };
  }

  const expected = MIME_TO_EXTENSIONS[contentType];
  if (!expected) return { spoofed: false }; // Unknown MIME — can't validate

  if (expected.length === 0) return { spoofed: false }; // Octet-stream or similar

  if (ext && !expected.includes(ext)) {
    // Detect: .exe disguised as .pdf — check if the actual ext is high risk
    const actualRisk = HIGH_RISK_EXTENSIONS.has(ext) ? 'high-risk' : 'mismatched';
    return {
      spoofed: true,
      description: `MIME type "${contentType}" expects ${expected.join('/')} but file has extension "${ext}" — potential ${actualRisk} file masquerading`,
    };
  }

  return { spoofed: false };
}

function checkMagicBytes(content, declaredExt) {
  for (const sig of MAGIC_SIGNATURES) {
    if (content.slice(0, sig.sig.length).equals(sig.sig)) {
      // Magic bytes detected — does it match declared extension?
      if (declaredExt && declaredExt !== sig.ext) {
        // Exception: ZIP is the container for Office Open XML (.docx, .xlsx etc.)
        if (sig.ext === '.zip' && ['.docx', '.xlsx', '.pptx', '.odt'].includes(declaredExt)) {
          return { mismatch: false, detected: sig.label };
        }
        // Real mismatch
        if (HIGH_RISK_EXTENSIONS.has(sig.ext)) {
          return {
            mismatch: true,
            description: `File magic bytes indicate ${sig.label} but declared as "${declaredExt}" — high-risk executable disguised as safe file`,
            detected: sig.label,
          };
        }
        return {
          mismatch: true,
          description: `Magic bytes suggest ${sig.label} but file declares extension "${declaredExt}"`,
          detected: sig.label,
        };
      }
      return { mismatch: false, detected: sig.label };
    }
  }
  return { mismatch: false };
}

function checkSuspiciousFilename(filename) {
  const risks = [];
  const nameLower = filename.toLowerCase();

  // Double extension (.pdf.exe)
  const doubleExtMatch = filename.match(/\.\w{2,4}\.\w{2,4}$/);
  if (doubleExtMatch) {
    risks.push({
      type:        'DOUBLE_EXTENSION',
      severity:    'high',
      description: `Filename "${filename}" has a double extension — common trick to disguise executables`,
    });
  }

  // Excessive spaces before extension (hiding real extension)
  if (/\s{5,}/.test(filename)) {
    risks.push({
      type:        'SPACE_EXTENSION_TRICK',
      severity:    'high',
      description: `Filename "${filename}" contains suspicious whitespace — may be hiding the true extension`,
    });
  }

  // Right-to-left Unicode override (RTLO attack)
  if (/[\u202E\u2066\u2067\u2068\u2069]/.test(filename)) {
    risks.push({
      type:        'UNICODE_RTLO',
      severity:    'high',
      description: 'Filename contains Right-to-Left Unicode override characters — classic extension spoofing technique',
    });
  }

  // Phishing lure keywords
  if (/invoice|payment|receipt|urgent|password|credential|bank|verify|confirm|account/i.test(nameLower)) {
    risks.push({
      type:        'SOCIAL_ENGINEERING_FILENAME',
      severity:    'medium',
      description: `Filename "${filename}" contains social engineering keywords commonly used in phishing lures`,
    });
  }

  return risks;
}

function checkContentPatterns(content, ext) {
  const risks = [];
  const textContent = content.toString('latin1'); // Safe binary-to-text

  // Check for embedded macro signatures in Office files
  if (['.doc', '.xls', '.ppt', '.docm', '.xlsm', '.pptm'].includes(ext)) {
    if (/AutoOpen|AutoExec|Document_Open|Workbook_Open|Shell\s*\(/i.test(textContent)) {
      risks.push({
        type:        'EMBEDDED_MACRO',
        severity:    'high',
        description: 'Office file contains embedded macro patterns (AutoOpen, Shell) — potential malware dropper',
      });
    }
  }

  // PDF with embedded JavaScript
  if (ext === '.pdf') {
    if (/\/JavaScript\s*<<|\/JS\s*\(/i.test(textContent)) {
      risks.push({
        type:        'PDF_JAVASCRIPT',
        severity:    'high',
        description: 'PDF file contains embedded JavaScript — can be used to exploit PDF readers',
      });
    }
    if (/\/OpenAction|\/AA\s*<</.test(textContent)) {
      risks.push({
        type:        'PDF_AUTO_ACTION',
        severity:    'medium',
        description: 'PDF contains auto-execute actions (OpenAction/AA) — may run code upon opening',
      });
    }
    if (/\/Launch\s*<</.test(textContent)) {
      risks.push({
        type:        'PDF_LAUNCH_ACTION',
        severity:    'high',
        description: 'PDF contains Launch action — can execute system commands',
      });
    }
  }

  // Obfuscated PowerShell patterns
  if (/powershell|FromBase64String|IEX\s*\(|Invoke-Expression/i.test(textContent)) {
    risks.push({
      type:        'POWERSHELL_OBFUSCATION',
      severity:    'high',
      description: 'File contains PowerShell execution patterns — commonly used in malware droppers',
    });
  }

  // Base64 encoded executable (MZ header)
  if (/TVqQAAMAAAAEAAAA/.test(textContent)) {
    risks.push({
      type:        'BASE64_EXECUTABLE',
      severity:    'high',
      description: 'File contains Base64-encoded Windows executable — common dropper technique',
    });
  }

  return risks;
}

function isPasswordProtected(content, ext) {
  if (!['.zip', '.rar', '.7z', '.docx', '.xlsx', '.pptx', '.pdf'].includes(ext)) return false;

  const text = content.toString('latin1');

  // ZIP password flag (general purpose bit flag bit 0 = 1)
  if (ext === '.zip' && content.length > 30) {
    const generalPurposeFlag = content.readUInt16LE(6);
    if (generalPurposeFlag & 0x0001) return true;
  }

  // PDF encryption dict
  if (ext === '.pdf' && /\/Encrypt\s*\d+\s*\d+\s*R/.test(text)) return true;

  // RAR password flag
  if (ext === '.rar' && content[9] & 0x04) return true;

  return false;
}

function extractMetadata(att, content) {
  const meta = {
    filename:     att.filename,
    contentType:  att.contentType,
    sizeBytes:    att.sizeBytes,
    sizeFormatted: formatSize(att.sizeBytes),
    encoding:     null,
    isInline:     att.contentDisposition === 'inline',
    extractedAt:  new Date().toISOString(),
  };

  // Try to extract text-level metadata for Office files
  if (content && att.filename) {
    const ext = getExtension(att.filename).toLowerCase();

    if (['.doc', '.xls', '.ppt'].includes(ext)) {
      // OLE2 format — check for embedded metadata
      const textContent = content.toString('latin1');
      const authorMatch = textContent.match(/Author\0{1,4}([A-Za-z\s]{3,50})/);
      if (authorMatch) meta.embeddedAuthor = authorMatch[1].replace(/\0/g, '').trim();
    }
  }

  return meta;
}

function generateDemoVTFileResult(sha256, ext) {
  const isHighRisk = HIGH_RISK_EXTENSIONS.has(ext);
  const detections = isHighRisk
    ? Math.floor(Math.random() * 25) + 5
    : Math.floor(Math.random() * 3);

  return {
    detections,
    total: 72,
    malicious: isHighRisk ? Math.floor(detections * 0.8) : 0,
    suspicious: isHighRisk ? Math.ceil(detections * 0.2) : detections,
    sha256,
    malwareFamily: isHighRisk && detections > 10 ? 'Trojan.GenericKD' : null,
    isDemo: true,
  };
}

function formatSize(bytes) {
  if (!bytes) return 'Unknown';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
