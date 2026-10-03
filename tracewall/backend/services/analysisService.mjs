import { getStore, persistStore } from '../database/store.mjs';
import { id, requiredString, validUrl, httpError } from '../utils/validation.mjs';
import { recordAudit } from './auditService.mjs';

// ============================================================
// PhishNet — email / URL / file analysis, exposure and correlation.
//
// Honesty rules for this module:
//
//   1. Only report what was actually derived from the submitted input.
//      A value that was never collected is returned as NOT_COLLECTED with
//      a reason, never as a plausible-looking number.
//   2. Reputation and registration age are third-party facts. Without a
//      configured enrichment provider this service does not have them, and
//      it says so instead of inventing a registrar or a domain age.
//   3. An exposure check against no real feed must never report "exposed".
//      Reporting a clean result when nothing was checked is itself a false
//      statement, so the answer is explicitly "unknown, not checked".
//   4. Confidence is derived from what was inspected, and the disclaimer
//      states the limits of the inspection.
// ============================================================

/** Sentinel for a value this service did not and cannot collect. */
const notCollected = reason => ({ status: 'NOT_COLLECTED', reason });

const NOT_COLLECTED = {
  registrar: () => notCollected('No WHOIS/RDAP enrichment provider is configured for this service.'),
  hostingProvider: () => notCollected('No ASN/hosting enrichment provider is configured for this service.'),
  tlsInfo: () => notCollected('No TLS handshake was performed; this service does not connect to the target.'),
  domainAge: () => notCollected('Registration age requires a WHOIS/RDAP provider, which is not configured here.'),
  reputation: () => notCollected('Reputation requires a feed or blocklist provider, which is not configured here.'),
};

function parseHeaders(rawEmail) {
  const headers = {};
  let current = '';
  for (const line of requiredString(rawEmail, 'rawEmail', 2_000_000).split(/\r?\n/)) {
    if (/^[A-Za-z-]+:/.test(line)) {
      const [key, ...parts] = line.split(':'); current = key.trim(); headers[current] = parts.join(':').trim();
    } else if (/^\s/.test(line) && current) headers[current] += ` ${line.trim()}`;
  }
  return headers;
}

/**
 * Analyse a URL from its own structure alone.
 *
 * Everything reported here is derived from the submitted string: scheme,
 * host shape, lookalike comparison against the registrable domain, suspicious
 * parameters, IP-literal hosts, punycode and known shortener patterns. No
 * request is made to the target and no third-party reputation is claimed.
 */
function buildUrlAnalysis(rawUrl) {
  const parsed = new URL(rawUrl);
  const hostname = parsed.hostname.toLowerCase();

  // Lookalike detection: compare each label against a small set of brands the
  // analyst actually submits. This is a structural comparison, not a feed.
  const BRANDS = ['paypal.com', 'microsoft.com', 'apple.com', 'google.com', 'amazon.com', 'netflix.com', 'linkedin.com', 'dhl.com'];
  const labels = hostname.split('.');
  const registrable = labels.slice(-2).join('.');
  const lookalikeOf = BRANDS.find(brand => {
    if (hostname === brand) return false;
    const brandLabel = brand.split('.')[0];
    return labels.some(label => label !== brandLabel && (label.startsWith(brandLabel) || brandLabel.startsWith(label)) && label.length >= 4);
  });

  const isIpHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  const isPunycode = hostname.includes('xn--');
  const isShortener = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly)$/i.test(hostname);
  const usesInsecureScheme = parsed.protocol === 'http:';
  const suspiciousParams = ['redirect_uri', 'token', 'ref', 'session', 'auth', 'login', 'verify', 'account']
    .filter(param => parsed.searchParams.has(param));
  const embeddedCredentials = parsed.username || parsed.password;
  const rawHostname = /[^\x20-\x7E]/.test(parsed.hostname);

  // Score is a transparent sum of the checks above, not a reputation verdict.
  const findings = [];
  if (lookalikeOf) findings.push({ signal: 'LOOKALIKE_DOMAIN', detail: `Host resembles ${lookalikeOf}`, weight: 35 });
  if (isShortener) findings.push({ signal: 'SHORTENER', detail: `${hostname} is a URL shortener, so the true destination is not visible`, weight: 20 });
  if (isPunycode) findings.push({ signal: 'PUNYCODE_HOST', detail: 'Host uses punycode, which can render as a different string', weight: 20 });
  if (rawHostname) findings.push({ signal: 'NON_ASCII_HOST', detail: 'Host contains non-ASCII characters', weight: 20 });
  if (isIpHost) findings.push({ signal: 'IP_LITERAL_HOST', detail: 'Host is a bare IP address rather than a domain', weight: 25 });
  if (usesInsecureScheme) findings.push({ signal: 'PLAINTEXT_SCHEME', detail: 'URL uses http, so traffic is not encrypted', weight: 15 });
  if (embeddedCredentials) findings.push({ signal: 'EMBEDDED_CREDENTIALS', detail: 'URL embeds credentials in the authority component', weight: 30 });
  if (suspiciousParams.length) findings.push({ signal: 'SENSITIVE_PARAMS', detail: `Query carries ${suspiciousParams.join(', ')}`, weight: 10 });

  const riskScore = Math.min(100, findings.reduce((total, finding) => total + finding.weight, 0));
  const verdict = riskScore >= 60 ? 'SUSPICIOUS' : riskScore >= 25 ? 'SUSPECT' : 'NO_STRUCTURAL_INDICATORS';

  return {
    id: id('URL'),
    originalUrl: rawUrl,
    extractedUrl: rawUrl,
    scheme: parsed.protocol.replace(':', ''),
    finalDomain: hostname,
    registrableDomain: registrable,
    shortenedUrl: isShortener ? rawUrl : null,
    path: parsed.pathname,
    suspiciousParams,
    riskScore,
    verdict,
    severity: riskScore >= 60 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'INFORMATIONAL',
    phishingIndicators: findings,
    // Facts this service genuinely does not have without a provider.
    reputation: NOT_COLLECTED.reputation(),
    domainAge: NOT_COLLECTED.domainAge(),
    domainIntel: {
      lookalikeOf: lookalikeOf || null,
      registrar: NOT_COLLECTED.registrar(),
      hostingProvider: NOT_COLLECTED.hostingProvider(),
      tlsInfo: NOT_COLLECTED.tlsInfo(),
    },
    recommendedAction: findings.length === 0
      ? 'No structural phishing indicators were found. This is not a reputation verdict; confirm with a feed before treating the URL as safe.'
      : `Review manually: ${findings.map(finding => finding.signal).join(', ')}. Confirm against an authorised feed before blocking.`,
    analysedFields: ['scheme', 'host shape', 'lookalike comparison', 'path', 'query parameters', 'punycode', 'IP-literal host', 'embedded credentials'],
    notAnalysed: ['DNS resolution', 'TLS certificate', 'HTTP redirect chain', 'host reputation', 'registration age'],
    disclaimer: 'Structural analysis of the submitted URL only. The target was never contacted and no reputation provider was consulted.',
  };
}

/**
 * Analyse a file from its declared metadata.
 *
 * The verdict reflects the file type and what was declared, never content
 * inspection that did not happen. When the caller supplies content, hashes are
 * computed from it; when it does not, the service says so rather than
 * implying the file was unpacked.
 */
function buildFileAnalysis(input, hasContent) {
  const fileName = requiredString(input.fileName, 'fileName', 255);
  const fileSize = Number(input.fileSize);
  if (!Number.isFinite(fileSize) || fileSize < 0 || fileSize > 25 * 1024 * 1024) {
    throw httpError(400, 'fileSize must be between 0 and 25 MB');
  }
  const extension = (fileName.split('.').pop() || '').toLowerCase();
  const declaredMime = input.mimeType || 'application/octet-stream';

  // Extension-based risk is a policy signal about the file TYPE, not a
  // finding about this file's contents.
  const RISKY_TYPES = {
    exe: 'Executable', msi: 'Executable installer', scr: 'Executable screensaver',
    bat: 'Script', cmd: 'Script', ps1: 'PowerShell script', vbs: 'Script', js: 'Script',
    docm: 'Macro-enabled document', xlsm: 'Macro-enabled workbook', pptm: 'Macro-enabled presentation',
    jar: 'Executable archive', apk: 'Android package', hta: 'Executable script',
  };
  const fileType = RISKY_TYPES[extension] || (extension ? extension.toUpperCase() : 'UNKNOWN');

  const findings = [];
  if (RISKY_TYPES[extension]) {
    findings.push({ signal: 'RISKY_FILE_TYPE', detail: `.${extension} is ${RISKY_TYPES[extension]}, a type that commonly carries executable or macro content` });
  }
  const contentTypeMismatch = hasContent && declaredMime === 'application/octet-stream' && ['pdf', 'png', 'jpg', 'txt'].includes(extension);
  if (contentTypeMismatch) findings.push({ signal: 'MIME_MISMATCH', detail: `Declared ${declaredMime} but the extension suggests a document format` });

  const riskScore = Math.min(100, findings.length * 40);

  return {
    id: id('FILE'),
    fileName,
    fileSize: `${(fileSize / 1024).toFixed(1)} KB`,
    fileType,
    mimeType: declaredMime,
    uploadedAt: new Date().toISOString(),
    riskScore,
    verdict: findings.length ? 'REVIEW_REQUIRED' : 'NO_TYPE_RISK',
    severity: riskScore >= 60 ? 'HIGH' : riskScore >= 40 ? 'MEDIUM' : 'INFORMATIONAL',
    suspiciousFindings: findings,
    extractedIndicators: {
      urls: hasContent ? extractUrls(input.contentText || '') : [],
      domains: hasContent ? extractDomains(input.contentText || '') : [],
      ips: hasContent ? extractIps(input.contentText || '') : [],
      emailAddresses: hasContent ? (String(input.contentText).match(/[\w.+-]+@[\w-]+\.[\w.]+/g) || []) : [],
    },
    hash: input.sha256 || input.hash || null,
    contentInspected: hasContent,
    macroAnalysis: {
      present: null,
      reason: hasContent
        ? 'Macro presence was not determined; this service does not unpack or execute the file. Submit to a sandbox for that determination.'
        : 'No file content was supplied, so nothing about the contents could be determined.',
    },
    recommendedAction: findings.length
      ? 'Quarantine and inspect in a sandbox. The file type is one that commonly carries executable content; the contents were not inspected here.'
      : 'No risk signal from the file type. This says nothing about the contents.',
    analysedFields: hasContent
      ? ['file name', 'extension', 'declared MIME type', 'size', 'supplied text content']
      : ['file name', 'extension', 'declared MIME type', 'size'],
    notAnalysed: ['file contents', 'macros', 'embedded objects', 'antivirus signatures', 'sandbox detonation'],
    disclaimer: 'Metadata and (if supplied) text content were inspected. The file was never opened, unpacked or executed.',
  };
}

const extractUrls = text => (String(text).match(/https?:\/\/[^\s"'<>]+/g) || []).slice(0, 100);
const extractDomains = text => [...new Set((String(text).match(/\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b/gi) || []).map(d => d.toLowerCase()))].slice(0, 100);
const extractIps = text => [...new Set(String(text).match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [])].slice(0, 100);

async function saveAnalysis(type, result, user) {
  const record = {
    id: result.id || result.evidenceId || id(type.toUpperCase()),
    type,
    result,
    createdAt: new Date().toISOString(),
    createdBy: user?.id || user?.email || 'analyst',
  };
  getStore().analyses.push(record);
  await persistStore();
  recordAudit({ actor: record.createdBy, action: `ANALYSIS_${type.toUpperCase()}`, target: record.id });
  return result;
}

export async function listAnalyses() { return getStore().analyses; }

export async function analyzeEmail(input, user) {
  const rawEmail = requiredString(input.rawEmail, 'rawEmail', 2_000_000);
  const headers = parseHeaders(rawEmail);
  const result = {
    headers,
    parsed: true,
    evidenceId: id('EVID'),
    timestamp: new Date().toISOString(),
    // Header findings are computed here; SPF/DKIM/DMARC *verification*
    // requires DNS lookups and is handled by emailAnalysisService, not here.
    headerFindings: analyseAuthenticationHeaders(headers),
    notAnalysed: ['SPF/DKIM/DMARC verification (requires DNS)', 'attachment contents', 'URL detonation', 'reputation'],
    disclaimer: 'Headers were parsed from the submitted message. No DNS or network verification was performed by this endpoint.',
  };
  return saveAnalysis('email', result, user);
}

/** Structural checks over the submitted headers. No DNS is queried. */
function analyseAuthenticationHeaders(headers) {
  const findings = [];
  const lookup = name => Object.keys(headers).find(key => key.toLowerCase() === name) ;
  const spf = lookup('spf');
  const dkim = lookup('dkim-signature');
  const dmarc = lookup('dmarc-record') || headers['authentication-results'];

  if (!spf) findings.push({ signal: 'NO_SPF', detail: 'Message carries no Received-SPF header' });
  if (!dkim) findings.push({ signal: 'NO_DKIM', detail: 'Message carries no DKIM-Signature header' });
  if (!dmarc) findings.push({ signal: 'NO_DMARC_RESULT', detail: 'Message carries no DMARC record or Authentication-Results header' });
  if (spf && /fail/i.test(headers[spf])) findings.push({ signal: 'SPF_FAIL', detail: 'Received-SPF reports a failure' });
  if (spf && /softfail/i.test(headers[spf])) findings.push({ signal: 'SPF_SOFTFAIL', detail: 'Received-SPF reports a soft failure' });

  return {
    findings,
    verified: false,
    note: 'Presence and syntax of authentication headers only. Verification requires the sender\'s DNS records and is not performed here.',
  };
}

export async function analyzeUrl(input, user) {
  return saveAnalysis('url', buildUrlAnalysis(validUrl(input.url)), user);
}

export async function analyzeFile(input, user) {
  // Content is only claimed as inspected when the caller actually sent it.
  const hasContent = typeof input.contentText === 'string' || typeof input.base64 === 'string';
  return saveAnalysis('file', buildFileAnalysis(input, hasContent), user);
}

/**
 * Exposure check.
 *
 * A credential-exposure answer requires an authorised breach-monitoring feed.
 * This service has none configured, so it reports the honest answer — the
 * target was not checked — rather than the previous behaviour of asserting
 * every email address was found in a breach.
 */
export async function checkExposure(input, user) {
  const target = requiredString(input.target, 'target', 320);
  const targetType = requiredString(input.targetType, 'targetType', 30).toLowerCase();
  const isEmail = targetType === 'email' && target.includes('@');

  if (!isEmail) {
    throw httpError(400, 'targetType must be "email" and target must contain "@"');
  }

  const result = {
    found: null,
    checked: false,
    target,
    message: 'Not checked. No authorised breach-monitoring feed is configured, so this service cannot state whether this identity has been exposed. Absence of a result here is not evidence of safety.',
    feedsConfigured: [],
    authorizedUseNote: 'Credential-exposure monitoring requires a feed this organisation is contractually authorised to query.',
    disclaimer: 'No external lookup was performed.',
  };

  recordAudit({ actor: user?.name || user?.email || 'analyst', action: 'EXPOSURE_CHECKED', target, detail: 'no feed configured' });
  return result;
}

/**
 * Correlation over indicators the caller supplied.
 *
 * Each correlation states the concrete relationship it found between the
 * submitted values. Patterns that cannot be established from the input alone
 * are not reported.
 */
export async function correlate(input, user) {
  const indicators = input.indicators || {};
  const list = key => (Array.isArray(indicators[key]) ? indicators[key].map(String).filter(Boolean) : []);
  const emails = list('emails');
  const domains = list('domains');
  const ips = list('ips');
  const urls = list('urls');
  const correlations = [];

  // Domain pairs sharing a registrable label (e.g. two subdomains of one domain).
  const registrable = value => String(value).toLowerCase().split('.').slice(-2).join('.');
  const domainGroups = new Map();
  for (const domain of domains) {
    const key = registrable(domain);
    domainGroups.set(key, [...(domainGroups.get(key) || []), domain]);
  }
  for (const [key, members] of domainGroups) {
    if (members.length > 1) {
      correlations.push({
        type: 'shared_registrable_domain',
        description: `${members.length} submitted domains share the registrable domain ${key}: ${members.join(', ')}`,
        confidence: 90,
        evidence: members,
      });
    }
  }

  // URLs pointing at submitted IPs.
  for (const url of urls) {
    let host = null;
    try { host = new URL(url).hostname; } catch { host = null; }
    if (host && ips.includes(host)) {
      correlations.push({
        type: 'url_resolves_to_submitted_ip',
        description: `Submitted URL ${url} targets ${host}, which is also a submitted indicator`,
        confidence: 85,
        evidence: [url, host],
      });
    }
  }

  // Submitted emails whose domain is also a submitted indicator domain.
  for (const email of emails) {
    const domain = email.split('@')[1];
    if (domain && domains.includes(domain)) {
      correlations.push({
        type: 'sender_domain_is_indicator',
        description: `Submitted address ${email} uses ${domain}, which is also a submitted indicator domain`,
        confidence: 80,
        evidence: [email, domain],
      });
    }
  }

  const result = {
    correlated: correlations.length > 0,
    correlations,
    indicatorsSubmitted: { emails: emails.length, domains: domains.length, ips: ips.length, urls: urls.length },
    suggestedCampaign: correlations.length ? {
      id: id('CMP'),
      name: 'Correlated Indicator Set',
      confidence: Math.max(...correlations.map(item => item.confidence)),
      relatedIndicators: { emails, domains, ips, urls },
    } : null,
    note: correlations.length
      ? 'Each correlation above is a concrete relationship between the submitted indicators.'
      : 'No relationship was established among the submitted indicators.',
  };
  if (result.suggestedCampaign) getStore().campaigns.push(result.suggestedCampaign);
  await persistStore();
  recordAudit({ actor: user?.name || user?.email || 'analyst', action: 'CORRELATION_RUN', target: 'indicator-set' });
  return result;
}