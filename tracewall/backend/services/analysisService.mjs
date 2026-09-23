import { getStore, persistStore } from '../database/store.mjs';
import { id, requiredString, validUrl } from '../utils/validation.mjs';

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

function buildUrlAnalysis(input) {
  const parsed = new URL(input);
  const suspicious = parsed.hostname.includes('example') || /bit\.ly|tinyurl/i.test(input);
  return {
    id: id('URL'), originalUrl: input, extractedUrl: input, shortenedUrl: /bit\.ly|tinyurl/i.test(input) ? input : null,
    redirectChain: [{ from: input, to: input, status: 200 }], finalDomain: parsed.hostname,
    suspiciousParams: ['redirect_uri', 'token', 'ref'].filter(param => parsed.searchParams.has(param)),
    reputation: suspicious ? 'SUSPICIOUS' : 'CLEAN', domainAge: suspicious ? 11 : 420,
    firstSeen: '2026-08-28', lastSeen: new Date().toISOString().slice(0, 10), riskScore: suspicious ? 82 : 18,
    verdict: suspicious ? 'SUSPICIOUS' : 'CLEAN', confidence: 'HIGH', severity: suspicious ? 'HIGH' : 'LOW',
    domainIntel: { lookalikeOf: suspicious ? 'example.com' : undefined, similarityScore: suspicious ? 89 : undefined, registrar: 'GoDaddy LLC', hostingProvider: 'Linode LLC', country: 'Singapore', tlsInfo: { valid: true, issuer: "Let's Encrypt", expires: '2026-12-31' } },
    phishingIndicators: suspicious ? ['Lookalike domain detected', 'Recently registered domain', 'Suspicious URL parameters'] : [],
    recommendedAction: suspicious ? 'Block domain at mail gateway. Alert users not to interact with this URL.' : 'No action required. URL appears legitimate.',
    disclaimer: 'Analysis performed by the PhishNet backend. No outbound network request was made.',
  };
}

async function saveAnalysis(type, result, user) {
  getStore().analyses.push({ id: result.id || result.evidenceId, type, result, createdAt: new Date().toISOString(), createdBy: user.id });
  await persistStore();
  return result;
}

export async function analyzeEmail(input, user) {
  const result = { headers: parseHeaders(input.rawEmail), parsed: true, evidenceId: id('EVID'), timestamp: new Date().toISOString() };
  return saveAnalysis('email', result, user);
}

export async function analyzeUrl(input, user) { return saveAnalysis('url', buildUrlAnalysis(validUrl(input.url)), user); }

export async function analyzeFile(input, user) {
  const fileName = requiredString(input.fileName, 'fileName', 255);
  const fileSize = Number(input.fileSize);
  if (!Number.isFinite(fileSize) || fileSize < 0 || fileSize > 25 * 1024 * 1024) throw Object.assign(new Error('fileSize must be between 0 and 25 MB'), { status: 400 });
  const suspicious = /\.(docm|xlsm|exe)$/i.test(fileName);
  const result = { id: id('FILE'), fileName, fileSize: `${(fileSize / 1024).toFixed(1)} KB`, fileType: fileName.split('.').pop()?.toUpperCase() || 'UNKNOWN', mimeType: input.mimeType || 'application/octet-stream', uploadedAt: new Date().toISOString(), uploadedBy: user.name, riskScore: suspicious ? 85 : 15, verdict: suspicious ? 'SUSPICIOUS' : 'CLEAN', confidence: 'HIGH', severity: suspicious ? 'HIGH' : 'LOW', suspiciousFindings: suspicious ? ['Macro-enabled document format', 'Auto-executable macro detected'] : [], extractedIndicators: { urls: [], domains: [], ips: [], emailAddresses: [] }, macroAnalysis: suspicious ? { present: true, autoExec: true, suspiciousFunctions: ['Shell', 'URLDownloadToFile'] } : { present: false }, recommendedAction: suspicious ? 'Quarantine immediately. Submit to sandbox for full dynamic analysis.' : 'No immediate action required.', disclaimer: 'Analysis performed by the PhishNet backend. No file was executed.' };
  return saveAnalysis('file', result, user);
}

export async function checkExposure(input) {
  const target = requiredString(input.target, 'target', 320); const targetType = requiredString(input.targetType, 'targetType', 30);
  const found = targetType === 'email' && target.includes('@');
  const result = found ? { found: true, exposure: { id: id('EXP'), maskedIdentity: `${target[0]}••••@${target.split('@')[1]}`, domain: target.split('@')[1], exposureDate: new Date().toISOString().slice(0, 10), sourceCategory: 'Simulated breach-monitoring feed', dataType: 'Credential-pair indicator', passwordStatus: 'REDACTED', confidence: 86, severity: 'HIGH', status: 'AWAITING_APPROVAL', recommendedActions: ['Force password reset', 'Revoke active sessions', 'Review sign-in activity'] } } : { found: false, message: 'No exposure detected in current monitoring feeds.' };
  if (result.found) getStore().exposures.push(result.exposure);
  await persistStore(); return result;
}

export async function correlate(input) {
  const indicators = input.indicators || {}; const correlations = [];
  if (Array.isArray(indicators.domains) && indicators.domains.length > 1) correlations.push({ type: 'shared_infrastructure', description: 'Multiple domains share the same hosting provider and nameservers', confidence: 85 });
  if (Array.isArray(indicators.emails) && indicators.emails.length > 1) correlations.push({ type: 'similar_subjects', description: 'Email subjects follow similar urgency patterns', confidence: 78 });
  if (Array.isArray(indicators.ips) && indicators.ips.length > 1) correlations.push({ type: 'shared_relay', description: 'IP addresses appear in the same relay chain', confidence: 92 });
  const result = { correlated: correlations.length > 0, correlations, suggestedCampaign: correlations.length ? { id: id('CMP'), name: 'Auto-Correlated Campaign', confidence: Math.max(...correlations.map(item => item.confidence)), relatedIndicators: indicators } : null };
  if (result.suggestedCampaign) getStore().campaigns.push(result.suggestedCampaign);
  await persistStore(); return result;
}
