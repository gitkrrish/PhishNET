import { Resolver } from 'node:dns/promises';
import { isIP } from 'node:net';
import { config } from '../config/env.mjs';
import { getStore, persistStore } from '../database/store.mjs';
import { id, requiredString } from '../utils/validation.mjs';

function timeout(promise, ms = config.infrastructureTimeoutMs) {
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('timeout')), ms);
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

async function observeProvider(provider, task) {
  const startedAt = Date.now();
  console.info(`[ip-analysis] provider=${provider} event=start`);
  try {
    const result = await task();
    const durationMs = Date.now() - startedAt;
    console.info(`[ip-analysis] provider=${provider} status=${result?.status || 'UNKNOWN'} durationMs=${durationMs}`);
    return result;
  } catch (error) {
    const durationMs = Date.now() - startedAt;
    console.info(`[ip-analysis] provider=${provider} status=ERROR category=${error?.name || 'Error'} durationMs=${durationMs}`);
    throw error;
  }
}

function safeDomain(input = '') {
  let domain = input.trim().toLowerCase();
  // Strip protocol if present
  domain = domain.replace(/^https?:\/\//i, '');
  // Strip trailing path/query/port
  domain = domain.split('/')[0].split('?')[0].split('#')[0].split(':')[0];
  return domain;
}

function isValidIp(ip) {
  return isIP(ip) === 4 || isIP(ip) === 6;
}

function isValidDomain(domain) {
  if (!domain || domain.length > 253) return false;
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

function normalizeText(value) {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (value && typeof value === 'object') {
    if (value.source || value.detail) {
      return [value.source, value.detail].filter(Boolean).join(': ');
    }
    if (typeof value.text === 'string') return value.text;
    if (typeof value.message === 'string') return value.message;
    return JSON.stringify(value);
  }
  return '';
}

function normalizeTextList(value) {
  if (!Array.isArray(value)) return value == null ? [] : [normalizeText(value)].filter(Boolean);
  return value.map(normalizeText).filter(Boolean);
}

function normalizeAiAssessment(value) {
  if (!value || typeof value !== 'object') return null;
  return {
    overallAssessment: normalizeText(value.overallAssessment),
    majorRiskIndicators: normalizeTextList(value.majorRiskIndicators),
    vpnProxyTorInterpretation: normalizeText(value.vpnProxyTorInterpretation),
    fraudIndicators: normalizeTextList(value.fraudIndicators),
    abuseIndicators: normalizeTextList(value.abuseIndicators),
    threatIntelligence: normalizeText(value.threatIntelligence),
    importantEvidence: normalizeTextList(value.importantEvidence),
    recommendedAction: normalizeText(value.recommendedAction),
    confidence: normalizeText(value.confidence),
    uncertainty: normalizeText(value.uncertainty),
    raw: normalizeText(value.raw),
  };
}

// ----------------------------------------------------------------------------
// PROVIDER FETCHERS
// ----------------------------------------------------------------------------

async function fetchAbuseIpDb(ip) {
  if (!config.abuseIpDbApiKey) {
    return { provider: 'AbuseIPDB', status: 'NOT CONFIGURED', detail: 'ABUSEIPDB_API_KEY is not configured.' };
  }
  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const response = await timeout(fetch(url, {
      headers: { Key: config.abuseIpDbApiKey, Accept: 'application/json' }
    }));
    if (response.status === 401 || response.status === 403) {
      return { provider: 'AbuseIPDB', status: 'FAILED', error: 'Authentication failed (invalid key)' };
    }
    if (response.status === 429) {
      return { provider: 'AbuseIPDB', status: 'FAILED', error: 'Rate limited by AbuseIPDB' };
    }
    if (!response.ok) {
      return { provider: 'AbuseIPDB', status: 'FAILED', error: `HTTP ${response.status}` };
    }
    const json = await response.json();
    const data = json.data || {};
    return {
      provider: 'AbuseIPDB',
      status: 'SUCCESS',
      data: {
        ip: data.ipAddress,
        abuseConfidenceScore: data.abuseConfidenceScore ?? 0,
        totalReports: data.totalReports ?? 0,
        numDistinctUsers: data.numDistinctUsers ?? 0,
        lastReportedAt: data.lastReportedAt || null,
        countryCode: data.countryCode || '',
        countryName: data.countryName || '',
        isp: data.isp || '',
        domain: data.domain || '',
        usageType: data.usageType || '',
        hostnames: data.hostnames || [],
        isWhitelisted: Boolean(data.isWhitelisted),
        isTor: Boolean(data.isTor),
      }
    };
  } catch (err) {
    return { provider: 'AbuseIPDB', status: err.message === 'timeout' ? 'UNAVAILABLE' : 'FAILED', error: err.message };
  }
}

async function fetchVirusTotalIp(ip) {
  if (!config.virustotalApiKey) {
    return { provider: 'VirusTotal', status: 'NOT CONFIGURED', detail: 'VIRUSTOTAL_API_KEY is not configured.' };
  }
  try {
    const url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`;
    const response = await timeout(fetch(url, {
      headers: { 'x-apikey': config.virustotalApiKey }
    }));
    if (response.status === 401 || response.status === 403) {
      return { provider: 'VirusTotal', status: 'FAILED', error: 'Authentication failed' };
    }
    if (response.status === 429) {
      return { provider: 'VirusTotal', status: 'FAILED', error: 'Rate limited' };
    }
    if (response.status === 404) {
      return { provider: 'VirusTotal', status: 'SUCCESS', data: { notFound: true, stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 } } };
    }
    if (!response.ok) {
      return { provider: 'VirusTotal', status: 'FAILED', error: `HTTP ${response.status}` };
    }
    const json = await response.json();
    const attrs = json.data?.attributes || {};
    return {
      provider: 'VirusTotal',
      status: 'SUCCESS',
      data: {
        stats: attrs.last_analysis_stats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        reputation: attrs.reputation ?? 0,
        asn: attrs.asn ? `AS${attrs.asn}` : '',
        asOwner: attrs.as_owner || '',
        country: attrs.country || '',
        network: attrs.network || '',
        whois: attrs.whois || '',
        tags: attrs.tags || [],
      }
    };
  } catch (err) {
    return { provider: 'VirusTotal', status: err.message === 'timeout' ? 'UNAVAILABLE' : 'FAILED', error: err.message };
  }
}

async function fetchVirusTotalDomain(domain) {
  if (!config.virustotalApiKey) {
    return { provider: 'VirusTotal', status: 'NOT CONFIGURED', detail: 'VIRUSTOTAL_API_KEY is not configured.' };
  }
  try {
    const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`;
    const response = await timeout(fetch(url, {
      headers: { 'x-apikey': config.virustotalApiKey }
    }));
    if (response.status === 401 || response.status === 403) {
      return { provider: 'VirusTotal', status: 'FAILED', error: 'Authentication failed' };
    }
    if (response.status === 429) {
      return { provider: 'VirusTotal', status: 'FAILED', error: 'Rate limited' };
    }
    if (response.status === 404) {
      return { provider: 'VirusTotal', status: 'SUCCESS', data: { notFound: true, stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 } } };
    }
    if (!response.ok) {
      return { provider: 'VirusTotal', status: 'FAILED', error: `HTTP ${response.status}` };
    }
    const json = await response.json();
    const attrs = json.data?.attributes || {};
    return {
      provider: 'VirusTotal',
      status: 'SUCCESS',
      data: {
        stats: attrs.last_analysis_stats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        reputation: attrs.reputation ?? 0,
        registrar: attrs.registrar || '',
        creationDate: attrs.creation_date ? new Date(attrs.creation_date * 1000).toISOString().slice(0, 10) : '',
        lastUpdateDate: attrs.last_update_date ? new Date(attrs.last_update_date * 1000).toISOString().slice(0, 10) : '',
        categories: attrs.categories || {},
        tags: attrs.tags || [],
        dnsRecords: attrs.last_dns_records || [],
      }
    };
  } catch (err) {
    return { provider: 'VirusTotal', status: err.message === 'timeout' ? 'UNAVAILABLE' : 'FAILED', error: err.message };
  }
}

async function fetchOtxIp(ip) {
  if (!config.otxApiKey) {
    return { provider: 'OTX', status: 'NOT CONFIGURED', detail: 'OTX_API_KEY is not configured.' };
  }
  try {
    const url = `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(ip)}/general`;
    const response = await timeout(fetch(url, {
      headers: { 'X-OTX-API-KEY': config.otxApiKey }
    }));
    if (response.status === 401 || response.status === 403) {
      return { provider: 'OTX', status: 'FAILED', error: 'Authentication failed' };
    }
    if (!response.ok) {
      return { provider: 'OTX', status: 'FAILED', error: `HTTP ${response.status}` };
    }
    const json = await response.json();
    const pulseCount = json.pulse_info?.count ?? 0;
    const pulses = (json.pulse_info?.pulses || []).slice(0, 5).map(p => ({
      id: p.id,
      name: p.name,
      tags: p.tags || [],
      author: p.author_name || '',
      created: p.created ? new Date(p.created).toISOString().slice(0, 10) : ''
    }));
    return {
      provider: 'OTX',
      status: 'SUCCESS',
      data: {
        pulseCount,
        pulses,
        reputation: json.reputation ?? 0,
        asn: json.asn || '',
        countryName: json.country_name || '',
        city: json.city || '',
      }
    };
  } catch (err) {
    return { provider: 'OTX', status: err.message === 'timeout' ? 'UNAVAILABLE' : 'FAILED', error: err.message };
  }
}

async function fetchOtxDomain(domain) {
  if (!config.otxApiKey) {
    return { provider: 'OTX', status: 'NOT CONFIGURED', detail: 'OTX_API_KEY is not configured.' };
  }
  try {
    const url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/general`;
    const response = await timeout(fetch(url, {
      headers: { 'X-OTX-API-KEY': config.otxApiKey }
    }));
    if (response.status === 401 || response.status === 403) {
      return { provider: 'OTX', status: 'FAILED', error: 'Authentication failed' };
    }
    if (!response.ok) {
      return { provider: 'OTX', status: 'FAILED', error: `HTTP ${response.status}` };
    }
    const json = await response.json();
    const pulseCount = json.pulse_info?.count ?? 0;
    const pulses = (json.pulse_info?.pulses || []).slice(0, 5).map(p => ({
      id: p.id,
      name: p.name,
      tags: p.tags || [],
      author: p.author_name || '',
      created: p.created ? new Date(p.created).toISOString().slice(0, 10) : ''
    }));
    return {
      provider: 'OTX',
      status: 'SUCCESS',
      data: {
        pulseCount,
        pulses,
        alexa: json.alexa || null,
        whois: json.whois || '',
      }
    };
  } catch (err) {
    return { provider: 'OTX', status: err.message === 'timeout' ? 'UNAVAILABLE' : 'FAILED', error: err.message };
  }
}

async function fetchIpWho(ip) {
  try {
    let url = `https://ipwho.is/${encodeURIComponent(ip)}`;
    if (config.ipWhoApiKey) {
      url = `https://ipwhois.pro/${encodeURIComponent(ip)}?key=${encodeURIComponent(config.ipWhoApiKey)}`;
    }
    let response = await timeout(fetch(url));
    if (!response.ok && config.ipWhoApiKey) {
      // Fallback to public ipwho.is endpoint
      response = await timeout(fetch(`https://ipwho.is/${encodeURIComponent(ip)}`));
    }
    if (!response.ok) {
      return { provider: 'IPWhois', status: 'FAILED', error: `HTTP ${response.status}` };
    }
    const json = await response.json();
    if (json.success === false) {
      return { provider: 'IPWhois', status: 'FAILED', error: json.message || 'IPWhois lookup failed' };
    }
    return {
      provider: 'IPWhois',
      status: 'SUCCESS',
      data: {
        ip: json.ip,
        type: json.type || 'IPv4',
        continent: json.continent || '',
        country: json.country || '',
        countryCode: json.country_code || '',
        region: json.region || '',
        city: json.city || '',
        latitude: typeof json.latitude === 'number' ? json.latitude : parseFloat(json.latitude),
        longitude: typeof json.longitude === 'number' ? json.longitude : parseFloat(json.longitude),
        asn: json.connection?.asn ? `AS${json.connection.asn}` : (json.asn || ''),
        asnOrg: json.connection?.org || json.org || '',
        isp: json.connection?.isp || json.isp || '',
        domain: json.connection?.domain || json.domain || '',
        timezone: json.timezone?.id || json.timezone || '',
        isProxy: Boolean(json.security?.proxy),
        isVpn: Boolean(json.security?.vpn),
        isTor: Boolean(json.security?.tor),
        isHosting: Boolean(json.security?.hosting),
      }
    };
  } catch (err) {
    return { provider: 'IPWhois', status: err.message === 'timeout' ? 'UNAVAILABLE' : 'FAILED', error: err.message };
  }
}

async function fetchIpInfo(ip) {
  if (!config.ipInfoToken) {
    return { provider: 'IPinfo', status: 'NOT CONFIGURED', detail: 'IPINFO_TOKEN is not configured.' };
  }
  try {
    const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(config.ipInfoToken)}`;
    const response = await timeout(fetch(url, {
      headers: { Authorization: `Bearer ${config.ipInfoToken}` }
    }));
    if (response.status === 401 || response.status === 403) {
      return { provider: 'IPinfo', status: 'FAILED', error: 'Authentication failed' };
    }
    if (!response.ok) {
      return { provider: 'IPinfo', status: 'FAILED', error: `HTTP ${response.status}` };
    }
    const json = await response.json();
    let latitude = null;
    let longitude = null;
    if (json.loc && typeof json.loc === 'string') {
      const [latStr, lngStr] = json.loc.split(',');
      latitude = parseFloat(latStr);
      longitude = parseFloat(lngStr);
    }
    return {
      provider: 'IPinfo',
      status: 'SUCCESS',
      data: {
        ip: json.ip,
        hostname: json.hostname || '',
        city: json.city || '',
        region: json.region || '',
        country: json.country || '',
        postal: json.postal || '',
        timezone: json.timezone || '',
        org: json.org || '',
        latitude: Number.isFinite(latitude) ? latitude : null,
        longitude: Number.isFinite(longitude) ? longitude : null,
        privacy: json.privacy || null,
        bogon: Boolean(json.bogon),
      }
    };
  } catch (err) {
    return { provider: 'IPinfo', status: err.message === 'timeout' ? 'UNAVAILABLE' : 'FAILED', error: err.message };
  }
}

async function fetchDnsForDomain(domain) {
  const resolver = new Resolver();
  resolver.setServers(config.dnsServers);

  const lookupRecord = async (fn) => {
    try {
      return await timeout(fn());
    } catch {
      return [];
    }
  };

  const [a, aaaa, mx, ns, txt, cname, ptr] = await Promise.all([
    lookupRecord(() => resolver.resolve4(domain)),
    lookupRecord(() => resolver.resolve6(domain)),
    lookupRecord(() => resolver.resolveMx(domain)),
    lookupRecord(() => resolver.resolveNs(domain)),
    lookupRecord(() => resolver.resolveTxt(domain)),
    lookupRecord(() => resolver.resolveCname(domain)),
    lookupRecord(async () => {
      const ips = await resolver.resolve4(domain).catch(() => []);
      if (!ips[0]) return [];
      return resolver.reverse(ips[0]).catch(() => []);
    }),
  ]);

  let dmarc = [];
  try {
    dmarc = await timeout(resolver.resolveTxt(`_dmarc.${domain}`));
  } catch {
    dmarc = [];
  }

  const txtRecords = txt.flat();
  const spfRecord = txtRecords.find(t => /^v=spf1/i.test(t)) || '';
  const dmarcRecords = dmarc.flat();
  const dmarcRecord = dmarcRecords.find(t => /^v=dmarc1/i.test(t)) || '';
  const mxRecords = mx.map(m => m.exchange ? `${m.priority ? m.priority + ' ' : ''}${m.exchange}` : String(m));

  return {
    status: 'SUCCESS',
    data: {
      a,
      aaaa,
      mx: mxRecords,
      ns,
      txt: txtRecords,
      cname,
      ptr,
      spfRecord: spfRecord || 'Not found',
      dmarcRecord: dmarcRecord || 'Not found',
    }
  };
}

async function fetchDnsForIp(ip) {
  const resolver = new Resolver();
  resolver.setServers(config.dnsServers);
  try {
    const hostnames = await timeout(resolver.reverse(ip));
    return { status: 'SUCCESS', data: { hostnames } };
  } catch {
    return { status: 'SUCCESS', data: { hostnames: [] } };
  }
}

// ----------------------------------------------------------------------------
// NEW PROVIDER FETCHERS
// ----------------------------------------------------------------------------

async function fetchIpQualityScore(ip) {
  if (!config.ipQualityScoreApiKey) {
    return { provider: 'IPQualityScore', status: 'NOT CONFIGURED', detail: 'IPQUALITYSCORE_API_KEY is not configured.' };
  }
  try {
    const url = `https://ipqualityscore.com/api/json/ip/${config.ipQualityScoreApiKey}/${encodeURIComponent(ip)}?strictness=1&allow_public_access_points=true&lighter_penalties=false&fast=false`;
    const response = await timeout(fetch(url, { headers: { Accept: 'application/json' } }));
    if (response.status === 401 || response.status === 403) {
      return { provider: 'IPQualityScore', status: 'FAILED', error: 'Authentication failed (invalid key)' };
    }
    if (response.status === 429) {
      return { provider: 'IPQualityScore', status: 'FAILED', error: 'Rate limited by IPQualityScore' };
    }
    if (!response.ok) {
      return { provider: 'IPQualityScore', status: 'FAILED', error: `HTTP ${response.status}` };
    }
    const json = await response.json();
    return {
      provider: 'IPQualityScore',
      status: 'SUCCESS',
      data: {
        fraudScore: json.fraud_score ?? null,
        proxy: json.proxy ?? false,
        vpn: json.vpn ?? false,
        tor: json.tor ?? false,
        bot: json.bot_status ?? false,
        crawler: json.crawler_status ?? false,
        recentAbuse: json.recent_abuse ?? false,
        abuseVelocity: json.abuse_velocity ?? null,
        connectionType: json.connection_type || '',
        isp: json.ISP || '',
        organization: json.organization || '',
        asn: json.ASN ? `AS${json.ASN}` : '',
        country: json.country_code || '',
        city: json.city || '',
        region: json.region || '',
        timezone: json.timezone || '',
        riskIndicators: json.risk_indicators || {},
        activeVpn: json.active_vpn ?? false,
        activeProxy: json.active_proxy ?? false,
        activeTor: json.active_tor ?? false,
        hostingProvider: json.hosting_provider || '',
      }
    };
  } catch (err) {
    return { provider: 'IPQualityScore', status: err.message === 'timeout' ? 'UNAVAILABLE' : 'FAILED', error: err.message };
  }
}

async function fetchProxyCheck(ip) {
  if (!config.proxyCheckApiKey) {
    return { provider: 'ProxyCheck', status: 'NOT CONFIGURED', detail: 'PROXYCHECK_API_KEY is not configured.' };
  }
  try {
    const url = `https://proxycheck.io/v2/${encodeURIComponent(ip)}?key=${encodeURIComponent(config.proxyCheckApiKey)}&vpn=1&asn=1&risk=1&port=1&seen=1&tag=tracewall`;
    const response = await timeout(fetch(url, { headers: { Accept: 'application/json' } }));
    if (response.status === 401 || response.status === 403) {
      return { provider: 'ProxyCheck', status: 'FAILED', error: 'Authentication failed (invalid key)' };
    }
    if (response.status === 429) {
      return { provider: 'ProxyCheck', status: 'FAILED', error: 'Rate limited by ProxyCheck' };
    }
    if (!response.ok) {
      return { provider: 'ProxyCheck', status: 'FAILED', error: `HTTP ${response.status}` };
    }
    const json = await response.json();
    const data = json[ip] || {};
    return {
      provider: 'ProxyCheck',
      status: 'SUCCESS',
      data: {
        proxy: data.proxy === 'yes',
        type: data.type || '',
        risk: data.risk || 0,
        provider: data.provider || '',
        country: data.country || '',
        city: data.city || '',
        asn: data.asn || '',
        organization: data.organisation || '',
        hostname: data.host || '',
        range: data.range || '',
        detectionStatus: data.status || '',
        daysSeen: data.days_seen || 0,
      }
    };
  } catch (err) {
    return { provider: 'ProxyCheck', status: err.message === 'timeout' ? 'UNAVAILABLE' : 'FAILED', error: err.message };
  }
}

async function fetchLlama3Assessment(normalizedData) {
  if (!config.groqApiKey) {
    return { provider: 'Llama3 (Groq)', status: 'NOT CONFIGURED', detail: 'GROQ_API_KEY is not configured.' };
  }
  try {
    const systemPrompt = `You are an IP intelligence analyst. Analyze the provided normalized IP intelligence data and produce a concise, evidence-based assessment. 

RULES:
- Only use the provided data. Do not fabricate or infer beyond what the data supports.
- If evidence is missing or providers disagree, state that clearly.
- Be specific about which providers support which findings.
- Include: overall assessment, major risk indicators, VPN/proxy/Tor interpretation, fraud/abuse indicators, threat intelligence, important evidence, recommended defensive action, confidence/uncertainty.
- Format as structured JSON with keys: overallAssessment, majorRiskIndicators, vpnProxyTorInterpretation, fraudIndicators, abuseIndicators, threatIntelligence, importantEvidence, recommendedAction, confidence, uncertainty. ONLY output the JSON object, nothing else.`;

    const userPrompt = `Analyze this IP intelligence data:\n${JSON.stringify(normalizedData, null, 2)}`;

    const response = await timeout(fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.groqApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'groq/compound-mini',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.1,
        max_tokens: 800,
        response_format: { type: 'json_object' },
      }),
    }));

    if (response.status === 401 || response.status === 403) {
      return { provider: 'Llama3 (Groq)', status: 'FAILED', error: 'Authentication failed (invalid key)' };
    }
    if (response.status === 429) {
      const errorBody = await response.clone().json().catch(() => ({}));
      const detail = errorBody.error?.message || 'Rate limited by Groq';
      return { provider: 'Llama3 (Groq)', status: 'FAILED', detail: 'Rate limited', error: detail };
    }
    if (!response.ok) {
      return { provider: 'Llama3 (Groq)', status: 'FAILED', error: `HTTP ${response.status}` };
    }
    const json = await response.json();
    const content = json.choices?.[0]?.message?.content || '{}';
    let assessment = {};
    try {
      assessment = JSON.parse(content);
    } catch {
      assessment = { raw: content };
    }
    return {
      provider: 'Llama3 (Groq)',
      status: 'SUCCESS',
      data: assessment,
    };
  } catch (err) {
    return { provider: 'Llama3 (Groq)', status: err.message === 'timeout' ? 'UNAVAILABLE' : 'FAILED', error: err.message };
  }
}

// ----------------------------------------------------------------------------
// MAIN EXPORTED SERVICES
// ----------------------------------------------------------------------------

export async function analyzeIp(input, user) {
  const rawIp = requiredString(input.ip || input.target, 'ip', 100).trim();
  if (!isValidIp(rawIp)) {
    throw Object.assign(new Error(`Invalid IP address format: "${rawIp}"`), { status: 400 });
  }

  const [abuseRes, vtRes, otxRes, ipWhoRes, ipInfoRes, dnsRes, ipqsRes, proxyCheckRes] = await Promise.all([
    observeProvider('AbuseIPDB', () => fetchAbuseIpDb(rawIp)),
    observeProvider('VirusTotal', () => fetchVirusTotalIp(rawIp)),
    observeProvider('OTX', () => fetchOtxIp(rawIp)),
    observeProvider('IPWhois', () => fetchIpWho(rawIp)),
    observeProvider('IPinfo', () => fetchIpInfo(rawIp)),
    observeProvider('DNS', () => fetchDnsForIp(rawIp)),
    observeProvider('IPQualityScore', () => fetchIpQualityScore(rawIp)),
    observeProvider('ProxyCheck', () => fetchProxyCheck(rawIp)),
  ]);

  const providers = [abuseRes, vtRes, otxRes, ipWhoRes, ipInfoRes, ipqsRes, proxyCheckRes];

  // Geolocation & Network Aggregation
  let latitude = ipInfoRes.data?.latitude ?? ipWhoRes.data?.latitude ?? null;
  let longitude = ipInfoRes.data?.longitude ?? ipWhoRes.data?.longitude ?? null;
  let country = ipInfoRes.data?.country || ipWhoRes.data?.country || abuseRes.data?.countryName || vtRes.data?.country || 'Unknown';
  let region = ipInfoRes.data?.region || ipWhoRes.data?.region || 'Unknown';
  let city = ipInfoRes.data?.city || ipWhoRes.data?.city || otxRes.data?.city || 'Unknown';
  let isp = abuseRes.data?.isp || ipWhoRes.data?.isp || ipInfoRes.data?.org || vtRes.data?.asOwner || 'Unknown';
  let asn = vtRes.data?.asn || ipWhoRes.data?.asn || otxRes.data?.asn || 'Unknown';
  let asnName = vtRes.data?.asOwner || ipWhoRes.data?.asnOrg || ipInfoRes.data?.org || 'Unknown';
  let hostingProvider = isp;

  // VPN/Proxy/Tor/Anonymization Detection (correlated from multiple providers)
  const ipqsData = ipqsRes.data || {};
  const proxyCheckData = proxyCheckRes.data || {};
  const ipWhoData = ipWhoRes.data || {};
  const ipInfoData = ipInfoRes.data || {};

  // VPN detection
  const vpnSignals = [
    { source: 'IPWhois', value: Boolean(ipWhoData.isVpn) },
    { source: 'IPQualityScore', value: Boolean(ipqsData.vpn || ipqsData.activeVpn) },
    { source: 'ProxyCheck', value: Boolean(proxyCheckData.proxy && (proxyCheckData.type === 'VPN' || proxyCheckData.type === 'VPN/Proxy')) },
    { source: 'IPinfo', value: Boolean(ipInfoData.privacy?.vpn) },
  ];
  const vpnDetected = vpnSignals.filter(s => s.value).length;
  const vpnSources = vpnSignals.filter(s => s.value).map(s => s.source);
  let isVpn = false;
  let vpnStatus = 'NOT DETECTED';
  let vpnConfidence = 0;
  if (vpnDetected >= 2) { isVpn = true; vpnStatus = 'DETECTED'; vpnConfidence = 85; }
  else if (vpnDetected === 1) { isVpn = true; vpnStatus = 'LIKELY'; vpnConfidence = 55; }

  // Proxy detection
  const proxySignals = [
    { source: 'IPWhois', value: Boolean(ipWhoData.isProxy) },
    { source: 'IPQualityScore', value: Boolean(ipqsData.proxy || ipqsData.activeProxy) },
    { source: 'ProxyCheck', value: Boolean(proxyCheckData.proxy) },
    { source: 'IPinfo', value: Boolean(ipInfoData.privacy?.proxy) },
  ];
  const proxyDetected = proxySignals.filter(s => s.value).length;
  const proxySources = proxySignals.filter(s => s.value).map(s => s.source);
  let isProxy = false;
  let proxyStatus = 'NOT DETECTED';
  let proxyConfidence = 0;
  if (proxyDetected >= 2) { isProxy = true; proxyStatus = 'DETECTED'; proxyConfidence = 85; }
  else if (proxyDetected === 1) { isProxy = true; proxyStatus = 'LIKELY'; proxyConfidence = 55; }

  // Tor detection
  const torSignals = [
    { source: 'AbuseIPDB', value: Boolean(abuseRes.data?.isTor) },
    { source: 'IPWhois', value: Boolean(ipWhoData.isTor) },
    { source: 'IPQualityScore', value: Boolean(ipqsData.tor || ipqsData.activeTor) },
    { source: 'IPinfo', value: Boolean(ipInfoData.privacy?.tor) },
  ];
  const torDetected = torSignals.filter(s => s.value).length;
  const torSources = torSignals.filter(s => s.value).map(s => s.source);
  let isTor = false;
  let torStatus = 'NOT DETECTED';
  let torConfidence = 0;
  if (torDetected >= 1) { isTor = true; torStatus = torDetected >= 2 ? 'DETECTED' : 'LIKELY'; torConfidence = torDetected >= 2 ? 85 : 55; }

  // Hosting/Cloud detection
  const hostingSignals = [
    { source: 'IPWhois', value: Boolean(ipWhoData.isHosting) },
    { source: 'IPQualityScore', value: Boolean(ipqsData.hostingProvider) },
    { source: 'IPinfo', value: Boolean(ipInfoData.privacy?.hosting) },
  ];
  const hostingDetected = hostingSignals.filter(s => s.value).length;
  const isCloud = Boolean(ipWhoData.isHosting || ipqsData.hostingProvider || ipInfoData.privacy?.hosting || /amazon|aws|google|azure|linode|digitalocean|hetzner|ovh|cloudflare/i.test(isp));
  let hostingStatus = 'NOT DETECTED';
  if (hostingDetected >= 2) hostingStatus = 'DETECTED';
  else if (hostingDetected === 1) hostingStatus = 'LIKELY';

  // Anonymization/Tunneling indicator
  const anonymizationScore = (vpnDetected > 0 ? 1 : 0) + (proxyDetected > 0 ? 1 : 0) + (torDetected > 0 ? 1 : 0) + (hostingDetected > 0 ? 1 : 0);
  let anonymizationStatus = 'NOT DETECTED';
  let anonymizationConfidence = 0;
  if (anonymizationScore >= 3) { anonymizationStatus = 'DETECTED'; anonymizationConfidence = 80; }
  else if (anonymizationScore === 2) { anonymizationStatus = 'LIKELY'; anonymizationConfidence = 60; }
  else if (anonymizationScore === 1) { anonymizationStatus = 'LIKELY'; anonymizationConfidence = 40; }

  // Fraud Score (from IPQS)
  const fraudScore = ipqsData.fraudScore !== undefined && ipqsData.fraudScore !== null ? ipqsData.fraudScore : null;
  let fraudStatus = 'UNKNOWN';
  if (fraudScore !== null) {
    if (fraudScore >= 85) fraudStatus = 'HIGH';
    else if (fraudScore >= 50) fraudStatus = 'MEDIUM';
    else if (fraudScore >= 15) fraudStatus = 'LOW';
    else fraudStatus = 'MINIMAL';
  }

  // Abuse & Threat Indicators
  const abuseConfidence = abuseRes.data?.abuseConfidenceScore ?? 0;
  const abuseReports = abuseRes.data?.totalReports ?? 0;
  const vtMalicious = vtRes.data?.stats?.malicious ?? 0;
  const vtSuspicious = vtRes.data?.stats?.suspicious ?? 0;
  const otxPulses = otxRes.data?.pulseCount ?? 0;

  // Risk Score & Verdict Calculation (extended with new evidence)
  let riskScore = 0;

  if (abuseConfidence > 0) riskScore += Math.min(50, abuseConfidence * 0.5);
  if (abuseReports > 0) riskScore += Math.min(20, abuseReports * 2);
  if (vtMalicious > 0) riskScore += Math.min(40, vtMalicious * 10);
  if (vtSuspicious > 0) riskScore += Math.min(15, vtSuspicious * 5);
  if (otxPulses > 0) riskScore += Math.min(25, otxPulses * 5);
  if (isTor) riskScore += 25;
  if (isVpn || isProxy) riskScore += 10;
  if (isCloud) riskScore += 15;
  if (fraudScore !== null) riskScore += Math.min(30, fraudScore * 0.3);

  riskScore = Math.min(100, Math.round(riskScore));

  let verdict = 'NEUTRAL';
  let reputation = 'NEUTRAL';
  let severity = 'LOW';

  if (riskScore >= 75 || vtMalicious >= 3 || abuseConfidence >= 80 || fraudScore >= 85) {
    verdict = 'SUSPICIOUS';
    reputation = 'POOR';
    severity = 'HIGH';
  } else if (riskScore >= 40 || vtMalicious >= 1 || abuseConfidence >= 25 || otxPulses >= 3 || (fraudScore !== null && fraudScore >= 50)) {
    verdict = 'SUSPICIOUS';
    reputation = 'NEUTRAL';
    severity = 'MEDIUM';
  } else if (riskScore < 15 && vtMalicious === 0 && abuseConfidence === 0 && (fraudScore === null || fraudScore < 15)) {
    verdict = 'CLEAN';
    reputation = 'GOOD';
    severity = 'LOW';
  }

  // Confidence Calculation (evidence-driven)
  const successfulProviders = providers.filter(p => p.status === 'SUCCESS').length;
  let confidence = 'LOW';
  if (successfulProviders >= 5) confidence = 'HIGH';
  else if (successfulProviders >= 3) confidence = 'MEDIUM';

  // Build anonymization evidence object
  const anonymization = {
    vpn: { status: vpnStatus, confidence: vpnConfidence, sources: vpnSources },
    proxy: { status: proxyStatus, confidence: proxyConfidence, sources: proxySources },
    tor: { status: torStatus, confidence: torConfidence, sources: torSources },
    tunneling: { status: anonymizationStatus, confidence: anonymizationConfidence },
    hosting: { status: hostingStatus },
  };

  // Fraud object
  const fraud = {
    score: fraudScore,
    status: fraudStatus,
    indicators: [
      ...(ipqsData.proxy ? ['Proxy detected'] : []),
      ...(ipqsData.vpn ? ['VPN detected'] : []),
      ...(ipqsData.tor ? ['Tor detected'] : []),
      ...(ipqsData.bot ? ['Bot detected'] : []),
      ...(ipqsData.recentAbuse ? ['Recent abuse'] : []),
      ...(ipqsData.crawler ? ['Crawler detected'] : []),
      ...(ipqsData.abuseVelocity ? [`Abuse velocity: ${ipqsData.abuseVelocity}`] : []),
    ],
  };

  // Reputation object
  const reputationObj = {
    riskScore,
    reputation,
    confidence,
  };

  // Build normalized data for AI assessment
  const normalizedData = {
    target: { type: 'ip', value: rawIp },
    identity: {
      ip: rawIp,
      hostname: dnsRes.data?.hostnames?.[0] || '',
      asn,
      organization: asnName,
      isp,
    },
    location: { country, region, city, timezone: ipInfoData.timezone || '' },
    anonymization,
    fraud,
    reputation: reputationObj,
    providers: {
      abuseIpDb: abuseRes.data,
      virusTotal: vtRes.data,
      otx: otxRes.data,
      ipWho: ipWhoRes.data,
      ipInfo: ipInfoRes.data,
      ipqs: ipqsRes.data,
      proxyCheck: proxyCheckRes.data,
    },
    evidence: [],
    analyzedAt: new Date().toISOString(),
  };

  // Fetch AI assessment
  const aiRes = await observeProvider('Llama3 (Groq)', () => fetchLlama3Assessment(normalizedData));
  providers.push(aiRes);

  // Evidence array
  const evidence = [
    ...(abuseConfidence > 0 ? [`AbuseIPDB abuse confidence score: ${abuseConfidence}% (${abuseReports} total reports)`] : []),
    ...(vtMalicious > 0 ? [`VirusTotal detected by ${vtMalicious} security vendors`] : []),
    ...(otxPulses > 0 ? [`AlienVault OTX associated with ${otxPulses} threat pulses`] : []),
    ...(isTor ? ['IP is a known Tor exit node'] : []),
    ...(isVpn ? [`VPN detected by: ${vpnSources.join(', ')}`] : []),
    ...(isProxy ? [`Proxy detected by: ${proxySources.join(', ')}`] : []),
    ...(isCloud ? ['IP is hosted on cloud/datacenter infrastructure'] : []),
    ...(fraudScore !== null ? [`IPQualityScore fraud score: ${fraudScore} (${fraudStatus})`] : []),
    ...(proxyCheckData.risk ? [`ProxyCheck risk score: ${proxyCheckData.risk}`] : []),
    ...(ipInfoData.privacy?.vpn ? ['IPinfo: VPN indicated'] : []),
    ...(ipInfoData.privacy?.proxy ? ['IPinfo: Proxy indicated'] : []),
    ...(ipInfoData.privacy?.tor ? ['IPinfo: Tor indicated'] : []),
    ...(ipInfoData.privacy?.hosting ? ['IPinfo: Hosting indicated'] : []),
  ];

  const analysisResult = {
    id: id('IP'),
    targetType: 'ip',
    ip: rawIp,
    asn,
    asnName,
    isp,
    hostingProvider,
    country,
    region,
    city,
    latitude,
    longitude,
    isVpn,
    isTor,
    isProxy,
    isCloud,
    isOpenRelay: false,
    reputation,
    firstSeen: abuseRes.data?.lastReportedAt ? abuseRes.data.lastReportedAt.slice(0, 10) : new Date().toISOString().slice(0, 10),
    lastSeen: new Date().toISOString().slice(0, 10),
    abuseReports,
    abuseConfidenceScore: abuseConfidence,
    vtMaliciousDetections: vtMalicious,
    vtSuspiciousDetections: vtSuspicious,
    otxPulseCount: otxPulses,
    hostnames: dnsRes.data?.hostnames || abuseRes.data?.hostnames || [],
    riskScore,
    verdict,
    confidence,
    severity,
    providers: providers.map(p => ({
      name: p.provider,
      status: p.status,
      detail: p.detail || p.error || null,
      data: p.data || null,
    })),
     anonymization,
    fraud,
    reputationInfo: reputationObj,
    aiAssessment: normalizeAiAssessment(aiRes.data),
    evidence,
    disclaimer: 'IP intelligence compiled from active threat feeds, network registries, and fraud intelligence providers.',
    createdAt: new Date().toISOString(),
  };

  getStore().analyses.push({
    id: analysisResult.id,
    type: 'ip',
    result: analysisResult,
    createdAt: analysisResult.createdAt,
    createdBy: user?.id || 'USR-DEMO-001',
  });
  await persistStore();

  return analysisResult;
}

export async function analyzeDomain(input, user) {
  const rawDomain = requiredString(input.domain || input.target, 'domain', 253);
  const domain = safeDomain(rawDomain);
  if (!isValidDomain(domain)) {
    throw Object.assign(new Error(`Invalid domain name format: "${rawDomain}"`), { status: 400 });
  }

  const [vtRes, otxRes, dnsRes] = await Promise.all([
    fetchVirusTotalDomain(domain),
    fetchOtxDomain(domain),
    fetchDnsForDomain(domain),
  ]);

  const providers = [vtRes, otxRes, { provider: 'DNS', status: dnsRes.status, data: dnsRes.data }];

  // DNS Details
  const aRecords = dnsRes.data?.a || [];
  const mxRecords = dnsRes.data?.mx || [];
  const nameservers = dnsRes.data?.ns || [];
  const spfRecord = dnsRes.data?.spfRecord || 'Not found';
  const dmarcRecord = dnsRes.data?.dmarcRecord || 'Not found';

  // Registrar & Dates
  const registrar = vtRes.data?.registrar || 'Not available';
  const creationDate = vtRes.data?.creationDate || '';

  let registeredDaysAgo = 0;
  if (creationDate) {
    const createdMs = new Date(creationDate).getTime();
    const nowMs = Date.now();
    registeredDaysAgo = Math.max(0, Math.floor((nowMs - createdMs) / (1000 * 60 * 60 * 24)));
  }

  // VirusTotal & OTX Stats
  const vtMalicious = vtRes.data?.stats?.malicious ?? 0;
  const vtSuspicious = vtRes.data?.stats?.suspicious ?? 0;
  const otxPulses = otxRes.data?.pulseCount ?? 0;

  let similarityScore = 0;
  let parentDomain = domain.split('.').slice(-2).join('.');

  // Risk Score & Verdict Calculation
  let riskScore = 0;
  if (vtMalicious > 0) riskScore += Math.min(50, vtMalicious * 15);
  if (vtSuspicious > 0) riskScore += Math.min(20, vtSuspicious * 8);
  if (otxPulses > 0) riskScore += Math.min(30, otxPulses * 6);

  if (registeredDaysAgo > 0 && registeredDaysAgo < 30) riskScore += 25;
  else if (registeredDaysAgo > 0 && registeredDaysAgo < 90) riskScore += 10;

  if (spfRecord === 'Not found') riskScore += 10;
  if (dmarcRecord === 'Not found') riskScore += 10;

  riskScore = Math.min(100, Math.round(riskScore));

  let verdict = 'NEUTRAL';
  let ipReputation = 'NEUTRAL';
  let severity = 'LOW';

  if (riskScore >= 70 || vtMalicious >= 2) {
    verdict = 'SUSPICIOUS';
    ipReputation = 'POOR';
    severity = 'HIGH';
  } else if (riskScore >= 35 || vtMalicious >= 1 || otxPulses >= 2) {
    verdict = 'SUSPICIOUS';
    ipReputation = 'NEUTRAL';
    severity = 'MEDIUM';
  } else if (riskScore < 15 && vtMalicious === 0) {
    verdict = 'CLEAN';
    ipReputation = 'GOOD';
    severity = 'LOW';
  }

  const successfulProviders = providers.filter(p => p.status === 'SUCCESS').length;
  let confidence = 'LOW';
  if (successfulProviders >= 3) confidence = 'HIGH';
  else if (successfulProviders >= 2) confidence = 'MEDIUM';

  const relatedDomains = vtRes.data?.tags || [];

  const analysisResult = {
    id: id('DOM'),
    targetType: 'domain',
    domain,
    parentDomain,
    similarityScore,
    registeredDaysAgo,
    registrationDate: creationDate || 'Not available',
    registrar,
    nameservers,
    mxRecords,
    spfRecord,
    dmarcRecord,
    aRecords,
    hostingProvider: aRecords.length > 0 ? `Resolved to ${aRecords.join(', ')}` : 'Hosting provider not available',
    ipReputation,
    firstSeen: creationDate || new Date().toISOString().slice(0, 10),
    lastSeen: new Date().toISOString().slice(0, 10),
    relatedDomains,
    vtMaliciousDetections: vtMalicious,
    vtSuspiciousDetections: vtSuspicious,
    otxPulseCount: otxPulses,
    riskScore,
    verdict,
    confidence,
    severity,
    providers: providers.map(p => ({
      name: p.provider,
      status: p.status,
      detail: p.detail || p.error || null,
      data: p.data || null,
    })),
    evidence: [
      ...(vtMalicious > 0 ? [`VirusTotal detected domain as malicious by ${vtMalicious} vendors`] : []),
      ...(otxPulses > 0 ? [`AlienVault OTX associated with ${otxPulses} threat pulses`] : []),
      ...(registeredDaysAgo > 0 && registeredDaysAgo < 30 ? [`Recently registered domain (${registeredDaysAgo} days ago)`] : []),
      ...(spfRecord === 'Not found' ? ['No SPF record configured in DNS'] : []),
      ...(dmarcRecord === 'Not found' ? ['No DMARC record configured in DNS'] : []),
    ],
    disclaimer: 'Domain intelligence compiled from active DNS resolvers and threat databases.',
    createdAt: new Date().toISOString(),
  };

  getStore().analyses.push({
    id: analysisResult.id,
    type: 'domain',
    result: analysisResult,
    createdAt: analysisResult.createdAt,
    createdBy: user?.id || 'USR-DEMO-001',
  });
  await persistStore();

  return analysisResult;
}
