import { id, requiredString, httpError } from '../utils/validation.mjs';
import { recordAudit } from './auditService.mjs';
import { getDynamoClient, getTableName, isDynamoConfigured, dynamoPut, dynamoGet, dynamoUpdate, dynamoDelete, dynamoQueryByIp } from './dynamodbService.mjs';
import { isValidIp } from './infrastructureService.mjs';

const IP_INTEL_TTL_DAYS = 90;

function calculateTtl() {
  return Math.floor(Date.now() / 1000) + (IP_INTEL_TTL_DAYS * 24 * 60 * 60);
}

function validateIpAddress(ip) {
  if (!ip) throw httpError(400, 'IP address is required');
  const trimmed = ip.trim();
  if (!isValidIp(trimmed)) {
    throw httpError(400, `Invalid IP address format: "${trimmed}"`);
  }
  return trimmed;
}

function buildIpIntelligenceRecord(ipAddress, analysisResult, userId) {
  const now = new Date().toISOString();
  return {
    'IPAddress': ipAddress,
    ipAddress,
    // Core analysis data
    analysisId: analysisResult.id,
    targetType: analysisResult.targetType,
    asn: analysisResult.asn,
    asnName: analysisResult.asnName,
    isp: analysisResult.isp,
    hostingProvider: analysisResult.hostingProvider,
    country: analysisResult.country,
    region: analysisResult.region,
    city: analysisResult.city,
    latitude: analysisResult.latitude,
    longitude: analysisResult.longitude,
    isVpn: analysisResult.isVpn,
    isTor: analysisResult.isTor,
    isProxy: analysisResult.isProxy,
    isCloud: analysisResult.isCloud,
    isOpenRelay: analysisResult.isOpenRelay,
    reputation: analysisResult.reputation,
    firstSeen: analysisResult.firstSeen,
    lastSeen: analysisResult.lastSeen,
    abuseReports: analysisResult.abuseReports,
    abuseConfidenceScore: analysisResult.abuseConfidenceScore,
    vtMaliciousDetections: analysisResult.vtMaliciousDetections,
    vtSuspiciousDetections: analysisResult.vtSuspiciousDetections,
    otxPulseCount: analysisResult.otxPulseCount,
    hostnames: analysisResult.hostnames || [],
    riskScore: analysisResult.riskScore,
    verdict: analysisResult.verdict,
    confidence: analysisResult.confidence,
    severity: analysisResult.severity,
    // Provider data
    providers: analysisResult.providers || [],
    anonymization: analysisResult.anonymization || {},
    fraud: analysisResult.fraud || {},
    reputationInfo: analysisResult.reputationInfo || {},
    aiAssessment: analysisResult.aiAssessment || {},
    evidence: analysisResult.evidence || [],
    disclaimer: analysisResult.disclaimer,
    // Viper Trace integration fields
    linkedActorIds: [],
    linkedHandleIds: [],
    linkedPgpIds: [],
    linkedWalletIds: [],
    linkedInfrastructureIds: [],
    linkedEvidenceIds: [],
    linkedInvestigationIds: [],
    // Metadata
    createdAt: now,
    updatedAt: now,
    createdBy: userId || 'USR-DEMO-001',
    ttl: calculateTtl(),
    version: 1,
  };
}

export async function createIpIntelligence(ipAddress, analysisResult, user) {
  const ip = validateIpAddress(ipAddress);
  
  if (!isDynamoConfigured()) {
    throw httpError(503, 'DynamoDB is not configured. Set AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and DYNAMODB_TABLE_NAME.');
  }

  const existing = await dynamoGet(ip);
  if (existing) {
    throw httpError(409, `IP intelligence record for ${ip} already exists`);
  }

  const record = buildIpIntelligenceRecord(ip, analysisResult, user?.id);
  
  await dynamoPut(record);

  recordAudit({
    actor: user?.name || user?.email || 'system',
    action: 'IP_INTEL_CREATE',
    target: ip,
    outcome: 'SUCCESS',
    detail: `Created IP intelligence record for ${ip} (analysis: ${analysisResult.id})`,
  });

  return record;
}

export async function getIpIntelligence(ipAddress) {
  const ip = validateIpAddress(ipAddress);
  
  if (!isDynamoConfigured()) {
    return null;
  }

  return dynamoGet(ip);
}

export async function updateIpIntelligence(ipAddress, updates, user) {
  const ip = validateIpAddress(ipAddress);
  
  if (!isDynamoConfigured()) {
    throw httpError(503, 'DynamoDB is not configured');
  }

  const existing = await dynamoGet(ip);
  if (!existing) {
    throw httpError(404, `IP intelligence record for ${ip} not found`);
  }

  const allowedUpdates = {
    linkedActorIds: updates.linkedActorIds,
    linkedHandleIds: updates.linkedHandleIds,
    linkedPgpIds: updates.linkedPgpIds,
    linkedWalletIds: updates.linkedWalletIds,
    linkedInfrastructureIds: updates.linkedInfrastructureIds,
    linkedEvidenceIds: updates.linkedEvidenceIds,
    linkedInvestigationIds: updates.linkedInvestigationIds,
    notes: updates.notes,
    tags: updates.tags,
    riskScore: updates.riskScore,
    verdict: updates.verdict,
    severity: updates.severity,
    lastSeen: updates.lastSeen,
  };

  const filteredUpdates = Object.fromEntries(
    Object.entries(allowedUpdates).filter(([, value]) => value !== undefined)
  );

  if (Object.keys(filteredUpdates).length === 0) {
    return existing;
  }

  filteredUpdates.version = (existing.version || 0) + 1;

  const updated = await dynamoUpdate(ip, filteredUpdates);

  recordAudit({
    actor: user?.name || user?.email || 'system',
    action: 'IP_INTEL_UPDATE',
    target: ip,
    outcome: 'SUCCESS',
    detail: `Updated IP intelligence record for ${ip}: ${Object.keys(filteredUpdates).join(', ')}`,
  });

  return updated;
}

export async function deleteIpIntelligence(ipAddress, user) {
  const ip = validateIpAddress(ipAddress);
  
  if (!isDynamoConfigured()) {
    throw httpError(503, 'DynamoDB is not configured');
  }

  const existing = await dynamoGet(ip);
  if (!existing) {
    throw httpError(404, `IP intelligence record for ${ip} not found`);
  }

  await dynamoDelete(ip);

  recordAudit({
    actor: user?.name || user?.email || 'system',
    action: 'IP_INTEL_DELETE',
    target: ip,
    outcome: 'SUCCESS',
    detail: `Deleted IP intelligence record for ${ip}`,
  });

  return { success: true, ipAddress: ip };
}

export async function queryIpIntelligence(ipAddress) {
  const ip = validateIpAddress(ipAddress);
  
  if (!isDynamoConfigured()) {
    return [];
  }

  return dynamoQueryByIp(ip);
}

export async function linkActorToIp(ipAddress, actorId, user) {
  const record = await getIpIntelligence(ipAddress);
  if (!record) {
    throw httpError(404, `IP intelligence record for ${ipAddress} not found`);
  }

  const linkedActorIds = Array.isArray(record.linkedActorIds) ? [...record.linkedActorIds] : [];
  if (!linkedActorIds.includes(actorId)) {
    linkedActorIds.push(actorId);
    return updateIpIntelligence(ipAddress, { linkedActorIds }, user);
  }
  return record;
}

export async function linkHandleToIp(ipAddress, handleId, user) {
  const record = await getIpIntelligence(ipAddress);
  if (!record) {
    throw httpError(404, `IP intelligence record for ${ipAddress} not found`);
  }

  const linkedHandleIds = Array.isArray(record.linkedHandleIds) ? [...record.linkedHandleIds] : [];
  if (!linkedHandleIds.includes(handleId)) {
    linkedHandleIds.push(handleId);
    return updateIpIntelligence(ipAddress, { linkedHandleIds }, user);
  }
  return record;
}

export async function linkPgpToIp(ipAddress, pgpId, user) {
  const record = await getIpIntelligence(ipAddress);
  if (!record) {
    throw httpError(404, `IP intelligence record for ${ipAddress} not found`);
  }

  const linkedPgpIds = Array.isArray(record.linkedPgpIds) ? [...record.linkedPgpIds] : [];
  if (!linkedPgpIds.includes(pgpId)) {
    linkedPgpIds.push(pgpId);
    return updateIpIntelligence(ipAddress, { linkedPgpIds }, user);
  }
  return record;
}

export async function linkWalletToIp(ipAddress, walletId, user) {
  const record = await getIpIntelligence(ipAddress);
  if (!record) {
    throw httpError(404, `IP intelligence record for ${ipAddress} not found`);
  }

  const linkedWalletIds = Array.isArray(record.linkedWalletIds) ? [...record.linkedWalletIds] : [];
  if (!linkedWalletIds.includes(walletId)) {
    linkedWalletIds.push(walletId);
    return updateIpIntelligence(ipAddress, { linkedWalletIds }, user);
  }
  return record;
}

export async function linkInfrastructureToIp(ipAddress, infrastructureId, user) {
  const record = await getIpIntelligence(ipAddress);
  if (!record) {
    throw httpError(404, `IP intelligence record for ${ipAddress} not found`);
  }

  const linkedInfrastructureIds = Array.isArray(record.linkedInfrastructureIds) ? [...record.linkedInfrastructureIds] : [];
  if (!linkedInfrastructureIds.includes(infrastructureId)) {
    linkedInfrastructureIds.push(infrastructureId);
    return updateIpIntelligence(ipAddress, { linkedInfrastructureIds }, user);
  }
  return record;
}

export async function linkEvidenceToIp(ipAddress, evidenceId, user) {
  const record = await getIpIntelligence(ipAddress);
  if (!record) {
    throw httpError(404, `IP intelligence record for ${ipAddress} not found`);
  }

  const linkedEvidenceIds = Array.isArray(record.linkedEvidenceIds) ? [...record.linkedEvidenceIds] : [];
  if (!linkedEvidenceIds.includes(evidenceId)) {
    linkedEvidenceIds.push(evidenceId);
    return updateIpIntelligence(ipAddress, { linkedEvidenceIds }, user);
  }
  return record;
}

export async function linkInvestigationToIp(ipAddress, investigationId, user) {
  const record = await getIpIntelligence(ipAddress);
  if (!record) {
    throw httpError(404, `IP intelligence record for ${ipAddress} not found`);
  }

  const linkedInvestigationIds = Array.isArray(record.linkedInvestigationIds) ? [...record.linkedInvestigationIds] : [];
  if (!linkedInvestigationIds.includes(investigationId)) {
    linkedInvestigationIds.push(investigationId);
    return updateIpIntelligence(ipAddress, { linkedInvestigationIds }, user);
  }
  return record;
}

export async function getIpRelatedIntelligence(ipAddress) {
  const record = await getIpIntelligence(ipAddress);
  if (!record) {
    return {
      ipAddress,
      found: false,
      actors: [],
      handles: [],
      pgpKeys: [],
      wallets: [],
      infrastructure: [],
      evidence: [],
      investigations: [],
    };
  }

  return {
    ipAddress,
    found: true,
    record,
    actors: record.linkedActorIds || [],
    handles: record.linkedHandleIds || [],
    pgpKeys: record.linkedPgpIds || [],
    wallets: record.linkedWalletIds || [],
    infrastructure: record.linkedInfrastructureIds || [],
    evidence: record.linkedEvidenceIds || [],
    investigations: record.linkedInvestigationIds || [],
  };
}

export function isIpIntelligenceEnabled() {
  return isDynamoConfigured();
}