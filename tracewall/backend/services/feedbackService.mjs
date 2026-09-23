import { getStore, persistStore } from '../database/store.mjs';
import { id, requiredString, httpError } from '../utils/validation.mjs';
import { sanitizeSubmission, escapeHtml } from '../utils/sanitizer.mjs';

// Valid moderation states (mirrors the data model in the spec).
const MODERATION_STATUSES = new Set(['PENDING', 'APPROVED', 'REJECTED', 'FLAGGED', 'PRIVATE']);

function ensureStore() {
  const store = getStore();
  if (!Array.isArray(store.feedback)) store.feedback = [];
  if (!Array.isArray(store.feedbackModLog)) store.feedbackModLog = [];
  return store;
}

const FEEDBACK_CATEGORIES = [
  'Cybercrime Incident', 'Phishing', 'Scam/Fraud', 'Malware', 'Ransomware',
  'Account Compromise', 'Social Engineering', 'Suspicious Email', 'Suspicious Domain',
  'Suspicious IP', 'Vulnerability/Weakness', 'Security Solution', 'Prevention Tip',
  'General Security Experience', 'Other',
];

// Max lengths guard against oversized / abusive submissions.
const FIELD_LIMITS = {
  title: 160,
  category: 60,
  description: 8000,
  whatHappened: 12000,
  impact: 4000,
  solution: 4000,
  prevention: 4000,
  indicators: 4000,
  technicalIndicators: 2000,
  moderationNote: 4000,
};

function optString(value, field) {
  const max = FIELD_LIMITS[field] || 4000;
  if (value === null || value === undefined) return '';
  if (typeof value !== 'string') throw httpError(400, `${field} must be a string`);
  if (value.length > max) throw httpError(400, `${field} is too long (max ${max} chars)`);
  return value.trim();
}

function normalizeInput(input) {
  if (!input || typeof input !== 'object') throw httpError(400, 'Invalid feedback payload');

  const category = optString(input.category, 'category') || 'Other';
  if (!FEEDBACK_CATEGORIES.includes(category)) {
    throw httpError(400, `Invalid category: ${category}`);
  }

  return {
    title: requiredString(input.title, 'title', FIELD_LIMITS.title),
    category,
    description: optString(input.description, 'description'),
    whatHappened: optString(input.whatHappened, 'whatHappened'),
    indicators: Array.isArray(input.indicators) ? input.indicators.map(i => String(i)) : [],
    impact: optString(input.impact, 'impact'),
    solution: optString(input.solution, 'solution'),
    prevention: optString(input.prevention, 'prevention'),
    technicalIndicators: Array.isArray(input.technicalIndicators) ? input.technicalIndicators.map(i => String(i)) : [],
    involvesCybercrime: Boolean(input.involvesCybercrime),
    isPublicSafe: Boolean(input.isPublicSafe === undefined ? false : input.isPublicSafe),
  };
}

export async function listFeedback(query = {}) {
  const store = ensureStore();
  const items = store.feedback;
  return filterFeedback(items, query);
}

function filterFeedback(items, query) {
  let result = items;
  if (query.status) result = result.filter(item => item.moderationStatus === query.status);
  if (query.category) result = result.filter(item => item.category === query.category);
  if (query.submittedBy) result = result.filter(item => item.submittedBy === query.submittedBy);
  if (query.q) {
    const needle = String(query.q).toLowerCase();
    result = result.filter(item =>
      (item.title || '').toLowerCase().includes(needle) ||
      (item.category || '').toLowerCase().includes(needle) ||
      (item.description || '').toLowerCase().includes(needle) ||
      (item.whatHappened || '').toLowerCase().includes(needle) ||
      (item.solution || '').toLowerCase().includes(needle) ||
      (item.prevention || '').toLowerCase().includes(needle) ||
      (item.indicators || []).some(i => String(i).toLowerCase().includes(needle))
    );
  }
  return result.slice().sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function searchFeedback(query = {}) {
  // Public search surface — only approved, anonymized knowledge is exposed.
  const store = ensureStore();
  const approved = store.feedback.filter(
    item => item.moderationStatus === 'APPROVED' && item.anonymized === true
  );
  return filterFeedback(approved, query);
}

export async function getFeedback(idParam) {
  const store = ensureStore();
  const record = store.feedback.find(item => item.id === idParam);
  if (!record) throw httpError(404, 'Feedback not found');
  return record;
}

export async function createFeedback(input, user) {
  const store = ensureStore();
  const normalized = normalizeInput(input);

  // 1. Input sanitization + sensitive-information detection (privacy protection)
  const { sanitized, redactionReport } = sanitizeSubmission(normalized);

  const now = new Date().toISOString();

  const record = {
    id: id('FEEDBACK'),
    title: sanitized.title,
    category: sanitized.category,
    description: sanitized.description,
    whatHappened: sanitized.whatHappened,
    indicators: sanitized.indicators,
    impact: sanitized.impact,
    solution: sanitized.solution,
    prevention: sanitized.prevention,
    technicalIndicators: sanitized.technicalIndicators,
    involvesCybercrime: sanitized.involvesCybercrime,
    status: 'PENDING',
    moderationStatus: 'PENDING',
    knowledgeStatus: 'NONE',
    anonymized: false,
    redactionReport,
    submittedBy: user.id,
    submittedByName: user.name,
    moderatorNotes: [],
    createdAt: now,
    updatedAt: now,
  };

  store.feedback.unshift(record);
  await persistStore();

  return record;
}

// Build an anonymized, consumer-safe "knowledge view" used by the AI
// retrieval layer. Strips submitter identity and any non-public fields.
function buildKnowledgeView(record) {
  return {
    id: record.id,
    category: record.category,
    title: escapeHtml(record.title),
    description: escapeHtml(record.description),
    whatHappened: escapeHtml(record.whatHappened),
    indicators: record.indicators,
    impact: escapeHtml(record.impact),
    solution: escapeHtml(record.solution),
    prevention: escapeHtml(record.prevention),
    involvesCybercrime: record.involvesCybercrime,
    createdAt: record.createdAt,
  };
}

export async function moderateFeedback(idParam, input, user) {
  const store = ensureStore();
  const record = store.feedback.find(item => item.id === idParam);
  if (!record) throw httpError(404, 'Feedback not found');

  const status = requiredString(input.status || input.moderationStatus, 'status', 20);
  if (!MODERATION_STATUSES.has(status)) throw httpError(400, `Invalid moderation status: ${status}`);
  const note = optString(input.note, 'moderationNote');

  const previousStatus = record.moderationStatus;
  record.moderationStatus = status;
  record.updatedAt = new Date().toISOString();

  if (note) {
    record.moderatorNotes.push({
      time: new Date().toISOString(),
      actor: user.name,
      from: previousStatus,
      to: status,
      note,
    });
  }

  // Approved feedback is fully anonymized before it can become knowledge:
  // submitter identity is dropped and only the sanitized (redacted) text
  // is ever exposed to other users or the AI.
  if (status === 'APPROVED') {
    record.anonymized = true;
    record.knowledgeView = buildKnowledgeView(record);
    record.knowledgeStatus = 'INDEXED';
  } else if (status === 'REJECTED' || status === 'PRIVATE') {
    record.knowledgeStatus = 'NONE';
    record.knowledgeView = null;
  } else {
    record.knowledgeStatus = record.knowledgeStatus || 'NONE';
  }

  store.feedbackModLog.unshift({
    id: id('MODLOG'),
    feedbackId: record.id,
    time: new Date().toISOString(),
    moderator: user.name,
    from: previousStatus,
    to: status,
    note,
  });

  await persistStore();
  return record;
}

export async function flagFeedback(idParam, user) {
  return moderateFeedback(idParam, { status: 'FLAGGED', note: 'Flagged by community' }, user);
}

// Internal knowledge retrieval surface. Returns only approved, anonymized,
// redacted knowledge. The AI consumes this as retrieved context (DATA), never
// as instructions, and never from PENDING/REJECTED submissions.
export async function getKnowledge(query = {}) {
  const store = ensureStore();
  const approved = store.feedback.filter(
    item => item.moderationStatus === 'APPROVED' && item.anonymized === true && item.knowledgeStatus === 'INDEXED'
  );
  let result = approved.map(item => ({
    id: item.id,
    category: item.category,
    knowledge: item.knowledgeView || buildKnowledgeView(item),
  }));

  if (query.q) {
    const needle = String(query.q).toLowerCase();
    result = result.filter(entry => {
      const k = entry.knowledge;
      return (k.title || '').toLowerCase().includes(needle) ||
        (k.category || '').toLowerCase().includes(needle) ||
        (k.description || '').toLowerCase().includes(needle) ||
        (k.whatHappened || '').toLowerCase().includes(needle) ||
        (k.indicators || []).some(i => String(i).toLowerCase().includes(needle)) ||
        (k.solution || '').toLowerCase().includes(needle) ||
        (k.prevention || '').toLowerCase().includes(needle);
    });
  }
  if (query.category) {
    result = result.filter(entry => entry.category === query.category);
  }
  return result.slice().sort((a, b) => b.knowledge.createdAt.localeCompare(a.knowledge.createdAt));
}

export { FEEDBACK_CATEGORIES, MODERATION_STATUSES };
