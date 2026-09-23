import { getStore, persistStore } from '../database/store.mjs';
import { id, requiredString } from '../utils/validation.mjs';

export async function listReports() { return getStore().reports; }

export async function createReport(input, user) {
  const caseId = requiredString(input.caseId, 'caseId', 100);
  const sections = Array.isArray(input.sections) ? input.sections.map(section => requiredString(section, 'section', 200)) : [];
  if (!sections.length) throw Object.assign(new Error('sections must contain at least one item'), { status: 400 });
  const report = { id: id('RPT'), caseId, title: `${requiredString(input.reportType, 'reportType', 100)} Report for ${caseId}`, generatedAt: new Date().toISOString(), generatedBy: user.name, status: 'DRAFT', sections: sections.map(section => ({ id: section.toLowerCase().replace(/\s+/g, '-'), title: section, content: `Generated from persisted PhishNet evidence for ${section}.` })), relatedCase: caseId, disclaimer: 'All demonstration data is fictional.' };
  getStore().reports.unshift(report); await persistStore(); return report;
}
