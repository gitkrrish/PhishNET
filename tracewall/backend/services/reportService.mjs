import { getStore, persistStore } from '../database/store.mjs';
import { id, requiredString, httpError } from '../utils/validation.mjs';
import { recordAudit } from './auditService.mjs';

export async function listReports() { return getStore().reports; }

export async function getReport(reportId) {
  const report = getStore().reports.find(item => item.id === reportId);
  if (!report) throw httpError(404, 'Report not found');
  return report;
}

/**
 * Compose one report section from the records that actually exist.
 *
 * Sections are built from the stored case, its evidence-linked analyses and
 * its timeline rather than from filler text, so a report is a view over real
 * backend data. A section with nothing behind it says so instead of inventing
 * findings.
 */
function buildSection(title, caseRecord, store) {
  const key = title.toLowerCase();
  const lines = [];

  const caseAnalyses = (store.analyses || []).filter(analysis =>
    (caseRecord.relatedEmails || []).includes(analysis.id) ||
    (caseRecord.relatedCampaign && analysis.id === caseRecord.relatedCampaign) ||
    JSON.stringify(analysis.input || analysis.subject || '').includes(caseRecord.id));

  if (key.includes('executive') || key.includes('summary')) {
    lines.push(`Case ${caseRecord.id}: ${caseRecord.title}`);
    lines.push(`Severity ${caseRecord.severity}, status ${caseRecord.status}, assigned to ${caseRecord.assignedTo}.`);
    lines.push(`Opened ${caseRecord.createdAt}.`);
    lines.push(`${(caseRecord.notes || []).length} analyst note(s), ${(caseRecord.tasks || []).length} task(s), ${(caseRecord.timelineEvents || []).length} timeline event(s).`);
  } else if (key.includes('evidence')) {
    lines.push(`${(caseRecord.exposureRecords || []).length} exposure record(s) attached to this case.`);
    for (const record of caseRecord.exposureRecords || []) {
      lines.push(`- ${record.subject || record.email || 'record'}: ${record.status || 'unknown'} (${record.source || 'source not recorded'})`);
    }
    if (!lines.length) lines.push('No evidence records are attached to this case.');
  } else if (key.includes('analysis')) {
    lines.push(`${caseAnalyses.length} stored analysis result(s) reference this case.`);
    for (const analysis of caseAnalyses.slice(0, 25)) {
      lines.push(`- ${analysis.id} (${analysis.type}): verdict ${analysis.result?.verdict ?? analysis.result?.status ?? 'n/a'}`);
    }
    if (!caseAnalyses.length) lines.push('No stored analyses reference this case.');
  } else if (key.includes('timeline') || key.includes('chronolog')) {
    for (const event of [...(caseRecord.timelineEvents || [])].sort((a, b) => String(a.time).localeCompare(String(b.time)))) {
      lines.push(`- ${event.time} · ${event.actor} · ${event.event} [${event.type}]`);
    }
    if (!lines.length) lines.push('No timeline events recorded for this case.');
  } else if (key.includes('remedi') || key.includes('recommend')) {
    const open = (caseRecord.tasks || []).filter(task => !task.done);
    lines.push(open.length ? `${open.length} open task(s):` : 'No open tasks remain.');
    for (const task of open) lines.push(`- ${task.id}: ${task.text}`);
    lines.push(`Assigned to ${caseRecord.assignedTo}.`);
  } else {
    lines.push(`Case ${caseRecord.id} · ${caseRecord.title}`);
    lines.push(caseRecord.description);
  }

  return {
    id: key.replace(/\s+/g, '-'),
    title,
    content: lines.join('\n'),
  };
}

export async function createReport(input, user) {
  const caseId = requiredString(input.caseId, 'caseId', 100);
  const sections = Array.isArray(input.sections) ? input.sections.map(section => requiredString(section, 'section', 200)) : [];
  if (!sections.length) throw httpError(400, 'sections must contain at least one item');

  const store = getStore();
  const caseRecord = store.cases.find(item => item.id === caseId);
  if (!caseRecord) throw httpError(404, 'Case not found');

  const report = {
    id: id('RPT'),
    caseId,
    title: `${requiredString(input.reportType, 'reportType', 100)} Report for ${caseId}`,
    generatedAt: new Date().toISOString(),
    generatedBy: user?.name || user?.email || 'analyst',
    status: 'DRAFT',
    redactionLevel: input.redactionLevel || 'STANDARD',
    sections: sections.map(section => buildSection(section, caseRecord, store)),
    relatedCase: caseId,
    disclaimer: 'Content is generated from the records persisted for this case. Demonstration data is fictional.',
  };
  store.reports.unshift(report);
  await persistStore();
  recordAudit({ actor: report.generatedBy, action: 'REPORT_GENERATED', target: report.id, detail: sections.join(', ') });
  return report;
}