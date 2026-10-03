import { getStore, persistStore } from '../database/store.mjs';
import { id, requiredString, httpError } from '../utils/validation.mjs';
import { recordAudit } from './auditService.mjs';

const who = user => user?.name || user?.email || 'analyst';

export async function listCases() { return getStore().cases; }

export async function getCase(caseId) { return findCase(caseId); }

export async function createCase(input, user) {
  const title = requiredString(input.title, 'title', 200); const severity = requiredString(input.severity, 'severity', 30); const description = requiredString(input.description, 'description', 10000); const assignedTo = requiredString(input.assignedTo, 'assignedTo', 200); const now = new Date().toISOString();
  const record = { id: id('CASE'), title, severity, description, assignedTo, status: 'Investigating', createdAt: now, updatedAt: now, relatedEmails: [], relatedCampaign: null, exposureRecords: [], timelineEvents: [{ time: now, actor: who(user), event: 'Case created', type: 'ANALYST' }], notes: [{ author: who(user), time: now, text: description }], tasks: [{ id: 'T1', text: 'Review initial evidence', done: false }, { id: 'T2', text: 'Identify threat vectors', done: false }] };
  getStore().cases.unshift(record); await persistStore();
  recordAudit({ actor: who(user), action: 'CASE_CREATED', target: record.id, detail: `${severity} · ${assignedTo}` });
  return record;
}

function findCase(caseId) { const record = getStore().cases.find(item => item.id === caseId); if (!record) throw httpError(404, 'Case not found'); return record; }

export async function addNote(caseId, input, user) {
  const record = findCase(caseId);
  const note = { author: who(user), time: new Date().toISOString(), text: requiredString(input.note, 'note', 10000) };
  record.notes.push(note); record.updatedAt = note.time;
  await persistStore();
  recordAudit({ actor: who(user), action: 'CASE_NOTE_ADDED', target: caseId });
  return { success: true, note };
}

export async function addTask(caseId, input, user) {
  const record = findCase(caseId);
  const task = { id: id('TASK'), text: requiredString(input.task, 'task', 500), done: false };
  record.tasks.push(task); record.updatedAt = new Date().toISOString();
  await persistStore();
  recordAudit({ actor: who(user), action: 'CASE_TASK_ADDED', target: caseId });
  return { success: true, task };
}

export async function addTimeline(caseId, input, user) {
  const record = findCase(caseId);
  const event = { time: new Date().toISOString(), actor: who(user), event: requiredString(input.event, 'event', 500), type: requiredString(input.type, 'type', 40) };
  record.timelineEvents.push(event); record.updatedAt = event.time;
  await persistStore();
  recordAudit({ actor: who(user), action: 'CASE_TIMELINE_ADDED', target: caseId, detail: event.type });
  return { success: true, timelineEvent: event };
}

export async function toggleTask(caseId, taskId, input, user) {
  const record = findCase(caseId);
  const task = record.tasks.find(item => item.id === taskId);
  if (!task) throw httpError(404, 'Task not found');
  task.done = Boolean(input.done); record.updatedAt = new Date().toISOString();
  await persistStore();
  recordAudit({ actor: who(user), action: 'CASE_TASK_UPDATED', target: caseId, detail: `${taskId}=${task.done}` });
  return { success: true, taskId, done: task.done };
}