import { getStore, persistStore } from '../database/store.mjs';
import { id, requiredString, httpError } from '../utils/validation.mjs';

export async function listCases() { return getStore().cases; }

export async function createCase(input, user) {
  const title = requiredString(input.title, 'title', 200); const severity = requiredString(input.severity, 'severity', 30); const description = requiredString(input.description, 'description', 10000); const assignedTo = requiredString(input.assignedTo, 'assignedTo', 200); const now = new Date().toISOString();
  const record = { id: id('CASE'), title, severity, description, assignedTo, status: 'Investigating', createdAt: now, updatedAt: now, relatedEmails: [], relatedCampaign: null, exposureRecords: [], timelineEvents: [{ time: now, actor: user.name, event: 'Case created', type: 'ANALYST' }], notes: [{ author: user.name, time: now, text: description }], tasks: [{ id: 'T1', text: 'Review initial evidence', done: false }, { id: 'T2', text: 'Identify threat vectors', done: false }] };
  getStore().cases.unshift(record); await persistStore(); return record;
}

function findCase(caseId) { const record = getStore().cases.find(item => item.id === caseId); if (!record) throw httpError(404, 'Case not found'); return record; }

export async function addNote(caseId, input, user) { const record = findCase(caseId); const note = { author: user.name, time: new Date().toISOString(), text: requiredString(input.note, 'note', 10000) }; record.notes.push(note); await persistStore(); return { success: true, note }; }
export async function addTask(caseId, input) { const record = findCase(caseId); const task = { id: id('TASK'), text: requiredString(input.task, 'task', 500), done: false }; record.tasks.push(task); await persistStore(); return { success: true, task }; }
export async function addTimeline(caseId, input, user) { const record = findCase(caseId); const event = { time: new Date().toISOString(), actor: user.name, event: requiredString(input.event, 'event', 500), type: requiredString(input.type, 'type', 40) }; record.timelineEvents.push(event); await persistStore(); return { success: true, timelineEvent: event }; }
export async function toggleTask(caseId, taskId, input) { const record = findCase(caseId); const task = record.tasks.find(item => item.id === taskId); if (!task) throw httpError(404, 'Task not found'); task.done = Boolean(input.done); record.updatedAt = new Date().toISOString(); await persistStore(); return { success: true, taskId, done: task.done }; }
