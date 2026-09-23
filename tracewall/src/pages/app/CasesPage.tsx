import { useState, useEffect, useMemo } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { cases, investigations, additionalCases, asteronCases, currentAnalyst } from '../../data/mockData';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { EvidenceStamp } from '../../components/ui/EvidenceStamp';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { CheckCircle, Circle, FileText, Shield, Users, Link2, FileCheck, Plus, X } from 'lucide-react';
import { tv, statusColor, hoverHandlers } from '../../lib/styles';
import clsx from 'clsx';
import { motion, AnimatePresence } from 'framer-motion';
import { createCase, addCaseNote, addCaseTask, toggleCaseTask, addTimelineEvent, createAuditEvent } from '../../lib/mockBackend';
import ThreatEvidenceNetwork from '../../components/3d/ThreatEvidenceNetwork';

function TimelineEvent({ event }: { event: any }) {
  const colors: Record<string, string> = {
    SYSTEM:   'var(--tw-dust)',
    ANALYST:  'var(--tw-burgundy)',
    EVIDENCE: 'var(--tw-brass)',
    DECISION: 'var(--tw-moss)',
  };
  const dot = colors[event.type] || colors.SYSTEM;
  const d = new Date(event.time);
  return (
    <div className="flex gap-4">
      <div className="flex flex-col items-center shrink-0">
        <div className="w-2 h-2 rounded-full mt-1" style={{ backgroundColor: dot }} />
        <div className="w-px flex-1 mt-1" style={{ backgroundColor: 'var(--tw-border-mid)' }} />
      </div>
      <div className="pb-5">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="font-mono text-[9px] uppercase tracking-widest px-1.5 py-0.5 rounded-sm"
            style={{ color: dot, backgroundColor: `color-mix(in srgb, ${dot} 18%, transparent)` }}
          >
            {event.type}
          </span>
          <span className="font-mono text-[10px]" style={tv.faint}>
            {d.toLocaleDateString()} {d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </span>
        </div>
        <p className="text-sm" style={tv.text}>{event.event}</p>
        <p className="font-mono text-[10px]" style={tv.muted}>{event.actor}</p>
      </div>
    </div>
  );
}

function CampaignLink({ campaignId }: { campaignId?: string | null }) {
  if (!campaignId) return null;
  return (
    <Link to="/app/campaigns" className="font-mono text-[10px] hover:underline" style={tv.low}>
      {campaignId}
    </Link>
  );
}

function ExposureLinks({ records }: { records?: string[] }) {
  if (!records || records.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {records.map(id => (
        <Link key={id} to="/app/exposure" className="font-mono text-[10px] px-2 py-0.5 rounded-sm border"
          style={{
            color: 'var(--tw-medium)',
            borderColor: 'color-mix(in srgb, var(--tw-medium) 35%, transparent)',
            backgroundColor: 'color-mix(in srgb, var(--tw-medium) 10%, transparent)',
          }}
          {...hoverHandlers()}
        >
          {id}
        </Link>
      ))}
    </div>
  );
}

function EmailChips({ ids }: { ids?: string[] }) {
  if (!ids || ids.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {ids.map(id => (
        <Link key={id} to="/app/evidence" className="font-mono text-[10px] px-2 py-0.5 rounded-sm border"
          style={{
            color: 'var(--tw-info)',
            borderColor: 'color-mix(in srgb, var(--tw-info) 35%, transparent)',
            backgroundColor: 'color-mix(in srgb, var(--tw-info) 10%, transparent)',
          }}
          {...hoverHandlers()}
        >
          {id}
        </Link>
      ))}
    </div>
  );
}

function CaseDetail({ caseData, onUpdate }: { caseData: any; onUpdate?: (updated: any) => void }) {
  const [activeTab, setActiveTab] = useState('timeline');
  const [newNote, setNewNote] = useState('');
  const [newTask, setNewTask] = useState('');
  const [addingNote, setAddingNote] = useState(false);
  const [addingTask, setAddingTask] = useState(false);
  const [timelineInput, setTimelineInput] = useState('');
  const [timelineType, setTimelineType] = useState<'ANALYST' | 'EVIDENCE' | 'DECISION'>('ANALYST');
  const [addingTimeline, setAddingTimeline] = useState(false);
  const tabs = ['timeline', 'tasks', 'notes', 'evidence'];

  return (
    <div className="space-y-5">
      <div className="rounded-sm p-5 space-y-4" style={tv.panelBorder}>
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <p className="font-mono text-[10px]" style={tv.muted}>{caseData.id}</p>
            <h2 className="font-serif text-xl" style={tv.text}>{caseData.title}</h2>
          </div>
          <EvidenceStamp
            verdict={(['CRITICAL'] as string[]).includes(caseData.severity) ? 'CRITICAL' : caseData.severity === 'HIGH' ? 'HIGH RISK' : 'REVIEW'}
            size="sm"
          />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Status',     val: caseData.status },
            { label: 'Assigned To', val: caseData.assignedTo },
            { label: 'Created',    val: new Date(caseData.createdAt).toLocaleDateString() },
            { label: 'Updated',    val: new Date(caseData.updatedAt).toLocaleDateString() },
          ].map(row => (
            <div key={row.label}>
              <p className="font-mono text-[10px] uppercase tracking-wider mb-0.5" style={tv.muted}>{row.label}</p>
              {row.label === 'Status' ? (
                <span className="font-mono text-xs px-2 py-0.5 rounded-sm border inline-block"
                  style={{
                    color: statusColor(row.val),
                    borderColor: `color-mix(in srgb, ${statusColor(row.val)} 35%, transparent)`,
                    backgroundColor: `color-mix(in srgb, ${statusColor(row.val)} 10%, transparent)`,
                  }}
                >
                  {row.val}
                </span>
              ) : (
                <p className="font-mono text-xs" style={tv.text}>{row.val}</p>
              )}
            </div>
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>
              <Link2 size={10} className="inline mr-1" />Related Emails
            </p>
            <EmailChips ids={caseData.relatedEmails} />
          </div>
          <div>
            <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>
              <Link2 size={10} className="inline mr-1" />Campaign
            </p>
            <CampaignLink campaignId={caseData.relatedCampaign} />
          </div>
          <div>
            <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>
              <Shield size={10} className="inline mr-1" />Dark-Web Findings
            </p>
            <ExposureLinks records={caseData.exposureRecords} />
          </div>
        </div>

        {/* Threat Evidence Network */}
        <ThreatEvidenceNetwork pageType="cases" />

        <div className="pt-2 flex items-center gap-2">
          <Users size={11} style={tv.muted} />
          <span className="font-mono text-[10px]" style={tv.muted}>Reviewer: {caseData.assignedTo}</span>
          <span style={tv.faint}>·</span>
          <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm border"
            style={{
              color: statusColor(caseData.status),
              borderColor: `color-mix(in srgb, ${statusColor(caseData.status)} 35%, transparent)`,
              backgroundColor: `color-mix(in srgb, ${statusColor(caseData.status)} 10%, transparent)`,
            }}
          >
            {(caseData.status === 'Contained' || caseData.status === 'Awaiting Remediation') ? 'Approved' : 'Pending Review'}
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b gap-0" style={{ borderColor: 'var(--tw-border-mid)' }}>
        {tabs.map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className="font-mono text-xs capitalize px-4 py-2.5 border-b-2 transition-colors"
            style={{
              borderBottomColor: activeTab === tab ? 'var(--tw-burgundy)' : 'transparent',
              color: activeTab === tab ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
            }}
          >
            {tab}
          </button>
        ))}
      </div>

      {activeTab === 'timeline' && (
        <div className="rounded-sm p-5" style={tv.panelBorder}>
          {caseData.timelineEvents.length === 0 ? (
            <p className="font-mono text-xs" style={tv.muted}>No timeline events recorded.</p>
          ) : (
            caseData.timelineEvents.map((event: any, i: number) => <TimelineEvent key={i} event={event} />)
          )}
          <div className="mt-4 pt-4 border-t space-y-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
            <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Add Timeline Event</p>
            <div className="flex gap-2">
              <select
                value={timelineType}
                onChange={e => setTimelineType(e.target.value as 'ANALYST' | 'EVIDENCE' | 'DECISION')}
                className="font-mono text-xs px-3 py-2 rounded-sm border focus:outline-none"
                style={tv.input}
              >
                <option value="ANALYST">Analyst Action</option>
                <option value="EVIDENCE">Evidence Added</option>
                <option value="DECISION">Decision Made</option>
              </select>
              <input
                type="text"
                value={timelineInput}
                onChange={e => setTimelineInput(e.target.value)}
                placeholder="Event description…"
                className="flex-1 font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40"
                style={tv.input}
              />
              <button
                onClick={async () => {
                  if (!timelineInput.trim()) return;
                  setAddingTimeline(true);
                  try {
                    const result = await addTimelineEvent(caseData.id, timelineInput, timelineType);
                    if (result.success && onUpdate) {
                      onUpdate({
                        ...caseData,
                        timelineEvents: [...caseData.timelineEvents, result.timelineEvent],
                      });
                    }
                    setTimelineInput('');
                    await createAuditEvent('Timeline Event Added', caseData.id, 'SUCCESS');
                  } catch (error) {
                    console.error('Failed to add timeline event:', error);
                  } finally {
                    setAddingTimeline(false);
                  }
                }}
                disabled={addingTimeline || !timelineInput.trim()}
                className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm disabled:opacity-40"
                style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
              >
                {addingTimeline ? 'Adding…' : 'Add'}
              </button>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'tasks' && (
        <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
          {caseData.tasks.length === 0 ? (
            <div className="p-6 text-center"><p className="font-mono text-xs" style={tv.muted}>No tasks assigned.</p></div>
          ) : (
            caseData.tasks.map((task: any) => (
              <div key={task.id} className="flex items-center gap-3 px-5 py-3 border-b last:border-0"
                style={{ borderColor: 'var(--tw-border-mid)' }}
              >
                <button 
                  onClick={async () => {
                    try {
                      const result = await toggleCaseTask(caseData.id, task.id);
                      if (result.success && onUpdate) {
                        onUpdate({
                          ...caseData,
                          tasks: caseData.tasks.map((t: any) => 
                            t.id === task.id ? { ...t, done: result.done } : t
                          ),
                        });
                      }
                      await createAuditEvent('Task Toggled', caseData.id, 'SUCCESS');
                    } catch (error) {
                      console.error('Failed to toggle task:', error);
                    }
                  }}
                  className="shrink-0"
                >
                  {task.done
                    ? <CheckCircle size={14} style={tv.low} />
                    : <Circle size={14} style={tv.faint} />
                  }
                </button>
                <p className={clsx('text-sm', task.done && 'line-through')}
                  style={{ color: task.done ? 'var(--tw-text-faint)' : 'var(--tw-text)' }}
                >
                  {task.text}
                </p>
              </div>
            ))
          )}
          <div className="p-4 space-y-2 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
            <div className="flex gap-2">
              <input
                type="text"
                value={newTask}
                onChange={e => setNewTask(e.target.value)}
                placeholder="Add new task…"
                className="flex-1 font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40"
                style={tv.input}
              />
              <button
                onClick={async () => {
                  if (!newTask.trim()) return;
                  setAddingTask(true);
                  try {
                    const result = await addCaseTask(caseData.id, newTask);
                    if (result.success && onUpdate) {
                      onUpdate({
                        ...caseData,
                        tasks: [...caseData.tasks, result.task],
                      });
                    }
                    setNewTask('');
                    await createAuditEvent('Task Added', caseData.id, 'SUCCESS');
                  } catch (error) {
                    console.error('Failed to add task:', error);
                  } finally {
                    setAddingTask(false);
                  }
                }}
                disabled={addingTask || !newTask.trim()}
                className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm disabled:opacity-40"
                style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
              >
                {addingTask ? 'Adding…' : 'Add'}
              </button>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'notes' && (
        <div className="space-y-3">
          {caseData.notes.length === 0 ? (
            <div className="rounded-sm p-4" style={tv.panelBorder}>
              <p className="font-mono text-xs" style={tv.muted}>No analyst notes yet.</p>
            </div>
          ) : (
            caseData.notes.map((note: any, i: number) => (
              <div key={i} className="rounded-sm p-4 space-y-1.5" style={tv.panelBorder}>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px]" style={tv.muted}>{note.author}</span>
                  <span style={tv.faint}>·</span>
                  <span className="font-mono text-[10px]" style={tv.faint}>{new Date(note.time).toLocaleString()}</span>
                </div>
                <p className="text-sm leading-relaxed" style={tv.text}>{note.text}</p>
              </div>
            ))
          )}
          <div className="rounded-sm p-4 space-y-2" style={tv.panelBorder}>
            <textarea 
              placeholder="Add analyst note…"
              value={newNote}
              onChange={e => setNewNote(e.target.value)}
              className="w-full font-mono text-xs rounded-sm px-3 py-2 h-24 resize-none placeholder:opacity-40 focus:outline-none"
              style={tv.input}
            />
            <button 
              onClick={async () => {
                if (!newNote.trim()) return;
                setAddingNote(true);
                try {
                  const result = await addCaseNote(caseData.id, newNote);
                  if (result.success && onUpdate) {
                    onUpdate({
                      ...caseData,
                      notes: [...caseData.notes, result.note],
                    });
                  }
                  setNewNote('');
                  await createAuditEvent('Note Added', caseData.id, 'SUCCESS');
                } catch (error) {
                  console.error('Failed to add note:', error);
                } finally {
                  setAddingNote(false);
                }
              }}
              disabled={addingNote || !newNote.trim()}
              className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm disabled:opacity-40"
              style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
            >
              {addingNote ? 'Adding…' : 'Add Note'}
            </button>
          </div>
        </div>
      )}

      {activeTab === 'evidence' && (
        <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
          <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Chain of Custody</p>
          </div>
          {caseData.relatedEmails.length === 0 ? (
            <div className="p-6"><p className="font-mono text-xs" style={tv.muted}>No evidence linked.</p></div>
          ) : (
            caseData.relatedEmails.map((eid: string, i: number) => (
              <div key={i} className="flex items-center gap-4 px-5 py-3 border-b last:border-0"
                style={{ borderColor: 'var(--tw-border-mid)' }}
              >
                <span className="evidence-num shrink-0">{String(i + 1).padStart(2, '0')}</span>
                <div className="flex-1">
                  <p className="font-mono text-xs" style={tv.text}>{eid}</p>
                  <p className="font-mono text-[10px]" style={tv.muted}>Email artifact · SHA-256 verified</p>
                </div>
                <span className="font-mono text-[10px]" style={tv.low}>Integrity OK</span>
              </div>
            ))
          )}
        </div>
      )}

      <div className="flex flex-wrap gap-3 pt-2">
        <Link to="/app/evidence" className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border inline-flex items-center gap-2"
          style={{
            borderColor: 'var(--tw-border-strong)',
            color: 'var(--tw-text)',
            backgroundColor: 'var(--tw-panel-alt)',
          }}
          {...hoverHandlers()}
        >
          <FileCheck size={12} /> Evidence Repository
        </Link>
        <Link to="/app/reports" className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border inline-flex items-center gap-2"
          style={{
            borderColor: 'var(--tw-border-strong)',
            color: 'var(--tw-text)',
            backgroundColor: 'var(--tw-panel-alt)',
          }}
          {...hoverHandlers()}
        >
          <FileText size={12} /> Reports
        </Link>
        <Link to="/app/decisions" className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border inline-flex items-center gap-2"
          style={{
            borderColor: 'var(--tw-border-strong)',
            color: 'var(--tw-text)',
            backgroundColor: 'var(--tw-panel-alt)',
          }}
          {...hoverHandlers()}
        >
          <Shield size={12} /> Decisions
        </Link>
      </div>
    </div>
  );
}

export default function CasesPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [showCreateCase, setShowCreateCase] = useState(false);
  const [newCase, setNewCase] = useState({
    title: '',
    severity: 'MEDIUM',
    description: '',
    assignedTo: currentAnalyst.name,
  });
  const [customCases, setCustomCases] = useState<any[]>([]);

  const allCasesData = [...cases, ...additionalCases, ...asteronCases] as Array<{
    id: string; title: string; severity: string; status: string; assignedTo: string;
    createdAt: string; updatedAt: string; relatedEmails: string[]; relatedCampaign: string | null;
    exposureRecords: string[]; timelineEvents: any[]; notes: any[]; tasks: any[];
  }>;

  const [selectedCase, setSelectedCase] = useState<any>(() => {
    if (id) {
      return allCasesData.find(c => c.id === id) ?? allCasesData[0];
    }
    return allCasesData[0];
  });

  const allCases = [...allCasesData, ...customCases] as Array<{
    id: string; title: string; severity: string; status: string; assignedTo: string;
    createdAt: string; updatedAt: string; relatedEmails: string[]; relatedCampaign: string | null;
    exposureRecords: string[]; timelineEvents: any[]; notes: any[]; tasks: any[];
  }>;

  function CaseListItem({ caseData, selected, onSelect }: {
    caseData: any;
    selected: boolean;
    onSelect: (c: any) => void;
  }) {
    const relatedCampaign = caseData.relatedCampaign;
    const riskScore = useMemo(() => {
      const investigation = investigations.find(inv => inv.id === caseData.id);
      if (investigation) return investigation.riskScore;
      const asteronIndex = allCasesData.findIndex(c => c.id === caseData.id);
      if (asteronIndex >= 2) return asteronCases[asteronIndex - 2]?.id === caseData.id ? 91 : 85;
      return undefined;
    }, [caseData]);

    return (
      <button
        onClick={() => onSelect(caseData)}
        className="w-full text-left px-5 py-4 border-b transition-colors"
        style={{
          borderColor: 'var(--tw-border-mid)',
          borderLeft: selected ? '2px solid var(--tw-burgundy)' : '2px solid transparent',
          backgroundColor: selected ? 'var(--tw-panel-alt)' : 'transparent',
        }}
        {...hoverHandlers()}
      >
        <div className="flex items-start justify-between gap-2 mb-1">
          <p className="font-mono text-[10px]" style={tv.muted}>{caseData.id}</p>
          <SeverityBadge severity={caseData.severity} />
        </div>
        <p className="text-sm font-medium leading-snug mb-1" style={tv.text}>{caseData.title}</p>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-[9px] px-2 py-0.5 rounded-sm border"
            style={{
              color: statusColor(caseData.status),
              borderColor: `color-mix(in srgb, ${statusColor(caseData.status)} 35%, transparent)`,
              backgroundColor: `color-mix(in srgb, ${statusColor(caseData.status)} 10%, transparent)`,
            }}
          >
            {caseData.status}
          </span>
          {relatedCampaign && (
            <span className="font-mono text-[9px]" style={tv.muted}>{relatedCampaign}</span>
          )}
          {riskScore !== undefined && (
            <span className="font-mono text-[10px]" style={tv.muted}>Score: {riskScore}</span>
          )}
        </div>
      </button>
    );
  }

  const handleCreateCase = async () => {
    if (!newCase.title.trim()) return;

    try {
      const caseData = await createCase({
        title: newCase.title,
        severity: newCase.severity,
        description: newCase.description,
        assignedTo: newCase.assignedTo,
      });

      setCustomCases(prev => [caseData, ...prev]);
      setSelectedCase(caseData);
      setShowCreateCase(false);
      setNewCase({
        title: '',
        severity: 'MEDIUM',
        description: '',
        assignedTo: currentAnalyst.name,
      });

      await createAuditEvent('Case Created', caseData.id, 'SUCCESS');
    } catch (error) {
      console.error('Failed to create case:', error);
    }
  };

  useEffect(() => {
    if (id) {
      const found = allCases.find(c => c.id === id);
      if (found) setSelectedCase(found);
      else navigate('/app/cases', { replace: true });
    }
  }, [id, navigate, allCases]);

  const caseListItems = useMemo(() => {
    const invItems = investigations.map(inv => {
      const match = allCases.find(c => c.id === inv.id);
      return match || { ...inv, relatedEmails: [], relatedCampaign: null, exposureRecords: [], timelineEvents: [], notes: [], tasks: [] } as typeof allCases[0];
    });
    const asteronItems = asteronCases.filter(ac => !invItems.some(i => i.id === ac.id));
    const customItems = customCases.filter(cc => !invItems.some(i => i.id === cc.id) && !asteronItems.some(a => a.id === cc.id));
    return [...invItems, ...asteronItems, ...customItems];
  }, [customCases, allCases]);

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8">
        <div className="flex items-end justify-between mb-6 gap-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Investigation Cases</p>
                <DemoLabel />
              </div>
              <button
                onClick={() => setShowCreateCase(!showCreateCase)}
                className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors flex items-center gap-2"
                style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
              >
                <Plus size={12} /> New Case
              </button>
            </div>
            <h1 className="font-serif text-3xl" style={tv.text}>Case Management</h1>
          </div>
        </div>

        {/* Create Case Form */}
        <AnimatePresence>
          {showCreateCase && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="rounded-sm overflow-hidden border"
              style={{ borderColor: 'var(--tw-border)' }}
            >
              <div className="p-5 space-y-4" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
                <div className="flex items-center justify-between">
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Create New Case</p>
                  <button onClick={() => setShowCreateCase(false)} className="p-1 rounded-sm hover:bg-[var(--tw-hover)]">
                    <X size={14} style={tv.faint} />
                  </button>
                </div>
                
                <div className="grid md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Case Title</label>
                    <input
                      type="text"
                      value={newCase.title}
                      onChange={e => setNewCase({ ...newCase, title: e.target.value })}
                      placeholder="e.g., Invoice Fraud Investigation"
                      className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40"
                      style={tv.input}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Severity</label>
                    <select
                      value={newCase.severity}
                      onChange={e => setNewCase({ ...newCase, severity: e.target.value })}
                      className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none"
                      style={tv.input}
                    >
                      <option value="LOW">Low</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="HIGH">High</option>
                      <option value="CRITICAL">Critical</option>
                    </select>
                  </div>
                </div>
                
                <div className="space-y-2">
                  <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Description</label>
                  <textarea
                    value={newCase.description}
                    onChange={e => setNewCase({ ...newCase, description: e.target.value })}
                    placeholder="Describe the investigation context..."
                    rows={2}
                    className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40 resize-none"
                    style={tv.input}
                  />
                </div>
                
                <div className="space-y-2">
                  <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Assigned To</label>
                  <input
                    type="text"
                    value={newCase.assignedTo}
                    onChange={e => setNewCase({ ...newCase, assignedTo: e.target.value })}
                    className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none"
                    style={tv.input}
                  />
                </div>
                
                <div className="flex gap-2">
                  <button
                    onClick={handleCreateCase}
                    disabled={!newCase.title.trim()}
                    className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40"
                    style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                  >
                    Create Case
                  </button>
                  <button
                    onClick={() => setShowCreateCase(false)}
                    className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                    style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Threat Evidence Network */}
        <ThreatEvidenceNetwork pageType="cases" />

        {caseListItems.length === 0 ? (
          <div className="rounded-sm p-10 text-center" style={tv.panelBorder}>
            <p className="font-mono text-sm" style={tv.muted}>No cases found.</p>
          </div>
        ) : (
          <div className="grid lg:grid-cols-5 rounded-sm overflow-hidden min-h-[70vh]" style={tv.panelBorder}>
            {/* Case list */}
            <div className="lg:col-span-2 border-r overflow-y-auto" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>All Cases ({caseListItems.length})</p>
              </div>
              {caseListItems.map(c => (
                <CaseListItem
                  key={c.id}
                  caseData={c}
                  selected={selectedCase?.id === c.id}
                  onSelect={setSelectedCase}
                />
              ))}
            </div>
            {/* Detail */}
            <div className="lg:col-span-3 p-6 overflow-y-auto">
              {selectedCase
                ? <CaseDetail 
                    caseData={selectedCase} 
                    onUpdate={(updated) => {
                      setSelectedCase(updated);
                      setCustomCases(prev => 
                        prev.map(c => c.id === updated.id ? updated : c)
                      );
                    }}
                  />
                : <div className="flex items-center justify-center h-full"><p className="font-mono text-sm" style={tv.faint}>Select a case to view details</p></div>
              }
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
