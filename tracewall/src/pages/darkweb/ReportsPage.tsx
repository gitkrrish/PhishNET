import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { FileText, Search, FileJson, Table, Printer } from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { DARKWEB_DEMO_LABEL } from '../../data/darkWebData';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { generateInvestigationSummary } from '../../lib/darkweb/aiEngine';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';
import {
  buildReportBundle,
  exportReport,
  type ReportBundle,
  type ReportFormat,
} from '../../lib/intelligence/reportExport';
import type { ReportRecord } from '../../lib/intelligence/types';

export default function DarkWebReportsPage() {
  const {
    darkWebReports,
    darkWebInvestigations,
    darkWebInvestigationById,
    darkWebActors,
    darkWebEvidence,
    darkWebRelationships,
    darkWebAlerts,
  } = useIntelligenceData();
  const [selectedType, setSelectedType] = useState<string | 'all'>('all');
  const [search, setSearch] = useState('');

  const types = Array.from(new Set(darkWebReports.map(r => r.type)));

  const filtered = useMemo(() => {
    let items = darkWebReports;
    const q = search.toLowerCase();
    if (q) items = items.filter(r => r.id.toLowerCase().includes(q) || r.title.toLowerCase().includes(q));
    if (selectedType !== 'all') items = items.filter(r => r.type === selectedType);
    return items;
  }, [search, selectedType, darkWebReports]);

  /**
   * Resolve everything the report actually references, straight from the
   * live dataset. Anything the report does not reference is left out
   * rather than padded in, so the export shows the real scope of the
   * report.
   */
  function bundleFor(report: ReportRecord): ReportBundle {
    const investigation = darkWebInvestigationById[report.investigationId];
    const summary = investigation ? generateInvestigationSummary(investigation.id) : undefined;

    const stepEvidenceIds = new Set<string>();
    const stepRelationshipIds = new Set<string>();
    const actorIds = new Set<string>();
    for (const step of investigation?.steps ?? []) {
      step.evidenceIds.forEach((id: string) => stepEvidenceIds.add(id));
      step.relationshipIds.forEach((id: string) => stepRelationshipIds.add(id));
      step.actorIds.forEach((id: string) => actorIds.add(id));
    }
    if (investigation?.seedActorId) actorIds.add(investigation.seedActorId);

    return buildReportBundle({
      report,
      investigation: investigation
        ? {
            id: investigation.id,
            title: investigation.title,
            status: investigation.status,
            analyst: investigation.analyst,
            confidence: investigation.confidence,
            updatedAt: investigation.updatedAt,
            summary: summary
              ? {
                  executiveSummary: summary.detail.executiveSummary,
                  keyFindings: summary.detail.keyFindings,
                  disclaimer: summary.detail.disclaimer,
                }
              : undefined,
            steps: investigation.steps,
          }
        : null,
      actors: darkWebActors.filter(actor => actorIds.has(actor.id)),
      evidence: darkWebEvidence.filter(item => stepEvidenceIds.has(item.id)),
      relationships: darkWebRelationships.filter(rel => stepRelationshipIds.has(rel.id)),
      alerts: darkWebAlerts.filter(alert => alert.actorId !== null && actorIds.has(alert.actorId)),
    });
  }

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-6xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="flex items-center justify-between"><div className="flex items-center gap-2"><FileText size={16} style={dw.critical} /><h1 className="font-serif text-3xl" style={dw.text}>Threat Intelligence Reports</h1></div><DemoLabel /></div>
        <p className="text-sm max-w-xl" style={dw.muted}>{filtered.length} of {darkWebReports.length} reports. Every export contains the stored report record, the investigation it references, and the entities that investigation names.</p>

        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative w-full md:w-64">
            <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search reports…"
              className="w-full font-mono text-[11px] pl-7 pr-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }} />
          </div>
          <select value={selectedType} onChange={e => setSelectedType(e.target.value)} className="font-mono text-[10px] px-2 py-1 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
            <option value="all">All Types</option>{types.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>
        </div>

        <div className="rounded-sm border" style={dw.panel}>
          {filtered.length === 0 ? (
            <div className="p-8 text-center" style={dw.muted}><FileText size={28} className="mx-auto mb-2" /><p>No reports match.</p></div>
          ) : (
            <div className="overflow-x-auto">
            <table className="w-full text-[11px] font-mono">
              <thead>
                <tr style={dw.canvasMid}>
                  <th className="text-left p-3" style={dw.text}>ID</th>
                  <th className="text-left p-3" style={dw.text}>Title</th>
                  <th className="text-left p-3" style={dw.text}>Owner</th>
                  <th className="text-left p-3" style={dw.text}>Type</th>
                  <th className="text-left p-3" style={dw.text}>Investigation</th>
                  <th className="text-left p-3" style={dw.text}>Published</th>
                  <th className="text-left p-3" style={dw.text}>Export</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(r => (
                  <tr key={r.id} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    <td className="p-3" style={dw.burg}>{r.id}</td>
                    <td className="p-3" style={dw.text}>{r.title}</td>
                    <td className="p-3" style={dw.muted}>{r.owner}</td>
                    <td className="p-3" style={dw.muted}>{r.type.replace(/_/g, ' ')}</td>
                    <td className="p-3" style={dw.muted}>
                      {darkWebInvestigationById[r.investigationId]
                        ? r.investigationId
                        : <span style={dw.faint}>{r.investigationId} (not in model)</span>}
                    </td>
                    <td className="p-3" style={dw.muted}>{new Date(r.publishedAt).toLocaleDateString()}</td>
                    <td className="p-3">
                      <ExportMenuInline report={r} bundleFor={bundleFor} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          )}
        </div>

        <div className="rounded-sm border p-4" style={dw.panel}>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Investigation dossier export</p>
          <p className="font-mono text-[10px]" style={dw.muted}>
            Export the stored investigation record, its steps, key findings, and the entities those steps reference.
            All content is derived from the local dataset; PDF opens the browser print dialog on a generated document.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            {darkWebInvestigations.length === 0 ? (
              <p className="font-mono text-[10px]" style={dw.faint}>No investigation exists in the current intelligence model.</p>
            ) : (
              darkWebInvestigations.map(inv => {
                const report: ReportRecord = {
                  id: `Dossier ${inv.id}`,
                  title: `Investigation Dossier — ${inv.title}`,
                  owner: inv.analyst,
                  type: 'ANALYTICAL',
                  publishedAt: inv.updatedAt,
                  investigationId: inv.id,
                  confidence: inv.confidence,
                };
                return (
                  <ExportMenuInline key={inv.id} report={report} bundleFor={bundleFor} label={inv.id} />
                );
              })
            )}
          </div>
        </div>
        <ProtectionModulePanel entityType="INVESTIGATION" />
      </div>
    </motion.div>
  );
}

/**
 * Per-row export menu. The outcome of each attempt is reported in the
 * page, so a blocked print window or a failed download is visible
 * rather than passing silently.
 */
function ExportMenuInline({
  report,
  bundleFor,
  label,
}: {
  report: ReportRecord;
  bundleFor: (report: ReportRecord) => ReportBundle;
  label?: string;
}) {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<{ ok: boolean; message: string } | null>(null);
  const [pending, setPending] = useState<ReportFormat | null>(null);
  const exports: Array<{ format: ReportFormat; icon: typeof FileJson }> = [
    { format: 'JSON', icon: FileJson },
    { format: 'CSV', icon: Table },
    { format: 'PDF', icon: Printer },
  ];

  async function run(format: ReportFormat) {
    setOpen(false);
    setPending(format);
    try {
      setStatus(await exportReport(bundleFor(report), format));
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="inline-block align-top">
      <div className="relative">
        <button type="button" onClick={() => setOpen(!open)} disabled={pending !== null}
          className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm border disabled:opacity-60"
          style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
          {pending ? `${pending}…` : (label ?? 'Export')} ▾
        </button>
        {open && (
          <div className="absolute top-full left-0 z-20 mt-1 rounded-sm border shadow-lg" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
            {exports.map(item => {
              const Icon = item.icon;
              return (
                <button key={item.format} type="button" onClick={() => run(item.format)}
                  className="block w-full text-left font-mono text-[9px] px-2.5 py-1 border-b last:border-0 flex items-center gap-1"
                  style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
                  <Icon size={10} /> {item.format}
                </button>
              );
            })}
          </div>
        )}
      </div>
      {status && (
        <p className="font-mono text-[9px] mt-1 max-w-[26rem]" style={{ color: status.ok ? 'var(--tw-moss)' : 'var(--tw-critical)' }}>
          {status.message}
        </p>
      )}
    </div>
  );
}