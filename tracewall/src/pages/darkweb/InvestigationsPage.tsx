import { useState, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Search, FileText, Plus } from 'lucide-react';
import { motion } from 'framer-motion';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { DARKWEB_DEMO_LABEL } from '../../data/darkWebData';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';
import { NlSearchPanel } from '../../components/darkweb/NlSearchPanel';
import type { NlAnswer, NlInvestigationMatch } from '../../lib/intelligence/nlSearch';

export default function InvestigationsPage() {
  const { darkWebInvestigations, darkWebActorsById, darkWebRelationships } = useIntelligenceData();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string | 'all'>('all');
  // IDs the natural language search returned. The text box and the status
  // select stay authoritative: an NL search narrows what is on screen and
  // can be cleared, it never becomes a hidden filter.
  const [nlMatchIds, setNlMatchIds] = useState<string[] | null>(null);
  const navigate = useNavigate();

  const filtered = useMemo(() => {
    let items = darkWebInvestigations;
    if (nlMatchIds) items = items.filter(i => nlMatchIds.includes(i.id));
    const q = search.toLowerCase();
    if (q) items = items.filter(i => i.id.toLowerCase().includes(q) || i.title.toLowerCase().includes(q));
    if (statusFilter !== 'all') items = items.filter(i => i.status === statusFilter);
    return items;
  }, [search, statusFilter, nlMatchIds, darkWebInvestigations]);

  function onNlResult(answer: NlAnswer) {
    if (answer.scope !== 'investigations') return;
    setNlMatchIds(answer.matches.map((match: NlInvestigationMatch) => match.id));
  }

  const stats = {
    total: darkWebInvestigations.length,
    active: darkWebInvestigations.filter(i => i.status === 'ACTIVE').length,
    completed: darkWebInvestigations.filter(i => i.status === 'COMPLETED').length,
    avgConfidence: darkWebInvestigations.length
      ? Math.round(darkWebInvestigations.reduce((s, i) => s + i.confidence, 0) / darkWebInvestigations.length)
      : 0,
  };

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2"><FileText size={16} style={dw.critical} /><h1 className="font-serif text-3xl" style={dw.text}>Investigations</h1></div>
          <div className="flex items-center gap-2">
            <button onClick={() => navigate('/app/darkweb/demo')} type="button"
              className="font-mono text-[10px] px-3 py-1.5 rounded-sm border flex items-center gap-1"
              style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}><Plus size={11} /> New Demo Investigation</button>
            <DemoLabel />
          </div>
        </div>
        <p className="text-sm max-w-xl" style={dw.muted}>{stats.total} investigations · {stats.active} active · {stats.completed} completed · {stats.avgConfidence}% avg confidence.</p>

        <NlSearchPanel
          scope="investigations"
          placeholder="Ask in plain language — e.g. open cases linked to threat actors, or cases with unverified evidence"
          onResult={onNlResult}
        />

        <div className="flex flex-col md:flex-row gap-3 items-end">
          <div className="relative w-full md:w-80">
            <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search investigations…"
              className="w-full font-mono text-[11px] pl-7 pr-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }} />
          </div>
          <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="font-mono text-[10px] px-2 py-1 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
            <option value="all">All Statuses</option><option value="ACTIVE">Active</option><option value="PENDING">Pending</option><option value="COMPLETED">Completed</option>
          </select>
          {nlMatchIds && (
            <button type="button" onClick={() => setNlMatchIds(null)}
              className="font-mono text-[10px] px-2 py-1 rounded-sm border"
              style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-faint)' }}>
              Clear question filter ({nlMatchIds.length})
            </button>
          )}
        </div>

        <div className="rounded-sm border" style={dw.panel}>
          {filtered.length === 0 ? (
            <div className="p-8 text-center" style={dw.muted}>
              <FileText size={28} className="mx-auto mb-2" />
              <p>No investigations match the selected filters.</p>
              {nlMatchIds && <p className="font-mono text-[10px] mt-1" style={dw.faint}>The question above returned {nlMatchIds.length} case(s); the text and status filters were then applied on top.</p>}
            </div>
          ) : (
            <div className="overflow-x-auto">
            <table className="w-full text-[11px] font-mono">
              <thead>
                <tr style={dw.canvasMid}>
                  <th className="text-left p-3" style={dw.text}>ID</th>
                  <th className="text-left p-3" style={dw.text}>Title</th>
                  <th className="text-left p-3" style={dw.text}>Status</th>
                  <th className="text-left p-3" style={dw.text}>Analyst</th>
                  <th className="text-left p-3" style={dw.text}>Steps</th>
                  <th className="text-left p-3" style={dw.text}>Confidence</th>
                  <th className="text-left p-3" style={dw.text}>Updated</th>
                  <th className="text-left p-3" style={dw.text}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(i => {
                  const actor = darkWebActorsById[i.seedActorId];
                  return (
                    <tr key={i.id} className="border-t hover:bg-[var(--tw-hover)]" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <td className="p-3" style={dw.burg}>{i.id}</td>
                      <td className="p-3" style={dw.text}>{i.title}</td>
                      <td className="p-3" style={dw.muted}>{i.status}</td>
                      <td className="p-3" style={dw.muted}>{i.analyst}</td>
                      <td className="p-3" style={dw.muted}>{i.steps.length}</td>
                      <td className="p-3" style={dw.text}>
                        <div className="w-24"><ConfidenceBar value={i.confidence} label={false} /></div>
                        <span className="font-mono text-[10px]" style={dw.faint}>{i.confidence}%</span>
                      </td>
                      <td className="p-3" style={dw.muted}>{new Date(i.updatedAt).toLocaleDateString()}</td>
                      <td className="p-3"><Link to={`/app/darkweb/investigations/${i.id}`} className="font-mono text-xs" style={dw.burg}>Open →</Link></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            </div>
          )}
        </div>
        <ProtectionModulePanel entityType="INVESTIGATION" />
    </div>
  </motion.div>
  );
}
