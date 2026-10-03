import { useState, useMemo, useEffect } from 'react';
import { Search, Download, Clock, ChevronLeft, ChevronRight } from 'lucide-react';
import { motion } from 'framer-motion';
import { useSearchParams } from 'react-router-dom';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { type TimelineEvent } from '../../data/darkWebData';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

export default function TimelinePage() {
  const [searchParams] = useSearchParams();
  const { darkWebTimeline, darkWebActorsById } = useIntelligenceData();
  const actorParam = searchParams.get('actor');
  const [actorFilter, setActorFilter] = useState<string | 'all'>(
    actorParam && darkWebActorsById[actorParam] ? actorParam : 'all'
  );
  const [typeFilter, setTypeFilter] = useState<string | 'all'>('all');
  const [search, setSearch] = useState('');
  const [month, setMonth] = useState(new Date().getMonth());

  // Deep link from a threat actor profile: /app/darkweb/timeline?actor=ACTOR-001
  useEffect(() => {
    if (actorParam && darkWebActorsById[actorParam]) setActorFilter(actorParam);
  }, [actorParam, darkWebActorsById]);

  const eventTypes = Array.from(new Set(darkWebTimeline.map(e => e.type)));
  const actors = Array.from(new Set(darkWebTimeline.map(e => e.actorId)));

  const filtered = useMemo(() => {
    let items = darkWebTimeline;
    const q = search.toLowerCase();
    if (q) items = items.filter(e => e.title.toLowerCase().includes(q) || e.description.toLowerCase().includes(q));
    if (actorFilter !== 'all') items = items.filter(e => e.actorId === actorFilter);
    if (typeFilter !== 'all') items = items.filter(e => e.type === typeFilter);
    return [...items].sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());
  }, [search, actorFilter, typeFilter, darkWebTimeline]);

  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const monthEvents = (m: number) => darkWebTimeline.filter(e => new Date(e.time).getMonth() === m);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-5xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="flex items-center gap-2"><Clock size={16} style={dw.critical} /><h1 className="font-serif text-3xl" style={dw.text}>Investigation Timeline</h1><DemoLabel /></div>
        <p className="text-sm max-w-xl" style={dw.muted}>{filtered.length} events · {actors.length} actors · filters: actor, type, search. Zoom by month.</p>

        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative w-full md:w-64">
            <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search events…"
              className="w-full font-mono text-[11px] pl-7 pr-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }} />
          </div>
          <div className="flex flex-wrap gap-2">
            <select value={actorFilter} onChange={e => setActorFilter(e.target.value)} className="font-mono text-[10px] px-2 py-1 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
              <option value="all">All Actors</option>{actors.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
            <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} className="font-mono text-[10px] px-2 py-1 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
              <option value="all">All Types</option>{eventTypes.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
            </select>
          </div>
        </div>

        <div className="rounded-sm border p-3 flex items-center gap-2 overflow-x-auto" style={dw.panel}>
          <button onClick={() => setMonth(m => (m + 11) % 12)} className="p-1 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}><ChevronLeft size={13} /></button>
          <span className="font-mono text-xs" style={dw.text}>{months[month]} 2026</span>
          <button onClick={() => setMonth(m => (m + 1) % 12)} className="p-1 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}><ChevronRight size={13} /></button>
          <span className="font-mono text-[10px]" style={dw.muted}>{monthEvents(month).length} events this month</span>
          <Download size={12} className="ml-auto" style={dw.muted} />
        </div>

        <div className="rounded-sm border p-4" style={dw.panel}>
          <div className="flex gap-6 overflow-x-auto pb-4">
            {monthEvents(month).length === 0 ? <p style={dw.muted}>No events in this month.</p> : monthEvents(month)
              .sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime())
              .map(e => <TimelineCard key={e.id} event={e} actorAlias={darkWebActorsById[e.actorId]?.aliases[0]} />)}
          </div>
        </div>

        <div className="rounded-sm border p-4" style={dw.panel}>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-3" style={dw.muted}>Filtered Timeline</p>
          {filtered.length === 0 ? <p style={dw.muted}>No events match.</p> : (
            <div className="relative border-l ml-3" style={{ borderColor: 'var(--tw-border-mid)' }}>
              {filtered.map((e) => (<TimelineCard key={e.id} event={e} actorAlias={darkWebActorsById[e.actorId]?.aliases[0]} />))}
            </div>
          )}
        </div>
        <ProtectionModulePanel entityType="ACTOR" />
      </div>
    </motion.div>
  );
}

function TimelineCard({ event, actorAlias }: { event: TimelineEvent; actorAlias?: string }) {
  const color = event.confidence >= 80 ? 'var(--tw-critical)' : event.confidence >= 60 ? 'var(--tw-high)' : 'var(--tw-medium)';
  return (
    <div className="mb-4 ml-4 relative">
      <div className="absolute -left-4 top-1 w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
      <div className="rounded-sm border p-3" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-0.5">
            <div className="flex items-center gap-2">
              <span className="font-mono text-[9px] uppercase px-1.5 py-0.25 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-burgundy) 18%, transparent)', color: 'var(--tw-burgundy)' }}>{event.type.replace('_', ' ')}</span>
              <span className="font-mono text-[9px]" style={dw.burg}>{event.actorId}</span>
            </div>
            <p className="text-sm font-medium" style={dw.text}>{event.title}</p>
            <p className="font-mono text-[10px]" style={dw.muted}>{event.description}</p>
            {actorAlias && <p className="font-mono text-[10px]" style={dw.faint}>Actor: {actorAlias} · {new Date(event.time).toLocaleString()}</p>}
          </div>
          <span className="font-mono text-[10px]" style={{ color }}>conf {event.confidence}%</span>
        </div>
      </div>
    </div>
  );
}
