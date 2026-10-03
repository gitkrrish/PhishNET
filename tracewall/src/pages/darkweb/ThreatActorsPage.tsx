import { useState, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Search, Filter, Users, SortAsc, SortDesc, Shield } from 'lucide-react';
import { motion } from 'framer-motion';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData, useProtection } from '../../lib/intelligence/IntelligenceContext';
import { type ThreatActor } from '../../data/darkWebData';
import { ThreatActorCard } from '../../components/darkweb/ThreatActorCard';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

export default function ThreatActorsPage() {
  const { darkWebActors, darkWebRelationships } = useIntelligenceData();
  const { scoreEntity } = useProtection();
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState<'confidence' | 'lastSeen' | 'firstSeen' | 'risk'>('confidence');
  const [dir, setDir] = useState<'asc' | 'desc'>('desc');
  const [activeOnly, setActiveOnly] = useState(false);
  const navigate = useNavigate();

  const filtered = useMemo(() => {
    let items = darkWebActors;
    if (search.trim()) {
      const q = search.toLowerCase();
      items = items.filter(a => a.id.toLowerCase().includes(q) || a.aliases.some(x => x.toLowerCase().includes(q)) || a.handles.some(h => h.toLowerCase().includes(q)));
    }
    if (activeOnly) items = items.filter(a => a.status === 'ACTIVE');
    items = [...items].sort((a, b) => {
      let av: number, bv: number;
      if (sort === 'confidence') { av = a.confidenceScore; bv = b.confidenceScore; }
      else if (sort === 'risk') {
        const sa = scoreEntity('ACTOR', a.id);
        const sb = scoreEntity('ACTOR', b.id);
        av = sa ? sa.value : 0;
        bv = sb ? sb.value : 0;
      }
      else { av = new Date(a[sort]).getTime(); bv = new Date(b[sort]).getTime(); }
      return dir === 'asc' ? av - bv : bv - av;
    });
    return items;
  }, [search, sort, dir, activeOnly, darkWebActors, scoreEntity]);

  const stats = {
    total: darkWebActors.length,
    active: darkWebActors.filter(a => a.status === 'ACTIVE').length,
    migrations: darkWebRelationships.filter(r => r.type === 'PERSONA_MIGRATION').length,
    avgConfidence: darkWebActors.length
      ? Math.round(darkWebActors.reduce((s, a) => s + a.confidenceScore, 0) / darkWebActors.length)
      : 0,
  };

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2"><Users size={16} style={dw.critical} /><h1 className="font-serif text-3xl" style={dw.text}>Threat Actors</h1></div>
            <p className="text-sm max-w-xl" style={dw.muted}>{stats.total} monitored actors · {stats.active} active · {stats.migrations} persona migrations · {stats.avgConfidence}% avg confidence</p>
          </div>
        </div>

        <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
          <div className="relative w-full md:w-72">
            <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search actors, aliases, handles…"
              className="w-full font-mono text-[11px] pl-7 pr-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }} />
          </div>
          <div className="flex gap-2 items-center">
            <button onClick={() => setActiveOnly(!activeOnly)} type="button"
              className={`font-mono text-[10px] px-2.5 py-1 rounded-sm border ${activeOnly ? 'bg-burg text-white' : ''}`}
              style={{ backgroundColor: activeOnly ? 'var(--tw-burgundy)' : 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: activeOnly ? '#FBFAF6' : 'var(--tw-text-muted)' }}>
              Active only
            </button>
            <select value={sort} onChange={e => setSort(e.target.value as any)} className="font-mono text-[10px] px-2 py-1 rounded-sm"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
              <option value="confidence">Confidence</option><option value="risk">Threat Risk</option><option value="lastSeen">Last Seen</option><option value="firstSeen">First Seen</option>
            </select>
            <button onClick={() => setDir(d => d === 'asc' ? 'desc' : 'asc')} type="button" className="p-1 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
              {dir === 'desc' ? <SortDesc size={12} /> : <SortAsc size={12} />}
            </button>
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="p-8 text-center rounded-sm border" style={dw.panel}>
            <Shield size={24} className="mx-auto mb-2" style={dw.muted} />
            <p style={dw.muted}>No actors match your query.</p>
          </div>
        ) : (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-5">
            {filtered.map((actor: ThreatActor) => (
              <ThreatActorCard key={actor.id} actor={actor} risk={scoreEntity('ACTOR', actor.id)?.riskLevel} />
            ))}
          </div>
        )}
        <ProtectionModulePanel entityType="ACTOR" />
      </div>
    </motion.div>
  );
}
