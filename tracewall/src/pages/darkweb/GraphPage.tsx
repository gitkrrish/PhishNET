import { useState, useEffect, Suspense, lazy } from 'react';
import { motion } from 'framer-motion';
import { useSearchParams } from 'react-router-dom';
import { Network, Filter, Search, BarChart2, Users, Database, Layers } from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { PathExplorer } from '../../components/darkweb/PathExplorer';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { ThreeDErrorBoundary } from '../../components/3d/ThreeDErrorBoundary';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

const RelationshipGraph = lazy(() => import('../../components/darkweb/RelationshipGraph').then(m => ({ default: m.RelationshipGraph })));

export default function GraphPage() {
  const [searchParams] = useSearchParams();
  const { darkWebActors, darkWebRelationships, darkWebEvidence, darkWebInfrastructure, darkWebHandles } = useIntelligenceData();
  const focusParam = searchParams.get('focus');
  const [seed, setSeed] = useState(
    focusParam && darkWebActors.some(a => a.id === focusParam) ? focusParam : ''
  );
  const [filterOpen, setFilterOpen] = useState(false);

  // Deep link from a threat actor profile: /app/darkweb/graph?focus=ACTOR-001
  useEffect(() => {
    if (focusParam && darkWebActors.some(a => a.id === focusParam)) setSeed(focusParam);
  }, [focusParam]);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2"><Network size={16} style={dw.critical} /><h1 className="font-serif text-3xl" style={dw.text}>Relationship Graph</h1></div>
          <DemoLabel />
        </div>
        <p className="text-sm" style={dw.muted}>Interactive relationship graph. Click nodes for intelligence details. Use filters and search to refine the view.</p>

        <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
          <div className="relative w-full md:w-80">
            <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input value={seed} onChange={e => setSeed(e.target.value)} placeholder="Enter actor ID (e.g. ACTOR-001) or handle…"
              className="w-full font-mono text-[11px] pl-7 pr-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }} />
          </div>
          <button onClick={() => setFilterOpen(!filterOpen)} type="button"
            className="font-mono text-[10px] px-2.5 py-1.5 rounded-sm border flex items-center gap-1"
            style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
            <Filter size={11} /> Filters
          </button>
        </div>

        <div className="rounded-sm border" style={dw.panel}>
          <Suspense fallback={<GraphFallback />}>
            <ThreeDErrorBoundary fallback={<GraphFallback />}>
              <RelationshipGraph seed={seed || undefined} heightClass="h-[600px]" />
            </ThreeDErrorBoundary>
          </Suspense>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-center">
          <Stat label="Actors" value={darkWebActors.length} icon={Users} />
          <Stat label="Relationships" value={darkWebRelationships.length} icon={Layers} />
          <Stat label="Evidence" value={darkWebEvidence.length} icon={Database} />
          <Stat label="Handles" value={darkWebHandles.length} icon={Search} />
          <Stat label="Infra" value={darkWebInfrastructure.length} icon={BarChart2} />
        </div>

        <PathExplorer />

        <div className="rounded-sm border p-4" style={dw.panel}>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Relationship Type Legend</p>
          <div className="flex flex-wrap gap-1.5">
            {['SHARED_HANDLE', 'SHARED_PGP', 'SHARED_WALLET', 'SHARED_INFRASTRUCTURE', 'ASSOCIATED_WITH', 'PERSONA_MIGRATION', 'SIMILAR_PERSONA', 'TEMPORAL_OVERLAP'].map(t => (
              <span key={t} className="font-mono text-[9px] px-2 py-0.5 rounded-sm border" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-burgundy) 12%, transparent)', borderColor: 'var(--tw-border-mid)' }}>{t.replace(/_/g, ' ')}</span>
            ))}
          </div>
        </div>
        <ProtectionModulePanel entityType="RELATIONSHIP" />
      </div>
    </motion.div>
  );
}

function Stat({ label, value, icon: Icon }: { label: string; value: number; icon: any }) {
  return (
    <div className="p-3 rounded-sm border text-center" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
      <div className="flex items-center justify-center gap-1"><Icon size={11} style={{ color: 'var(--tw-burgundy)' }} /><span className="font-mono text-xs" style={dw.text}>{value}</span></div>
      <p className="font-mono text-[9px]" style={dw.faint}>{label}</p>
    </div>
  );
}

function GraphFallback() {
  return (
    <div className="p-10 text-center" style={dw.canvasMid}>
      <Database size={28} className="mx-auto mb-2" style={dw.muted} />
      <p className="font-mono text-sm" style={dw.muted}>Graph visualization loading…</p>
    </div>
  );
}
