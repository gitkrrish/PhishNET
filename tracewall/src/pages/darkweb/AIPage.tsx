import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Bot,
  Sparkles,
  Search,
  Fingerprint,
  Network,
  AlertTriangle,
  FileText,
  ArrowRight,
  Users,
} from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import {
  stylometricSimilarity,
  behavioralAnalysis,
  explainRelationship,
  anomalyDetection,
  generateInvestigationSummary,
  threatActors as darkWebActors,
  darkWebRelationships,
  darkWebEvidence,
  darkWebInvestigations,
} from '../../lib/darkweb/aiEngine';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { ConfidenceRing } from '../../components/darkweb/ConfidenceRing';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { RelationshipChip } from '../../components/darkweb/RelationshipChip';
import { ExportMenu } from '../../components/darkweb/ExportMenu';
import { AiAssistant } from '../../components/darkweb/AiAssistant';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';
import { NlSearchPanel } from '../../components/darkweb/NlSearchPanel';

const TABS = [
  { key: 'insights', label: 'AI Investigation Insights', icon: Sparkles },
  { key: 'extraction', label: 'Entity Extraction', icon: Fingerprint },
  { key: 'discovery', label: 'Relationship Discovery', icon: Network },
  { key: 'anomalies', label: 'Anomaly Detection', icon: AlertTriangle },
  { key: 'summary', label: 'Evidence Summary', icon: FileText },
  { key: 'assistant', label: 'Investigation Assistant', icon: Bot },
] as const;

type TabKey = (typeof TABS)[number]['key'];

const DEFAULT_SEED = 'ACTOR-001';

function Panel({
  icon: Icon,
  title,
  meta,
  children,
}: {
  icon: typeof Search;
  title: string;
  meta?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-sm border" style={dw.panel}>
      <div className="px-5 py-3 border-b flex items-center justify-between gap-3" style={dw.borderMid}>
        <div className="flex items-center gap-2" style={dw.muted}>
          <Icon size={13} />
          {title}
        </div>
        {meta && (
          <span className="font-mono text-[10px]" style={dw.faint}>
            {meta}
          </span>
        )}
      </div>
      {children}
    </div>
  );
}

export default function AIPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const actorParam = searchParams.get('actor');
  const [tab, setTab] = useState<TabKey>('insights');
  // The engine reads the dataset at call time, so the revision is the only
  // dependency these memos need to recompute after a write.
  const { revision } = useIntelligence();
  const [seedId, setSeedId] = useState(
    actorParam && darkWebActors.some(a => a.id === actorParam) ? actorParam : DEFAULT_SEED
  );

  // Deep link from a threat actor profile: /app/darkweb/ai?actor=ACTOR-001
  useEffect(() => {
    if (actorParam && darkWebActors.some(a => a.id === actorParam)) setSeedId(actorParam);
  }, [actorParam]);

  function setTabAndClearActor(next: TabKey) {
    setTab(next);
    if (actorParam) {
      searchParams.delete('actor');
      setSearchParams(searchParams, { replace: true });
    }
  }

  const seed = darkWebActors.find(actor => actor.id === seedId) ?? darkWebActors[0];

  const insights = useMemo(() => {
    const others = darkWebActors.filter(actor => actor.id !== seed.id);
    const pairs = others.map(other => ({
      other,
      stylometry: stylometricSimilarity(seed, other),
      behavior: behavioralAnalysis(seed, other),
    }));
    const strongest = pairs
      .slice()
      .sort((a, b) => b.stylometry.similarity + b.behavior.overall - (a.stylometry.similarity + a.behavior.overall))[0];
    const personaMigrations = darkWebRelationships.filter(
      rel => rel.type === 'PERSONA_MIGRATION' && (rel.sourceEntity === seed.id || rel.targetEntity === seed.id),
    );
    const related = darkWebRelationships.filter(
      rel => rel.sourceEntity === seed.id || rel.targetEntity === seed.id,
    );
    const anomalies = anomalyDetection().filter(item => item.actorId === seed.id);
    return {
      pairs,
      strongest,
      personaMigrations,
      related,
      anomalies,
      evidence: darkWebEvidence.filter(item => item.relatedActor === seed.id),
      overall: Math.round(
        (pairs.reduce((sum, p) => sum + p.stylometry.similarity + p.behavior.overall, 0) / Math.max(1, pairs.length * 2)) *
          0.4 +
          seed.confidenceScore * 0.6,
      ),
    };
  }, [seed, revision]);

  const entityExtraction = useMemo(
    () => (!seed ? [] : [
      { label: 'Threat Actor', value: seed.id, note: `aliases: ${seed.aliases.join(', ')}` },
      { label: 'Handles', value: seed.handles.join(', '), note: `${seed.handles.length} observed handles` },
      { label: 'PGP Fingerprints', value: seed.pgpFingerprints.join(', ') || '—', note: 'Cryptographic identity' },
      { label: 'Wallets', value: seed.walletAddrs.join(', ') || '—', note: 'Cryptocurrency indicators' },
      { label: 'Infrastructure', value: seed.domains.join(', ') || '—', note: 'Domains and relays' },
      { label: 'Platforms', value: seed.platforms.join(', '), note: 'Source platforms' },
      { label: 'Topic Clusters', value: seed.behavioralProfile.topicClusters.join(', '), note: 'Behavioral signal' },
      { label: 'Recurring Expressions', value: seed.stylometricProfile.recurringExpressions.join(', ') || '—', note: 'Stylometric signal' },
    ]),
    [seed, revision],
  );

  const discovery = useMemo(
    () =>
      darkWebRelationships
        .slice()
        .sort((a, b) => b.confidence - a.confidence)
        .map(rel => ({ rel, explanation: explainRelationship(rel.id) })),
    [revision],
  );

  const investigation = darkWebInvestigations[0];
  const investigationSummary = useMemo(
    () => investigation
      ? generateInvestigationSummary(investigation.id)
      : {
          summary: { id: '—', title: 'No investigation', confidence: 0, status: 'OPEN' as const },
          detail: {
            investigation: { id: '—', title: 'No investigation in the central model', analyst: '—', status: 'OPEN' as const },
            executiveSummary: 'The central intelligence model currently holds no investigation. Load the demo dataset or create one to generate an evidence summary.',
            keyFindings: [] as string[],
            confidenceBreakdown: [] as { label: string; value: number; note?: string }[],
            evidenceCount: 0,
            relationshipCount: 0,
            steps: [],
            disclaimer: 'No records available.',
          },
        },
    [investigation?.id, revision],
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="min-h-screen page-enter"
      style={sectionStyle()}
    >
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bot size={16} style={dw.critical} />
            <h1 className="font-serif text-3xl" style={dw.text}>
              AI Analysis
            </h1>
          </div>
          <DemoLabel />
        </div>
        <p className="text-sm max-w-2xl leading-relaxed" style={dw.muted}>
          AI investigation intelligence. Extraction, persona similarity, relationship discovery and
          evidence summarization for dark web investigations. Every finding cites the records it was
          derived from — the assistant never invents evidence.
        </p>

        {/* Seed selector */}
        <div className="rounded-sm border p-4 flex flex-col md:flex-row gap-3 md:items-end" style={dw.panel}>
          <div>
            <p className="font-mono text-[10px] tracking-widest uppercase mb-1.5" style={dw.muted}>
              Analysis target
            </p>
            <select
              value={seed?.id ?? ''}
              onChange={e => setSeedId(e.target.value)}
              className="font-mono text-[11px] px-2 py-1.5 rounded-sm focus:outline-none"
              style={{
                backgroundColor: 'var(--tw-panel-alt)',
                borderColor: 'var(--tw-border-mid)',
                color: 'var(--tw-text)',
              }}
            >
              {darkWebActors.map(actor => (
                <option key={actor.id} value={actor.id}>
                  {actor.id} — {actor.aliases[0]}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Natural language search across the whole stored model. Every
            answer names the records it read, and the operations that
            produced it, so a statement can be checked against its
            source. Nothing is generated when no filter is understood. */}
        <NlSearchPanel
          scope="ai"
          placeholder="Ask about the intelligence model — e.g. infrastructure shared between actors, unverified evidence, what is known about ACTOR-001"
        />

        {/* Seed entity context — the threat actor is the central entity */}
        {actorParam && darkWebActors.some(a => a.id === actorParam) && (
          <div
            className="rounded-sm border p-3 flex flex-wrap items-center justify-between gap-3"
            style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border-mid)' }}
          >
            <div className="flex items-center gap-2">
              <Link
                to={`/app/darkweb/actors/${actorParam}`}
                className="font-mono text-[10px] tracking-widest uppercase px-2 py-1 rounded-sm border"
                style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)', textDecoration: 'none' }}
              >
                {actorParam}
              </Link>
              <span className="text-xs" style={dw.text}>
                AI findings below are scoped to{' '}
                <span className="font-mono" style={dw.burg}>{seed.aliases[0]}</span> and its linked records
              </span>
            </div>
            <Link to={`/app/darkweb/actors/${actorParam}`} className="font-mono text-[10px]" style={dw.burg}>
              Open full profile →
            </Link>
          </div>
        )}

        {/* Tabs */}
        <div>
          <div className="flex items-center overflow-x-auto" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
            {TABS.map(item => {
              const Icon = item.icon;
              const active = tab === item.key;
              return (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => setTabAndClearActor(item.key)}
                  className="px-4 py-3 font-mono text-xs border-b-2 flex items-center gap-1.5 whitespace-nowrap transition-colors"
                  style={{
                    borderBottomColor: active ? 'var(--tw-burgundy)' : 'transparent',
                    color: active ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
                  }}
                >
                  <Icon size={12} />
                  {item.label}
                </button>
              );
            })}
          </div>

          <div className="p-5 space-y-6">
            {tab === 'insights' && (
              <div className="space-y-6">
                <div className="grid md:grid-cols-4 gap-4">
                  <div className="rounded-sm border p-5 flex flex-col items-center" style={dw.panel}>
                    <ConfidenceRing value={insights.overall} label="Confidence" />
                  </div>
                  <div className="rounded-sm border p-5" style={dw.panel}>
                    <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>
                      Potential relationships
                    </p>
                    <p className="font-mono text-3xl font-light" style={dw.burg}>
                      {insights.related.length}
                    </p>
                  </div>
                  <div className="rounded-sm border p-5" style={dw.panel}>
                    <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>
                      Persona migration
                    </p>
                    <p className="font-mono text-3xl font-light" style={dw.burg}>
                      {insights.personaMigrations.length}
                    </p>
                  </div>
                  <div className="rounded-sm border p-5" style={dw.panel}>
                    <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>
                      Behavior anomalies
                    </p>
                    <p className="font-mono text-3xl font-light" style={dw.burg}>
                      {insights.anomalies.length}
                    </p>
                  </div>
                </div>

                <Panel icon={Sparkles} title="AI Investigation Insights" meta={seed.id}>
                  <div className="p-5 space-y-3">
                    <p className="text-sm leading-relaxed" style={dw.text}>
                      {seed.aliases[0]} ({seed.id}) resolves to {insights.related.length} relationships
                      across {seed.platforms.length} platforms, backed by {insights.evidence.length} evidence
                      items. Strongest correlation:{' '}
                      <span style={dw.burg}>
                        {insights.strongest
                          ? insights.strongest.stylometry.similarity >= insights.strongest.behavior.overall
                            ? `stylometric match with ${insights.strongest.other.aliases[0]} (${insights.strongest.stylometry.similarity}%)`
                            : `behavioral match with ${insights.strongest.other.aliases[0]} (${insights.strongest.behavior.overall}%)`
                          : 'no comparable actor'}
                      </span>
                      .
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <Link
                        to={`/app/darkweb/actors/${seed.id}`}
                        className="font-mono text-[10px] px-2 py-1 rounded-sm border flex items-center gap-1"
                        style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                      >
                        Open actor profile <ArrowRight size={10} />
                      </Link>
                      <Link
                        to={`/app/darkweb/graph?seed=${seed.id}`}
                        className="font-mono text-[10px] px-2 py-1 rounded-sm border flex items-center gap-1"
                        style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                      >
                        Open relationship graph <ArrowRight size={10} />
                      </Link>
                      <Link
                        to="/app/darkweb/correlation"
                        className="font-mono text-[10px] px-2 py-1 rounded-sm border flex items-center gap-1"
                        style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                      >
                        Open correlation workspace <ArrowRight size={10} />
                      </Link>
                    </div>
                  </div>
                </Panel>

                <Panel icon={Users} title="AI Persona Similarity" meta={`${insights.pairs.length} candidate pair(s)`}>
                  {insights.pairs.map(pair => (
                    <div key={pair.other.id} className="p-4 border-b last:border-0" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <div className="flex items-center justify-between gap-3 mb-2">
                        <Link to={`/app/darkweb/actors/${pair.other.id}`} className="font-mono text-xs" style={dw.burg}>
                          {seed.aliases[0]} ↔ {pair.other.aliases[0]}
                        </Link>
                        <RelationshipChip
                          type="SIMILAR_PERSONA"
                          confidence={Math.round((pair.stylometry.similarity + pair.behavior.overall) / 2)}
                        />
                      </div>
                      <div className="grid md:grid-cols-2 gap-4">
                        <div>
                          <p className="font-mono text-[10px] tracking-widest uppercase mb-1" style={dw.muted}>
                            Stylometric — {pair.stylometry.similarity}% ({pair.stylometry.label})
                          </p>
                          <ConfidenceBar value={pair.stylometry.similarity} label={false} />
                        </div>
                        <div>
                          <p className="font-mono text-[10px] tracking-widest uppercase mb-1" style={dw.muted}>
                            Behavioral — {pair.behavior.overall}%
                          </p>
                          <ConfidenceBar value={pair.behavior.overall} label={false} />
                        </div>
                      </div>
                    </div>
                  ))}
                </Panel>
              </div>
            )}

            {tab === 'extraction' && (
              <Panel icon={Fingerprint} title="AI Entity Extraction" meta={seed.id}>
                <table className="w-full text-[10px] font-mono">
                  <thead>
                    <tr style={dw.canvasMid}>
                      <th className="text-left p-2" style={dw.text}>Entity type</th>
                      <th className="text-left p-2" style={dw.text}>Extracted value</th>
                      <th className="text-left p-2" style={dw.text}>Signal</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entityExtraction.map(entry => (
                      <tr key={entry.label} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                        <td className="p-2 whitespace-nowrap" style={dw.text}>{entry.label}</td>
                        <td className="p-2 break-all" style={dw.burg}>{entry.value}</td>
                        <td className="p-2" style={dw.muted}>{entry.note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Panel>
            )}

            {tab === 'discovery' && (
              <Panel
                icon={Network}
                title="Relationship Discovery & Explainable Attribution"
                meta={`${discovery.length} relationships`}
              >
                {discovery.map(({ rel, explanation }) => (
                  <div key={rel.id} className="p-4 border-b last:border-0" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-0.5 min-w-0">
                        <p className="font-mono text-[10px] tracking-wider" style={dw.burg}>{rel.id}</p>
                        <p className="font-mono text-xs" style={dw.text}>
                          {rel.sourceEntity} → {rel.targetEntity}
                        </p>
                      </div>
                      <RelationshipChip type={rel.type} confidence={rel.confidence} />
                    </div>
                    <p className="text-xs mt-1.5 leading-relaxed" style={dw.muted}>{rel.explanation}</p>
                    <div className="grid md:grid-cols-2 gap-4 mt-3">
                      <div>
                        <p className="font-mono text-[10px] tracking-widest uppercase mb-1" style={dw.low}>
                          Why linked
                        </p>
                        {(explanation?.supporting ?? []).map((point, index) => (
                          <p key={index} className="font-mono text-[10px]" style={dw.muted}>+ {point}</p>
                        ))}
                      </div>
                      <div>
                        <p className="font-mono text-[10px] tracking-widest uppercase mb-1" style={dw.critical}>
                          Counter-evidence
                        </p>
                        {(explanation?.against ?? []).map((point, index) => (
                          <p key={index} className="font-mono text-[10px]" style={dw.muted}>− {point}</p>
                        ))}
                      </div>
                    </div>
                    {!!explanation?.evidence.length && (
                      <p className="font-mono text-[10px] mt-2" style={dw.faint}>
                        Evidence: {explanation.evidence.map(e => e.id).join(', ')}
                      </p>
                    )}
                  </div>
                ))}
              </Panel>
            )}

            {tab === 'anomalies' && (
              <Panel icon={AlertTriangle} title="Anomaly Detection">
                {anomalyDetection().map(anomaly => (
                  <div key={anomaly.id} className="p-4 border-b last:border-0" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-0.5">
                        <p className="font-mono text-[10px] tracking-wider" style={dw.burg}>{anomaly.id}</p>
                        <p className="font-mono text-[10px]" style={dw.faint}>
                          {anomaly.type} · {new Date(anomaly.timestamp).toLocaleString()}
                        </p>
                      </div>
                      <RelationshipChip type="ANOMALY_DETECTED" confidence={anomaly.confidence} />
                    </div>
                    <p className="text-xs mt-1.5 leading-relaxed" style={dw.muted}>{anomaly.description}</p>
                  </div>
                ))}
              </Panel>
            )}

            {tab === 'summary' && (
              <div className="space-y-6">
                <Panel
                  icon={FileText}
                  title="Evidence Summarization"
                  meta={`${investigationSummary.detail.evidenceCount} evidence · ${investigationSummary.detail.relationshipCount} relationships`}
                >
                  <div className="p-5 space-y-4">
                    <p className="text-sm leading-relaxed" style={dw.text}>
                      {investigationSummary.detail.executiveSummary}
                    </p>
                    <div>
                      <p className="font-mono text-[10px] tracking-widest uppercase mb-1.5" style={dw.muted}>
                        Key findings
                      </p>
                      {investigationSummary.detail.keyFindings.map((finding, index) => (
                        <div key={index} className="flex items-start gap-3">
                          <span className="evidence-num shrink-0">{String(index + 1).padStart(2, '0')}</span>
                          <p className="text-xs leading-relaxed" style={dw.muted}>{finding}</p>
                        </div>
                      ))}
                    </div>
                    <div>
                      <p className="font-mono text-[10px] tracking-widest uppercase mb-1.5" style={dw.muted}>
                        Confidence breakdown
                      </p>
                      <div className="grid md:grid-cols-2 gap-x-6 gap-y-2">
                        {investigationSummary.detail.confidenceBreakdown.map(factor => (
                          <div key={factor.label} className="flex items-center gap-3">
                            <span className="font-mono text-[10px] w-44 shrink-0" style={dw.muted}>{factor.label}</span>
                            <span className="flex-1">
                              <ConfidenceBar value={factor.value} label={false} />
                            </span>
                            <span className="font-mono text-[10px] w-8 text-right" style={dw.text}>{factor.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <p className="font-mono text-[10px] leading-relaxed" style={dw.faint}>
                      {investigationSummary.detail.disclaimer}
                    </p>
                    <div className="flex items-center gap-2">
                      <Link
                        to={`/app/darkweb/investigations/${investigationSummary.detail.investigation.id}`}
                        className="font-mono text-[10px] px-3 py-1.5 rounded-sm border flex items-center gap-1"
                        style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                      >
                        Open investigation <ArrowRight size={10} />
                      </Link>
                      <ExportMenu type="investigation" id={investigationSummary.detail.investigation.id} />
                    </div>
                  </div>
                </Panel>
              </div>
            )}

            {tab === 'assistant' && (
              <Panel icon={Bot} title="Investigation Assistant" meta="Dataset-derived only">
                <div className="p-4">
                  {investigation ? (
                    <AiAssistant contextActorId={seed.id} investigationId={investigation.id} />
                  ) : (
                    <p className="text-xs" style={dw.muted}>
                      No investigation exists in the central model, so the assistant has no case to work from. Load the
                      demo dataset or create an investigation first.
                    </p>
                  )}
                </div>
              </Panel>
            )}
          </div>
        </div>
        <ProtectionModulePanel entityType="ACTOR" />
      </div>
    </motion.div>
  );
}
