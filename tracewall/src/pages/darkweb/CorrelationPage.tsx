import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Search,
  MousePointer,
  Key,
  Wallet,
  Globe,
  Brain,
  Fingerprint,
  AlertTriangle,
  Users,
  Network,
  ArrowRight,
} from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import {
  correlateHandles,
  identityCorrelationMatrix,
  searchPgp,
  searchWallet,
  searchInfrastructure,
  stylometricSimilarity,
  behavioralAnalysis,
  resolveEntity,
  anomalyDetection,
  threatActors as darkWebActors,
  darkWebPgpKeys,
  darkWebWallets,
  darkWebInfrastructure,
} from '../../lib/darkweb/aiEngine';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { CorrelationMatrix } from '../../components/darkweb/CorrelationMatrix';
import { RelationshipChip } from '../../components/darkweb/RelationshipChip';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

const TABS = [
  { key: 'handles', label: 'Handle Correlation', icon: MousePointer },
  { key: 'identifiers', label: 'PGP & Wallet', icon: Key },
  { key: 'infrastructure', label: 'Infrastructure', icon: Globe },
  { key: 'behavior', label: 'Behavioral & Stylometry', icon: Brain },
  { key: 'resolution', label: 'Entity Resolution', icon: Fingerprint },
  { key: 'anomalies', label: 'Anomalies', icon: AlertTriangle },
] as const;

type TabKey = (typeof TABS)[number]['key'];

const DEFAULT_QUERY = 'shadowfox';

const IDENTIFIER_SEEDS = [DEFAULT_QUERY, 'ghostwire', '4A3B', 'bc1q', 'relay'];

function SectionTitle({ icon: Icon, children }: { icon: typeof Search; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 mb-3" style={dw.muted}>
      <Icon size={13} />
      {children}
    </div>
  );
}

export default function CorrelationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const actorParam = searchParams.get('actor');
  // The engine reads the dataset at call time; the revision is the dependency
  // that makes every memo below recompute after an analyst write.
  const { revision } = useIntelligence();
  const actorHandles = darkWebActors.find(a => a.id === actorParam)?.handles ?? [];
  const [tab, setTab] = useState<TabKey>('handles');
  const [query, setQuery] = useState(actorHandles[0] ?? DEFAULT_QUERY);

  // A deep link such as /app/darkweb/correlation?actor=ACTOR-001 re-runs the
  // workspace against that actor's primary handle, so the threat actor stays
  // the central entity no matter which page the analyst lands on.
  useEffect(() => {
    if (actorHandles[0]) setQuery(actorHandles[0]);
  }, [actorParam]);

  function setTabAndClearActor(next: TabKey) {
    setTab(next);
    if (actorParam) {
      searchParams.delete('actor');
      setSearchParams(searchParams, { replace: true });
    }
  }

  const handleMatches = useMemo(() => correlateHandles(query), [query, revision]);
  const matrix = useMemo(() => identityCorrelationMatrix(query), [query, revision]);
  const pgpResults = useMemo(() => searchPgp(query), [query, revision]);
  const walletResults = useMemo(() => searchWallet(query), [query, revision]);
  const infraResults = useMemo(() => searchInfrastructure(query), [query, revision]);
  const resolution = useMemo(() => {
    try {
      return resolveEntity(query);
    } catch {
      return null;
    }
  }, [query, revision]);
  const anomalies = useMemo(() => anomalyDetection(), [revision]);

  const behaviorPairs = useMemo(
    () =>
      darkWebActors.flatMap((actor, i) =>
        darkWebActors.slice(i + 1).map(other => ({
          a: actor,
          b: other,
          stylometry: stylometricSimilarity(actor, other),
          behavior: behavioralAnalysis(actor, other),
        })),
      ),
    [revision],
  );

  const identifierHits = useMemo(() => {
    const all = [
      ...pgpResults.map(r => ({ value: r.key.fingerprint, kind: 'PGP', actors: r.key.actorIds, confidence: r.key.confidence })),
      ...walletResults.map(r => ({ value: r.wallet.address, kind: 'WALLET', actors: r.wallet.actorIds, confidence: r.wallet.confidence })),
    ];
    if (all.length) return all;
    return [
      ...darkWebPgpKeys.map(k => ({ value: k.fingerprint, kind: 'PGP', actors: k.actorIds, confidence: k.confidence })),
      ...darkWebWallets.map(w => ({ value: w.address, kind: 'WALLET', actors: w.actorIds, confidence: w.confidence })),
    ].filter(entry => entry.value.toLowerCase().includes(query.toLowerCase()));
  }, [pgpResults, walletResults, query, revision]);

  const infraHits = useMemo(() => {
    if (infraResults.length) {
      return infraResults.map(r => ({
        value: r.infra.value,
        type: r.infra.type,
        actors: r.infra.actorIds,
        host: r.infra.hostingProvider,
        asn: r.infra.asn,
        country: r.infra.country,
      }));
    }
    return darkWebInfrastructure
      .filter(i => i.value.toLowerCase().includes(query.toLowerCase()))
      .map(i => ({
        value: i.value,
        type: i.type,
        actors: i.actorIds,
        host: i.hostingProvider,
        asn: i.asn,
        country: i.country,
      }));
  }, [infraResults, query, revision]);

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
            <Network size={16} style={dw.critical} />
            <h1 className="font-serif text-3xl" style={dw.text}>
              Identity Correlation
            </h1>
          </div>
          <DemoLabel />
        </div>
        <p className="text-sm max-w-2xl leading-relaxed" style={dw.muted}>
          Dark web analytical workspace. Correlate handles, PGP fingerprints, wallets, infrastructure,
          behavior and stylometry to a single threat actor. Every score below is derived from the
          collected dataset — no indicator is invented.
        </p>

        {/* Query bar */}
        <div className="rounded-sm border p-4" style={dw.panel}>
          <div className="flex flex-col md:flex-row gap-3 items-end">
            <div className="flex-1">
              <label className="font-mono text-[10px] tracking-widest uppercase mb-1.5 block" style={dw.muted}>
                Correlation query
              </label>
              <div className="relative w-full">
                <Search
                  size={12}
                  className="absolute left-2 top-1/2 -translate-y-1/2"
                  style={{ color: 'var(--tw-text-faint)' }}
                />
                <input
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  placeholder="Handle, alias, actor id, PGP fingerprint, wallet or domain…"
                  className="w-full font-mono text-[11px] pl-7 pr-2 py-1.5 rounded-sm focus:outline-none"
                  style={{
                    backgroundColor: 'var(--tw-panel-alt)',
                    borderColor: 'var(--tw-border-mid)',
                    color: 'var(--tw-text)',
                  }}
                />
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {IDENTIFIER_SEEDS.map(seed => (
                <button
                  key={seed}
                  type="button"
                  onClick={() => setQuery(seed)}
                  className="font-mono text-[10px] px-2 py-1.5 rounded-sm border transition-colors"
                  style={{
                    borderColor: 'var(--tw-border-mid)',
                    color: 'var(--tw-text-muted)',
                    backgroundColor: 'var(--tw-panel-alt)',
                  }}
                >
                  {seed}
                </button>
              ))}
            </div>
          </div>
        </div>

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
                Seeded from the threat actor profile — correlating{' '}
                <span className="font-mono" style={dw.burg}>{query}</span>
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
            {tab === 'handles' && (
              <>
                <div className="grid md:grid-cols-2 gap-6">
                  <div className="rounded-sm border" style={dw.panel}>
                    <div className="px-5 py-3 border-b" style={dw.borderMid}>
                      <SectionTitle icon={MousePointer}>
                        Handle Correlation — {handleMatches.length} match
                        {handleMatches.length === 1 ? '' : 'es'}
                      </SectionTitle>
                    </div>
                    {handleMatches.length === 0 ? (
                      <div className="p-8 text-center" style={dw.muted}>
                        <MousePointer size={28} className="mx-auto mb-2" />
                        <p>No handle correlates with “{query}”.</p>
                      </div>
                    ) : (
                      handleMatches.map(match => (
                        <div
                          key={match.handleId}
                          className="p-4 border-b last:border-0"
                          style={{ borderColor: 'var(--tw-border-mid)' }}
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="space-y-0.5 min-w-0">
                              <p className="font-mono text-sm" style={dw.text}>
                                {match.value}
                              </p>
                              <p className="font-mono text-[10px]" style={dw.faint}>
                                {match.handleId} · {match.platform} · {match.source}
                              </p>
                            </div>
                            <RelationshipChip type={match.matchType} confidence={match.confidence} />
                          </div>
                          <p className="font-mono text-[10px] mt-1.5 leading-relaxed" style={dw.muted}>
                            {match.why}
                          </p>
                          <div className="mt-2 flex items-center gap-2">
                            <div className="flex-1">
                              <ConfidenceBar value={match.confidence} label={false} />
                            </div>
                            {match.actorId && (
                              <Link
                                to={`/app/darkweb/actors/${match.actorId}`}
                                className="font-mono text-[10px] flex items-center gap-1"
                                style={dw.burg}
                              >
                                {match.actorId} <ArrowRight size={10} />
                              </Link>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  <div className="rounded-sm border" style={dw.panel}>
                    <div className="px-5 py-3 border-b" style={dw.borderMid}>
                      <SectionTitle icon={Users}>Identity Correlation Matrix</SectionTitle>
                    </div>
                    <div className="p-4">
                      {matrix.length === 0 ? (
                        <div className="p-8 text-center" style={dw.muted}>
                          <Users size={28} className="mx-auto mb-2" />
                          <p>No cross-platform identities observed for “{query}”.</p>
                        </div>
                      ) : (
                        <CorrelationMatrix
                          actorIds={Array.from(
                            new Set(handleMatches.map(m => m.actorId).filter(Boolean) as string[]),
                          )}
                        />
                      )}
                    </div>
                  </div>
                </div>
              </>
            )}

            {tab === 'identifiers' && (
              <div className="space-y-6">
                <div className="rounded-sm border" style={dw.panel}>
                  <div className="px-5 py-3 border-b" style={dw.borderMid}>
                    <SectionTitle icon={Key}>
                      PGP Fingerprint &amp; Wallet Correlation — {identifierHits.length} identifier
                      {identifierHits.length === 1 ? '' : 's'}
                    </SectionTitle>
                  </div>
                  <table className="w-full text-[10px] font-mono">
                    <thead>
                      <tr style={dw.canvasMid}>
                        <th className="text-left p-2" style={dw.text}>Identifier</th>
                        <th className="text-left p-2" style={dw.text}>Type</th>
                        <th className="text-left p-2" style={dw.text}>Linked Actors</th>
                        <th className="text-left p-2" style={dw.text}>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {identifierHits.map(entry => (
                        <tr key={`${entry.kind}-${entry.value}`} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                          <td className="p-2 break-all" style={dw.text}>{entry.value}</td>
                          <td className="p-2" style={dw.muted}>
                            {entry.kind === 'PGP' ? <Key size={11} className="inline mr-1" /> : <Wallet size={11} className="inline mr-1" />}
                            {entry.kind}
                          </td>
                          <td className="p-2" style={dw.burg}>
                            {entry.actors.length ? entry.actors.join(', ') : '—'}
                          </td>
                          <td className="p-2" style={dw.text}>{entry.confidence}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="font-mono text-[10px] leading-relaxed" style={dw.faint}>
                  A shared PGP fingerprint or wallet address is the strongest single link in this dataset —
                  handle similarity alone never exceeds 90% confidence.
                </p>
              </div>
            )}

            {tab === 'infrastructure' && (
              <div className="rounded-sm border" style={dw.panel}>
                <div className="px-5 py-3 border-b" style={dw.borderMid}>
                  <SectionTitle icon={Globe}>
                    Infrastructure Correlation — {infraHits.length} record{infraHits.length === 1 ? '' : 's'}
                  </SectionTitle>
                </div>
                <table className="w-full text-[10px] font-mono">
                  <thead>
                    <tr style={dw.canvasMid}>
                      <th className="text-left p-2" style={dw.text}>Value</th>
                      <th className="text-left p-2" style={dw.text}>Type</th>
                      <th className="text-left p-2" style={dw.text}>Actors</th>
                      <th className="text-left p-2" style={dw.text}>Hosting / ASN</th>
                      <th className="text-left p-2" style={dw.text}>Country</th>
                    </tr>
                  </thead>
                  <tbody>
                    {infraHits.map(entry => (
                      <tr key={entry.value} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                        <td className="p-2" style={dw.text}>{entry.value}</td>
                        <td className="p-2" style={dw.muted}>{entry.type}</td>
                        <td className="p-2" style={dw.burg}>{entry.actors.length ? entry.actors.join(', ') : '—'}</td>
                        <td className="p-2" style={dw.muted}>{entry.host ?? '—'} {entry.asn ? `· ${entry.asn}` : ''}</td>
                        <td className="p-2" style={dw.text}>{entry.country ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className="p-4 border-t" style={dw.borderMid}>
                  <Link to="/app/darkweb/infrastructure" className="font-mono text-[10px]" style={dw.burg}>
                    Open full infrastructure analysis →
                  </Link>
                </div>
              </div>
            )}

            {tab === 'behavior' && (
              <div className="space-y-6">
                <div className="rounded-sm border" style={dw.panel}>
                  <div className="px-5 py-3 border-b" style={dw.borderMid}>
                    <SectionTitle icon={Brain}>Attribution Confidence — Stylometry &amp; Behavior</SectionTitle>
                  </div>
                  <div className="divide-y" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    {behaviorPairs
                      .slice()
                      .sort((a, b) => b.stylometry.similarity + b.behavior.overall - (a.stylometry.similarity + a.behavior.overall))
                      .map(pair => {
                        const combined = Math.round((pair.stylometry.similarity + pair.behavior.overall) / 2);
                        return (
                          <div key={`${pair.a.id}-${pair.b.id}`} className="p-4">
                            <div className="flex items-center justify-between gap-3 mb-2">
                              <Link
                                to={`/app/darkweb/actors/${pair.a.id}`}
                                className="font-mono text-xs"
                                style={dw.burg}
                              >
                                {pair.a.aliases[0]} ↔ {pair.b.aliases[0]}
                              </Link>
                              <RelationshipChip type="SHARED_BEHAVIOR" confidence={combined} />
                            </div>
                            <div className="grid md:grid-cols-2 gap-4">
                              <div>
                                <p className="font-mono text-[10px] tracking-widest uppercase mb-1" style={dw.muted}>
                                  Stylometry — {pair.stylometry.similarity}%
                                </p>
                                {pair.stylometry.factors.map(factor => (
                                  <div key={factor.name} className="flex items-start gap-2 text-[10px]">
                                    <span style={factor.matched ? dw.low : dw.faint}>
                                      {factor.matched ? '✓' : '✗'}
                                    </span>
                                    <span style={factor.matched ? dw.text : dw.faint}>
                                      {factor.name} — {factor.detail}
                                    </span>
                                  </div>
                                ))}
                              </div>
                              <div>
                                <p className="font-mono text-[10px] tracking-widest uppercase mb-1" style={dw.muted}>
                                  Behavior — {pair.behavior.overall}%
                                </p>
                                {pair.behavior.factors.map(factor => (
                                  <div key={factor.name} className="flex items-start gap-2 text-[10px]">
                                    <span style={factor.matched ? dw.low : dw.faint}>
                                      {factor.matched ? '✓' : '✗'}
                                    </span>
                                    <span style={factor.matched ? dw.text : dw.faint}>
                                      {factor.name} — {factor.value}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                  </div>
                </div>
              </div>
            )}

            {tab === 'resolution' && (
              <div className="rounded-sm border p-5" style={dw.panel}>
                <SectionTitle icon={Fingerprint}>Entity Resolution</SectionTitle>
                {resolution ? (
                  <div className="space-y-4">
                    <div className="grid md:grid-cols-3 gap-4">
                      <div>
                        <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>
                          Primary entity
                        </p>
                        <Link
                          to={`/app/darkweb/actors/${resolution.primaryActorId}`}
                          className="font-mono text-sm flex items-center gap-1"
                          style={dw.burg}
                        >
                          {resolution.primaryActorId} <ArrowRight size={11} />
                        </Link>
                      </div>
                      <div>
                        <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>
                          Attribution confidence
                        </p>
                        <p className="font-mono text-sm" style={dw.text}>{resolution.confidence}%</p>
                        <div className="mt-1">
                          <ConfidenceBar value={resolution.confidence} label={false} />
                        </div>
                      </div>
                      <div>
                        <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>
                          Classification
                        </p>
                        <p className="font-mono text-[10px] leading-relaxed" style={dw.muted}>
                          {resolution.label}
                        </p>
                      </div>
                    </div>
                    <div>
                      <p className="font-mono text-[10px] tracking-widest uppercase mb-1.5" style={dw.muted}>
                        Supporting indicators
                      </p>
                      <table className="w-full text-[10px] font-mono">
                        <thead>
                          <tr style={dw.canvasMid}>
                            <th className="text-left p-2" style={dw.text}>Source</th>
                            <th className="text-left p-2" style={dw.text}>Indicator</th>
                            <th className="text-left p-2" style={dw.text}>Weight</th>
                          </tr>
                        </thead>
                        <tbody>
                          {resolution.indicators.map((indicator, index) => (
                            <tr key={`${indicator.source}-${index}`} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                              <td className="p-2" style={dw.text}>{indicator.source}</td>
                              <td className="p-2" style={dw.muted}>{indicator.value}</td>
                              <td className="p-2" style={dw.text}>{indicator.weight}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <p className="font-mono text-[10px] leading-relaxed" style={dw.faint}>
                      {resolution.disclaimer}
                    </p>
                  </div>
                ) : (
                  <p className="text-xs" style={dw.muted}>
                    “{query}” does not resolve to an entity in the current dataset.
                  </p>
                )}
              </div>
            )}

            {tab === 'anomalies' && (
              <div className="rounded-sm border" style={dw.panel}>
                <div className="px-5 py-3 border-b" style={dw.borderMid}>
                  <SectionTitle icon={AlertTriangle}>
                    Anomaly Detection — {anomalies.length} finding{anomalies.length === 1 ? '' : 's'}
                  </SectionTitle>
                </div>
                {anomalies.map(anomaly => (
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
              </div>
            )}
          </div>
        </div>
        <ProtectionModulePanel entityType="HANDLE" />
      </div>
    </motion.div>
  );
}
