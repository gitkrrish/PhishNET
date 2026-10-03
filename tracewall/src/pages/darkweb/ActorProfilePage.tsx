import { useState, Fragment } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Key, Wallet, Server, Clock, BarChart2, Users, Link2, Database, Activity, Sparkle, ChevronLeft, FileText, Globe, Brain, Fingerprint } from 'lucide-react';
import { ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { type ThreatActor } from '../../data/darkWebData';
import { stylometricSimilarity, behavioralAnalysis, explainRelationship, resolveEntity } from '../../lib/darkweb/aiEngine';
import { ThreatActorCard } from '../../components/darkweb/ThreatActorCard';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { EvidenceItem } from '../../components/darkweb/EvidenceItem';
import { RelationshipChip } from '../../components/darkweb/RelationshipChip';
import { ConfidenceRing } from '../../components/darkweb/ConfidenceRing';
import { CorrelationMatrix } from '../../components/darkweb/CorrelationMatrix';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { AiAssistant } from '../../components/darkweb/AiAssistant';
import { MonitorEntityButton } from '../../components/darkweb/MonitorEntityButton';
import { ProtectionPanel } from '../../components/darkweb/ProtectionPanel';

type TabIcon = React.ComponentType<{ size?: number; className?: string }>;

const TAB_ICONS: Record<string, TabIcon> = {
  Overview: BarChart2, Identity: Link2, Activity: Activity, Infrastructure: Server,
  Relationships: Users, Timeline: Clock, Evidence: Database, 'AI Analysis': Sparkle,
};

export default function ActorProfilePage() {
  const { id } = useParams<{ id: string }>();
  const { darkWebActorsById, darkWebEvidenceById, darkWebEvidence, darkWebPgpKeys, darkWebWallets, darkWebInfrastructure, darkWebRelationships, darkWebTimeline } = useIntelligenceData();
     const actor = id ? (darkWebActorsById[id] ?? darkWebActorsById[id.replace(/^ACT/, 'ACTOR-')]) : undefined;
   const navigate = useNavigate();
   const [activeTab, setActiveTab] = useState('Overview');

   if (!actor) {
    return (
      <div className="min-h-screen page-enter" style={sectionStyle()}>
        <div className="max-w-3xl mx-auto px-6 lg:px-10 py-16 text-center" style={dw.text}>
          <Shield size={40} className="mx-auto mb-4" style={dw.muted} />
          <h2 className="font-serif text-2xl mb-2">Actor Not Found</h2>
          <p style={dw.muted}>The requested threat actor does not exist in the dataset.</p>
          <button onClick={() => navigate('/app/darkweb/actors')} className="mt-4 font-mono text-xs px-4 py-2 rounded-sm border" style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}>← Back to Actors</button>
        </div>
      </div>
    );
  }

  const tabs = ['Overview', 'Identity', 'Activity', 'Infrastructure', 'Relationships', 'Timeline', 'Evidence', 'AI Analysis'];

  // Derived data
  const relatedActors = actor.relatedActorIds.map(rid => darkWebActorsById[rid]).filter(Boolean);
  const actorEvidence = actor.associatedEvidence;
  const relatedRels = darkWebRelationships.filter(r => r.sourceEntity === actor.id || r.targetEntity === actor.id || actor.handles.some(h => h === r.sourceEntity || h === r.targetEntity));
  const timeline = darkWebTimeline.filter(t => t.actorId === actor.id);
  const infra = darkWebInfrastructure.filter(i => i.actorIds.includes(actor.id));
  const pgpKeys = actor.pgpFingerprints.map(fp => darkWebPgpKeys.find(k => k.fingerprint === fp)).filter(Boolean);
  const wallets = actor.walletAddrs.map(a => darkWebWallets.find(w => w.address === a)).filter(Boolean);

  const activityHeatmap = actor.behavioralProfile.activeHours;
  const relatedActorSim = relatedActors.map(ra => {
    const sim = stylometricSimilarity(actor, ra);
    const beh = behavioralAnalysis(actor, ra);
    return { id: ra.id, alias: ra.aliases[0], stylometry: sim.similarity, behavior: beh.overall, confidence: ra.confidenceScore };
  });

  const radarData = actor.behavioralProfile.platformPreferences.map(p => ({ platform: p.platform.slice(0, 8), weight: p.weight }));
  // ensure at least 3 points for radar
  while (radarData.length < 3) radarData.push({ platform: '—', weight: 0 });

  const renderTab = (tab: string) => {
    switch (tab) {
      case 'Overview':
        return (
          <div className="space-y-6">
            <div className="grid md:grid-cols-3 gap-5">
              <div className="rounded-sm border p-4 text-center" style={dw.panel}><p className="font-mono text-[10px] uppercase" style={dw.muted}>Confidence</p><ConfidenceRing value={actor.confidenceScore} label="Overall" /></div>
              <div className="rounded-sm border p-4 text-center" style={dw.panel}>
                <p className="font-mono text-[10px] uppercase" style={dw.muted}>Status</p>
                <p className="font-serif text-2xl mt-2" style={{ color: actor.status === 'ACTIVE' ? 'var(--tw-critical)' : actor.status === 'DORMANT' ? 'var(--tw-medium)' : 'var(--tw-dust)' }}>{actor.status}</p>
                <p className="font-mono text-[10px]" style={dw.muted}>{actor.primaryMotivation}</p>
              </div>
              <div className="rounded-sm border p-4 text-center" style={dw.panel}>
                <p className="font-mono text-[10px] uppercase" style={dw.muted}>Related Actors</p>
                <p className="font-serif text-2xl mt-2" style={dw.burg}>{relatedActors.length}</p>
              <div className="flex gap-1 justify-center mt-1">{relatedActors.map(a => <span key={a.id} className="font-mono text-[9px]" style={dw.muted}>{a.id}</span>)}</div>
               </div>
             </div>

            <ProtectionPanel entityType="ACTOR" entityId={actor.id} title="Threat Protection & Response" />

            <div className="grid md:grid-cols-2 gap-5">
               <div className="rounded-sm border p-4" style={dw.panel}>
                 <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Behavioral Profile</p>
                <div className="space-y-2 text-[11px]">
                  <div><span style={dw.faint}>Frequency</span><span className="font-mono" style={dw.text}> {actor.behavioralProfile.activityFrequency} ({actor.behavioralProfile.postingFrequency}/wk)</span></div>
                  <div><span style={dw.faint}>Interaction</span><span className="font-mono" style={dw.text}> {actor.behavioralProfile.interactionPattern}</span></div>
                  <div><span style={dw.faint}>Topic clusters</span><span className="font-mono" style={dw.text}> {actor.behavioralProfile.topicClusters.join(', ')}</span></div>
                </div>
              </div>
              <div className="rounded-sm border p-4" style={dw.panel}>
                <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Active Hours Heatmap</p>
                <div className="grid grid-cols-6 gap-1">
                  {Array.from({ length: 24 }).map((_, h) => {
                    const level = actor.behavioralProfile.activeHours.find(a => a.hour === h)?.level ?? 0;
                    return <div key={h} className="font-mono text-[8px] text-center" style={{ backgroundColor: level ? `color-mix(in srgb, var(--tw-burgundy) ${level}%, transparent)` : 'var(--tw-canvas-mid)', color: level ? 'var(--tw-panel)' : 'var(--tw-text-faint)', padding: '4px 2px', borderRadius: '2px' }}>{h}</div>;
                  })}
                </div>
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-5">
              <div className="rounded-sm border p-4" style={dw.panel}>
                <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Platform Preferences</p>
                <ResponsiveContainer width="100%" height={140}>
                  <RadarChart data={radarData} margin={{ top: 5, right: 5, bottom: 5, left: 5 }}>
                    <PolarGrid />
                    <PolarAngleAxis dataKey="platform" tick={{ fontSize: 9, fill: 'var(--tw-text-muted)' }} />
                    <PolarRadiusAxis angle={30} tick={{ fontSize: 8, fill: 'var(--tw-text-faint)' }} />
                    <Radar dataKey="weight" stroke="var(--tw-burgundy)" fill="var(--tw-burgundy)" fillOpacity={0.35} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
              <div className="rounded-sm border p-4" style={dw.panel}>
                <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Stylometric Sample</p>
                <blockquote className="text-sm italic" style={dw.muted}>"{actor.stylometricProfile.sampleText}"</blockquote>
                <div className="grid grid-cols-2 gap-2 mt-2 text-[10px]">
                  <div><span style={dw.faint}>Avg sentence</span><span className="font-mono" style={dw.text}> {actor.stylometricProfile.avgSentenceLength} words</span></div>
                  <div><span style={dw.faint}>Vocab richness</span><span className="font-mono" style={dw.text}> {(actor.stylometricProfile.vocabularyRichness * 100).toFixed(0)}%</span></div>
                </div>
              </div>
            </div>

            {relatedActorSim.length > 0 && (
              <div className="rounded-sm border p-4" style={dw.panel}>
                <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Related Actor Similarity</p>
                <div className="overflow-x-auto">
                  <table className="w-full text-[10px] font-mono">
                    <thead><tr style={dw.canvasMid}><th className="text-left p-2" style={dw.text}>Actor</th><th className="text-left p-2" style={dw.text}>Stylometry</th><th className="text-left p-2" style={dw.text}>Behavior</th><th className="text-left p-2" style={dw.text}>Confidence</th></tr></thead>
                    <tbody>
                      {relatedActorSim.map(r => (
                        <tr key={r.id} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                          <td className="p-2" style={dw.text}>{r.id} ({r.alias})</td>
                          <td className="p-2" style={dw.text}>{r.stylometry}%</td>
                          <td className="p-2" style={dw.text}>{r.behavior}%</td>
                          <td className="p-2" style={dw.text}>{r.confidence}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        );
      case 'Identity':
        return (
          <div className="space-y-5">
            <div className="rounded-sm border p-4" style={dw.panel}>
              <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Identity Resolution</p>
              {(() => { const res = resolveEntity(actor.handles[0]); return (
                <div className="space-y-2">
                  <p className="font-mono text-sm" style={dw.critical}>{res.label}</p>
                  <p className="text-xs" style={dw.muted}>{res.disclaimer}</p>
                  <div><ConfidenceBar value={res.confidence} />
                    <p className="font-mono text-[10px] mt-1" style={dw.faint}>Primary entity: {res.primaryActorId}</p>
                  </div>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {res.indicators.map((ind, i) => (
                      <span key={i} className="font-mono text-[9px] px-2 py-0.5 rounded-sm border" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-brass) 18%, transparent)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-brass)' }}>{ind.source}: {ind.value} ({ind.weight}%)</span>
                    ))}
                  </div>
                </div>
              ); })()}
            </div>
            <CorrelationMatrix actorIds={[actor.id]} />
            <div className="grid md:grid-cols-2 gap-4">
              <div className="rounded-sm border p-3" style={dw.panel}>
                <p className="font-mono text-[10px] uppercase" style={dw.muted}>Handles ({actor.handles.length})</p>
                <div className="flex flex-wrap gap-1.5 mt-1">{actor.handles.map(h => <span key={h} className="font-mono text-xs px-2 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-burgundy) 18%, transparent)', color: 'var(--tw-burgundy)' }}>{h}</span>)}</div>
              </div>
              <div className="rounded-sm border p-3" style={dw.panel}>
                <p className="font-mono text-[10px] uppercase" style={dw.muted}>PGP Fingerprints ({actor.pgpFingerprints.length})</p>
                <div className="flex flex-col gap-1 mt-1 font-mono text-xs break-all" style={dw.text}>{actor.pgpFingerprints.map(fp => <span key={fp} style={{ wordBreak: 'break-all' }}>{fp}</span>)}</div>
              </div>
              <div className="rounded-sm border p-3" style={dw.panel}>
                <p className="font-mono text-[10px] uppercase" style={dw.muted}>Wallet Addresses ({actor.walletAddrs.length})</p>
                <div className="flex flex-col gap-1 mt-1 font-mono text-xs break-all" style={dw.text}>{actor.walletAddrs.map(w => <span key={w}>{w}</span>)}</div>
              </div>
              <div className="rounded-sm border p-3" style={dw.panel}>
                <p className="font-mono text-[10px] uppercase" style={dw.muted}>Domains ({actor.domains.length})</p>
                <div className="flex flex-wrap gap-1.5 mt-1">{actor.domains.map(d => <span key={d} className="font-mono text-xs px-2 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-medium) 18%, transparent)', color: 'var(--tw-medium)' }}>{d}</span>)}</div>
              </div>
            </div>
            <div className="rounded-sm border p-3" style={dw.panel}>
              <p className="font-mono text-[10px] uppercase" style={dw.muted}>Platforms</p>
              <div className="flex flex-wrap gap-1.5 mt-1">{actor.platforms.map(p => <span key={p} className="font-mono text-xs px-2 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-info) 18%, transparent)', color: 'var(--tw-info)' }}>{p}</span>)}</div>
            </div>
          </div>
        );
      case 'Activity':
        return (
          <div className="space-y-6">
            <div className="rounded-sm border p-4" style={dw.panel}>
              <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Posting Frequency Trend</p>
              <p className="text-xs mb-2" style={dw.muted}>Actor posts at a baseline of {actor.behavioralProfile.postingFrequency}/week with peak bursts around {actor.behavioralProfile.activeHours[0]?.hour ?? 2}:00 UTC.</p>
              <div className="grid grid-cols-24 gap-0.5">
                {Array.from({ length: 24 }).map((_, h) => {
                  const level = actor.behavioralProfile.activeHours.find(a => a.hour === h)?.level ?? 0;
                  return <div key={h} className="h-5 rounded-sm" style={{ backgroundColor: level ? `color-mix(in srgb, var(--tw-burgundy) ${level}%, transparent)` : 'var(--tw-canvas-mid)' }}></div>;
                })}
              </div>
              <p className="font-mono text-[9px] mt-2" style={dw.faint}>Peak activity at 02:00–03:00 UTC (consistent with ACTOR-003 migration).</p>
            </div>
            <div className="rounded-sm border p-4" style={dw.panel}>
              <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Activity Heatmap (24h)</p>
              <div className="grid grid-cols-8 gap-1 text-[8px]">
                {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((d, di) => (
                  <Fragment key={d}>{Array.from({ length: 7 }).map((_, h) => {
                    const level = ((di * 7 + h) % 24 === (actor.behavioralProfile.activeHours[0]?.hour ?? 2) || ((di * 7 + h) % 24) === 14) ? 70 : 20;
                    return <div key={h} className="aspect-square rounded-sm" style={{ backgroundColor: `color-mix(in srgb, var(--tw-burgundy) ${level}%, transparent)` }}></div>;
                  })}</Fragment>
                ))}
              </div>
            </div>
            <div className="rounded-sm border p-4" style={dw.panel}>
              <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Topic Engagement</p>
              <div className="space-y-2">{actor.behavioralProfile.topicClusters.map(t => <div key={t}><span className="font-mono text-xs" style={dw.text}>{t}</span><div className="h-2 rounded-sm mt-0.5" style={{ backgroundColor: 'var(--tw-border-mid)', width: `${70 + Math.random() * 30}%` }}></div></div>)}</div>
            </div>
          </div>
        );
      case 'Infrastructure':
        return (
          <div className="space-y-5">
            {infra.length === 0 ? <p style={dw.muted}>No infrastructure observed for this actor.</p> : (
              <div className="grid md:grid-cols-2 gap-4">
                {infra.map(i => (
                  <div key={i.id} className="rounded-sm border p-4" style={dw.panel}>
                    <div className="flex items-center gap-2 mb-2"><Server size={13} style={dw.burg} /><span className="font-mono text-xs" style={dw.text}>{i.type}</span></div>
                    <p className="font-mono text-sm break-all" style={dw.text}>{i.value}</p>
                    <div className="grid grid-cols-2 gap-1 mt-2 text-[10px]">
                      {i.firstSeen && <div><span style={dw.faint}>First seen</span><span className="font-mono" style={dw.text}> {new Date(i.firstSeen).toLocaleDateString()}</span></div>}
                      {i.hostingProvider && <div><span style={dw.faint}>Hosting</span><span className="font-mono" style={dw.text}> {i.hostingProvider}</span></div>}
                      {i.asn && <div><span style={dw.faint}>ASN</span><span className="font-mono" style={dw.text}> {i.asn}</span></div>}
                      {i.country && <div><span style={dw.faint}>Country</span><span className="font-mono" style={dw.text}> {i.country}</span></div>}
                      {i.tlsIssuer && <div><span style={dw.faint}>TLS Issuer</span><span className="font-mono" style={dw.text}> {i.tlsIssuer}</span></div>}
                    </div>
                  </div>
                ))}
              </div>
            )}
            <Link to="/app/darkweb/graph" className="font-mono text-xs" style={dw.burg}>→ Open infrastructure in Relationship Graph</Link>
          </div>
        );
      case 'Relationships':
        return (
          <div className="space-y-4">
            {relatedRels.length === 0 ? <p style={dw.muted}>No relationships.</p> : relatedRels.map(r => {
              const exp = explainRelationship(r.id);
              return (
                <div key={r.id} className="rounded-sm border p-4" style={dw.panel}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <RelationshipChip type={r.type} confidence={r.confidence} />
                      <p className="font-mono text-sm" style={dw.text}>{r.sourceEntity} <span style={dw.burg}>→</span> {r.targetEntity}</p>
                      <p className="text-xs" style={dw.muted}>{r.explanation}</p>
                    </div>
                    <ConfidenceRing value={r.confidence} label="Conf" />
                  </div>
                  {exp && (
                    <div className="mt-3 grid md:grid-cols-2 gap-3 text-[10px]">
                      <div>
                        <p className="font-mono uppercase" style={dw.muted}>Supporting</p>
                        <ul className="list-disc list-inside" style={dw.faint}>{exp.supporting.map(s => <li key={s}>{s}</li>)}</ul>
                      </div>
                      <div>
                        <p className="font-mono uppercase" style={dw.muted}>Against</p>
                        <ul className="list-disc list-inside" style={dw.faint}>{exp.against.map(s => <li key={s}>{s}</li>)}</ul>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        );
      case 'Timeline':
        return (
          <div className="space-y-4">
            {timeline.length === 0 ? <p style={dw.muted}>No timeline events.</p> : timeline.map(e => (
              <div key={e.id} className="flex gap-4">
                <div className="flex flex-col items-center shrink-0">
                  <div className="w-2 h-2 rounded-full mt-1" style={{ color: 'var(--tw-burgundy)' }} />
                  <div className="w-px flex-1 mt-1" style={{ backgroundColor: 'var(--tw-border-mid)' }} />
                </div>
                <div className="pb-4">
                  <div className="flex items-center gap-2"><span className="font-mono text-[9px] uppercase px-1.5 py-0.25 rounded-sm" style={{ color: 'var(--tw-burgundy)', backgroundColor: 'color-mix(in srgb, var(--tw-burgundy) 18%, transparent)' }}>{e.type.replace('_', ' ')}</span>
                    <span className="font-mono text-[10px]" style={dw.faint}>{new Date(e.time).toLocaleString()}</span>
                  </div>
                  <p className="text-sm" style={dw.text}>{e.title}</p>
                  <p className="font-mono text-[10px]" style={dw.muted}>{e.description}</p>
                </div>
              </div>
            ))}
          </div>
        );
      case 'Evidence':
        return (
          <div className="space-y-3">{actorEvidence.map(eid => { const ev = darkWebEvidenceById[eid]; return ev ? <EvidenceItem key={ev.id} evidence={ev} siblings={darkWebEvidence} /> : null; })}</div>
        );
      case 'AI Analysis':
        return (
          <div className="space-y-5">
            <div className="rounded-sm border p-4" style={dw.panel}>
              <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Stylometric Similarity — Related Actors</p>
              <div className="space-y-3">
                {relatedActors.map(ra => { const sim = stylometricSimilarity(actor, ra); return (
                  <div key={ra.id} className="rounded-sm border p-3" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                    <div className="flex items-center justify-between mb-1"><span className="font-mono text-xs" style={dw.text}>vs {ra.id} ({ra.aliases[0]})</span><span style={{ color: confidenceRingColor(sim.similarity) }}>{sim.similarity}%</span></div>
                    <ConfidenceBar value={sim.similarity} label={false} />
                    <div className="grid md:grid-cols-2 gap-2 mt-2 text-[10px]">
                      {sim.factors.map(f => <div key={f.name} className="flex justify-between"><span style={dw.muted}>{f.name}</span><span style={dw.text}>{f.matched ? '✓' : '✗'} {f.detail}</span></div>)}
                    </div>
                  </div>
                ); })}
              </div>
            </div>
            <div className="rounded-sm border p-4" style={dw.panel}>
              <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Behavioral Similarity — Related Actors</p>
              <div className="space-y-3">
                {relatedActors.map(ra => { const beh = behavioralAnalysis(actor, ra); return (
                  <div key={ra.id} className="rounded-sm border p-3" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                    <div className="flex items-center justify-between mb-1"><span className="font-mono text-xs" style={dw.text}>vs {ra.id}</span><span style={{ color: confidenceRingColor(beh.overall) }}>{beh.overall}%</span></div>
                    <div className="grid md:grid-cols-2 gap-2 text-[10px]">
                      {beh.factors.map(f => <div key={f.name} className="flex justify-between"><span style={dw.muted}>{f.name}</span><span style={dw.text}>{f.matched ? '✓' : '✗'}</span></div>)}
                    </div>
                  </div>
                ); })}
              </div>
            </div>
            <div className="rounded-sm border p-4" style={dw.panel}>
              <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>AI Assistant</p>
              <AiAssistant contextActorId={actor.id} />
            </div>
          </div>
        );
      default: return null;
    }
  };

  return (
    <div className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <button onClick={() => navigate('/app/darkweb/actors')} className="font-mono text-[10px] flex items-center gap-1" style={dw.muted}><ChevronLeft size={12} /> Back to Threat Actors</button>

        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2"><Shield size={16} style={dw.critical} /><span className="font-mono text-[10px] tracking-wider" style={dw.burg}>{actor.id}</span><DemoLabel /><MonitorEntityButton entityType="ACTOR" entityId={actor.id} entityLabel={actor.aliases[0]} targetType="ACTOR" /></div>
            <h1 className="font-serif text-3xl" style={dw.text}>{actor.aliases[0]}</h1>
            <p className="text-sm max-w-2xl" style={dw.muted}>{actor.primaryMotivation}. Active on {actor.platforms.length} platforms. First seen {new Date(actor.firstSeen).toLocaleDateString()}.</p>
          </div>
        </div>

        <div className="rounded-sm border overflow-x-auto" style={dw.panel}>
          <div className="flex items-center" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
            {tabs.map(t => { const Icon = TAB_ICONS[t]; const active = activeTab === t; return (
              <button key={t} onClick={() => setActiveTab(t)} type="button"
                className="flex items-center gap-1.5 px-4 py-3 font-mono text-xs transition-all border-b-2"
                style={{ borderBottomColor: active ? 'var(--tw-burgundy)' : 'transparent', color: active ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)' }}>
                {<Icon size={12} />} {t}
              </button>
            );})}
          </div>
          <div className="p-5">{renderTab(activeTab)}</div>
        </div>

        {/* Actor-centric workflow — everything downstream of this profile */}
        <div className="rounded-sm border p-5" style={dw.panel}>
          <div className="flex items-center gap-2 mb-3" style={dw.muted}>
            <Link2 size={13} />Continue from {actor.id}
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {[
              { label: 'Identity Correlation',  hint: `Correlate ${actor.handles[0] ?? actor.id} against every collected identity`, to: `/app/darkweb/correlation?actor=${actor.id}`, icon: Users },
              { label: 'AI Analysis',           hint: 'Explainable insights, extraction and discovery for this actor', to: `/app/darkweb/ai?actor=${actor.id}`, icon: Sparkle },
              { label: 'Relationship Graph',    hint: 'This actor in the shared relationship graph', to: `/app/darkweb/graph?focus=${actor.id}`, icon: Link2 },
              { label: 'Actor Timeline',        hint: 'Collection and change history for this actor', to: `/app/darkweb/timeline?actor=${actor.id}`, icon: Clock },
              { label: 'Evidence Locker',       hint: 'Evidence attributed to this actor', to: `/app/darkweb/evidence?actor=${actor.id}`, icon: Database },
              { label: 'Open Investigations',   hint: 'Investigations seeded from this actor', to: '/app/darkweb/investigations', icon: Activity },
            ].map(l => (
              <Link key={l.label} to={l.to} className="rounded-sm border p-3 transition-colors"
                style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)', textDecoration: 'none' }}
                onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
                onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'var(--tw-canvas-mid)')}
              >
                <div className="flex items-center gap-2">
                  <l.icon size={13} style={{ color: 'var(--tw-burgundy)' }} />
                  <span className="text-xs font-medium" style={dw.text}>{l.label}</span>
                </div>
                <p className="font-mono text-[10px] mt-1 leading-relaxed" style={dw.faint}>{l.hint}</p>
              </Link>
            ))}
          </div>
        </div>

        <ThreatActorCard actor={actor} />
      </div>
    </div>
  );
}

function confidenceRingColor(conf: number): string {
  return conf >= 90 ? 'var(--tw-critical)' : conf >= 75 ? 'var(--tw-high)' : conf >= 60 ? 'var(--tw-medium)' : 'var(--tw-low)';
}
