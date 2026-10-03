// ============================================================
// PhishNet — Natural language search panel.
//
// One component serves both the Investigations list and the AI
// Analysis page; only the endpoint scope differs. Everything the
// panel renders comes from the response: the operations the parser
// applied, the operations it refused, the records that matched, and
// the reason each one qualified.
//
// What the panel deliberately does not do:
//
//  * Present an unparsed question as a result. `unfiltered` renders as
//    "no filter was understood" with the parser's own wording, never
//    as a list of everything.
//  * Hide the operations. A question that produced one match and a
//    question that produced fifty are both auditable, because the
//    applied filters are shown above the results.
//  * Invent prose. There is no template that turns zero matches into a
//    summary of the dataset.
// ============================================================
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Search, Sparkles, TriangleAlert, CircleHelp, Ban, Filter, Loader2, ArrowRight } from 'lucide-react';
import { dw } from '../../lib/darkweb/styles';
import {
  isEmptyResult,
  isUnparsed,
  searchIntelligenceNl,
  searchInvestigationsNl,
  NL_EXAMPLES,
  type NlAnswer,
  type NlEntities,
  type NlReason,
  type NlStatement,
} from '../../lib/intelligence/nlSearch';

function ReasonChip({ reason }: { reason: NlReason }) {
  const color = reason.kind === 'correlation' ? 'var(--tw-brass)' : 'var(--tw-moss)';
  return (
    <span
      className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm border inline-flex items-center gap-1"
      style={{ borderColor: 'var(--tw-border-mid)', color }}
      title={reason.kind === 'correlation' ? 'Computed by joining stored records' : 'Read directly from a stored field'}
    >
      {reason.field}: {reason.matched}
    </span>
  );
}

function OperationList({ answer }: { answer: NlAnswer }) {
  if (!answer.operations.length && !answer.unsupported.length) return null;
  return (
    <div className="space-y-2">
      {answer.operations.length > 0 && (
        <div>
          <p className="font-mono text-[9px] uppercase tracking-widest mb-1 flex items-center gap-1" style={dw.faint}>
            <Filter size={10} /> Applied filters
          </p>
          <ul className="space-y-1">
            {answer.operations.map((operation, index) => (
              <li key={`${operation.kind}-${index}`} className="font-mono text-[10px] flex items-start gap-1.5">
                <span style={{ color: operation.applied ? 'var(--tw-moss)' : 'var(--tw-text-faint)' }}>
                  {operation.applied ? '✓' : '·'}
                </span>
                <span style={operation.applied ? dw.muted : dw.faint}>
                  {operation.label}
                  {!operation.applied && ' — recognised but not applied'}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {answer.unsupported.length > 0 && (
        <div>
          <p className="font-mono text-[9px] uppercase tracking-widest mb-1 flex items-center gap-1" style={{ color: 'var(--tw-brass)' }}>
            <Ban size={10} /> Not used
          </p>
          <ul className="space-y-1">
            {answer.unsupported.map((item, index) => (
              <li key={`${item.clause}-${index}`} className="font-mono text-[10px] leading-relaxed" style={dw.faint}>
                <span style={dw.muted}>{item.clause}</span> — {item.reason}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function StatementList({ title, tone, statements }: { title: string; tone: 'moss' | 'brass'; statements: NlStatement[] }) {
  if (!statements.length) return null;
  return (
    <div>
      <p className="font-mono text-[9px] uppercase tracking-widest mb-1" style={{ color: tone === 'moss' ? 'var(--tw-moss)' : 'var(--tw-brass)' }}>
        {title} · {statements.length}
      </p>
      <ul className="space-y-1.5">
        {statements.map((item, index) => (
          <li key={`${item.sourceId}-${index}`} className="font-mono text-[10px] leading-relaxed" style={dw.muted}>
            <span style={dw.text}>{item.statement}</span>
            {item.integrity && !item.integrity.verified && (
              <span style={{ color: 'var(--tw-brass)' }}> — digest not rechecked against content</span>
            )}
            {Object.values(item.navigation ?? {}).filter(Boolean).length > 0 && (
              <span className="block mt-0.5">
                {Object.entries(item.navigation).filter(([, path]) => path).map(([key, path]) => (
                  <Link key={key} to={path!} className="font-mono text-[9px] mr-2" style={dw.burg}>
                    {key.replace(/Path$/, '')} →
                  </Link>
                ))}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * Flatten the entity buckets into display pairs, dropping the empty ones.
 * The response groups resolved ids by kind, so the panel shows which kinds
 * actually matched rather than an empty "recognised entities" line.
 */
function resolvedEntities(entities: NlEntities): Array<{ kind: string; values: string[] }> {
  const LABELS: Array<[keyof NlEntities, string]> = [
    ['actorIds', 'actor'],
    ['handleValues', 'handle'],
    ['walletAddresses', 'wallet'],
    ['pgpFingerprints', 'pgp'],
    ['infrastructureValues', 'infrastructure'],
    ['ipValues', 'ip'],
    ['domainValues', 'domain'],
    ['evidenceIds', 'evidence'],
    ['relationshipIds', 'relationship'],
    ['investigationIds', 'investigation'],
  ];
  return LABELS
    .map(([key, label]) => ({ kind: label, values: entities[key] as string[] }))
    .filter(entry => entry.values.length > 0);
}

/**
 * Everything the panel shows once an answer exists.
 *
 * Split out from the panel because this is the part that reads the
 * response shape, and the response shape is where this feature is most
 * likely to be wrong: the entity field is a set of grouped buckets, and
 * the two scopes return different structures entirely. Rendering it as a
 * pure function of the answer makes it directly checkable against a
 * recorded response.
 */
export function NlSearchResults({ answer }: { answer: NlAnswer }) {
  return (
    <div className="px-4 pb-4 space-y-3">
      <OperationList answer={answer} />

      {/* Unparsed: say so, show nothing that looks like a result. */}
      {isUnparsed(answer) ? (
        <div className="p-2.5 rounded-sm border font-mono text-[10px] flex items-start gap-2"
          style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-brass)' }}>
          <CircleHelp size={12} style={{ color: 'var(--tw-brass)', flexShrink: 0 }} />
          <span style={dw.muted}>
            <span style={{ color: 'var(--tw-brass)' }}>No filter was understood.</span>{' '}
            {answer.operations.length === 0 && answer.unsupported.length === 0
              ? 'Nothing in this question mapped to a stored field.'
              : 'The clauses above were recognised but could not be applied, so no records were selected.'}{' '}
            {answer.scope === 'investigations' && `${answer.evaluated} stored investigations were left untouched. Rephrase using a status, severity, actor, indicator, or time window.`}
            {answer.scope === 'ai' && 'Name an actor, investigation, indicator, wallet, or a filter such as status, severity or recency.'}
          </span>
        </div>
      ) : isEmptyResult(answer) ? (
        <div className="p-2.5 rounded-sm border font-mono text-[10px] flex items-start gap-2"
          style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
          <CircleHelp size={12} style={{ color: 'var(--tw-text-faint)', flexShrink: 0 }} />
          <span style={dw.muted}>
            <span style={dw.text}>No records match.</span>{' '}
            {answer.scope === 'investigations'
              ? `0 matches out of ${answer.evaluated} stored investigations. Every filter above was applied.`
              : 'Every filter above was applied and no stored record satisfies it. This is an empty result, not a failure.'}
          </span>
        </div>
      ) : (
        <>
          {answer.scope === 'investigations' ? (
            <div className="space-y-2">
              <p className="font-mono text-[9px] uppercase tracking-widest" style={dw.faint}>
                {answer.matches.length} match{answer.matches.length === 1 ? '' : 'es'} of {answer.evaluated} stored investigations
                {answer.truncated && ' (list capped)'}
              </p>
              <ul className="space-y-2">
                {answer.matches.map(match => (
                  <li key={match.id} className="rounded-sm border p-3" style={dw.panelBorder}>
                    <div className="flex flex-wrap items-baseline justify-between gap-2">
                      <Link to={match.navigation.investigationPath ?? '/app/darkweb/investigations'} style={{ ...dw.text, textDecoration: 'none' }}>
                        <span style={dw.burg}>{match.id}</span> · <span className="font-mono text-[11px]">{match.title}</span>
                      </Link>
                      <span className="font-mono text-[9px]" style={dw.faint}>
                        {match.status} · confidence {match.confidence} · {match.evidenceCount} evidence · {match.entityCount} entities
                        {match.unverifiedEvidenceCount > 0 && ` · ${match.unverifiedEvidenceCount} digest not rechecked`}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {match.reasons.map((reason, index) => (
                        <ReasonChip key={`${reason.field}-${index}`} reason={reason} />
                      ))}
                    </div>
                    <div className="flex flex-wrap gap-2 mt-1.5 font-mono text-[9px]" style={dw.faint}>
                      {match.sourceRecords.evidenceIds.length > 0 && <span>evidence: {match.sourceRecords.evidenceIds.join(', ')}</span>}
                      {match.sourceRecords.actorIds.length > 0 && <span>actors: {match.sourceRecords.actorIds.join(', ')}</span>}
                      <Link to={match.navigation.investigationPath ?? '#'} style={dw.burg}>
                        open case <ArrowRight size={9} className="inline" />
                      </Link>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="space-y-3">
              <p className="font-mono text-[9px]" style={dw.faint}>
                {answer.answerKind.toLowerCase()} · {answer.total} statement(s) · {answer.note}
              </p>
              {answer.matchedInvestigations.length > 0 && (
                <div>
                  <p className="font-mono text-[9px] uppercase tracking-widest mb-1" style={dw.faint}>
                    Matching investigations · {answer.matchedInvestigations.length}
                  </p>
                  <ul className="space-y-1.5">
                    {answer.matchedInvestigations.map(ref => (
                      <li key={ref.id} className="font-mono text-[10px]">
                        <Link to={ref.navigation.investigationPath ?? '#'} style={{ ...dw.text, textDecoration: 'none' }}>
                          <span style={dw.burg}>{ref.id}</span> · <span style={dw.muted}>{ref.title}</span>
                        </Link>
                        <span className="block mt-0.5 flex flex-wrap gap-1">
                          {ref.reasons.map((reason, index) => (
                            <ReasonChip key={`${reason.field}-${index}`} reason={reason} />
                          ))}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <StatementList title="Observed (stored fields)" tone="moss" statements={answer.observed} />
              <StatementList title="Correlation (joined records)" tone="brass" statements={answer.correlation} />
              {answer.inference.length > 0 ? (
                <StatementList title="Inference" tone="brass" statements={answer.inference} />
              ) : (
                <p className="font-mono text-[9px]" style={dw.faint}>
                  No inference is offered: this endpoint reads stored records and joins them, and calls no language
                  model. Every line above is either a stored field or a join of stored records.
                </p>
              )}
            </div>
          )}
        </>
      )}

      {resolvedEntities(answer.entities).length > 0 && (
        <p className="font-mono text-[9px]" style={dw.faint}>
          Recognised entities: {resolvedEntities(answer.entities).map(entry => `${entry.kind}: ${entry.values.join(', ')}`).join(' · ')}
          {answer.entities.unresolvedIds.length > 0 && (
            <span style={{ color: 'var(--tw-brass)' }}>
              {' '}Not used as a filter (no such record): {answer.entities.unresolvedIds.join(', ')}
            </span>
          )}
        </p>
      )}
    </div>
  );
}

export function NlSearchPanel({
  scope,
  placeholder,
  autoFocus = false,
  onResult,
}: {
  scope: 'investigations' | 'ai';
  placeholder: string;
  autoFocus?: boolean;
  /** Called with the answer so the host page can mirror the matches into its own list. */
  onResult?: (answer: NlAnswer) => void;
}) {
  const [query, setQuery] = useState('');
  const [answer, setAnswer] = useState<NlAnswer | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(event: React.FormEvent) {
    event.preventDefault();
    if (!query.trim()) return;
    setPending(true);
    setError(null);
    try {
      const result = scope === 'ai' ? await searchIntelligenceNl(query) : await searchInvestigationsNl(query);
      setAnswer(result);
      onResult?.(result);
    } catch (caught) {
      // A failed search is reported as a failure. Nothing is displayed in
      // place of a result set.
      setAnswer(null);
      setError(caught instanceof Error ? caught.message : 'The search could not be completed');
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="rounded-sm border" style={dw.panel}>
      <div className="px-4 py-3 border-b flex items-center justify-between gap-2" style={dw.borderMid}>
        <div className="flex items-center gap-2" style={dw.muted}>
          <Sparkles size={13} />
          <p className="font-mono text-[10px] tracking-widest uppercase">Ask the case</p>
        </div>
        <span className="font-mono text-[9px]" style={dw.faint}>
          {scope === 'ai' ? 'whole intelligence model' : 'investigations & cases'}
        </span>
      </div>

      <form onSubmit={run} className="p-4 space-y-3">
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input
              value={query}
              onChange={event => setQuery(event.target.value)}
              placeholder={placeholder}
              autoFocus={autoFocus}
              className="w-full font-mono text-[11px] pl-7 pr-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}
            />
          </div>
          <button
            type="submit"
            disabled={pending || !query.trim()}
            className="font-mono text-[10px] px-3 py-1.5 rounded-sm border flex items-center gap-1.5 justify-center disabled:opacity-60"
            style={{ backgroundColor: 'var(--tw-burgundy)', borderColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
          >
            {pending ? <Loader2 size={11} className="animate-spin" /> : <Search size={11} />}
            {pending ? 'Searching…' : 'Search'}
          </button>
        </div>

        {!answer && !error && (
          <div className="flex flex-wrap gap-1.5">
            {NL_EXAMPLES.slice(0, 4).map(example => (
              <button
                key={example}
                type="button"
                onClick={() => setQuery(example)}
                className="font-mono text-[9px] px-2 py-0.5 rounded-sm border"
                style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-faint)' }}
              >
                {example}
              </button>
            ))}
          </div>
        )}
      </form>

      {error && (
        <div className="px-4 pb-4">
          <div className="p-2.5 rounded-sm border font-mono text-[10px] flex items-start gap-2"
            style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-critical)' }}>
            <TriangleAlert size={12} style={{ color: 'var(--tw-critical)', flexShrink: 0 }} />
            <span style={dw.muted}>
              <span style={{ color: 'var(--tw-critical)' }}>Search failed.</span> {error} No result is shown because
              none was produced.
            </span>
          </div>
        </div>
      )}

      {answer && <NlSearchResults answer={answer} />}
    </div>
  );
}