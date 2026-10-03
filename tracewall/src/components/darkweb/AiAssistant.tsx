// ============================================================
// PhishNet — AI Investigation Assistant.
//
// Answers come from the backend, which reads the centralized intelligence
// records. Nothing is answered from the browser, and every answer keeps the
// three categories apart:
//
//   observed   — a stored record says so
//   derived    — computed from stored records by a documented rule
//   inference  — model interpretation, shown only when the backend
//                produced one, and always labelled
//
// When the backend cannot answer from records, the UI says that instead of
// filling the gap.
// ============================================================
import { useState } from 'react';
import { dw } from '../../lib/darkweb/styles';
import { Send, Bot, User, Sparkle, Loader2, Database, GitCompare, Cpu } from 'lucide-react';
import { askInvestigation, type AiAnswer } from '../../lib/intelligence/monitoring';

interface AiAssistantProps {
  contextActorId?: string;
  investigationId?: string;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
  sources: string[];
  type: 'observed' | 'derived' | 'interpretation';
  ts: string;
  answer?: AiAnswer;
}

const TYPE_META = {
  observed: { label: 'OBSERVED DATA', color: 'var(--tw-low)', icon: Database },
  derived: { label: 'DERIVED (computed from records)', color: 'var(--tw-info)', icon: GitCompare },
  interpretation: { label: 'AI INFERENCE', color: 'var(--tw-brass)', icon: Cpu },
} as const;

export function AiAssistant({ contextActorId }: AiAssistantProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content:
        'I answer from the centralized intelligence records held by the backend. Ask about actors, handles, links, infrastructure or summaries. ' +
        'Every answer separates stored facts from computed relationships and from model inference.',
      sources: [],
      type: 'observed',
      ts: new Date().toISOString(),
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const suggested = [
    `What indicators are associated with ${contextActorId ?? 'ACTOR-001'}?`,
    `Why are ACTOR-001 and ACTOR-003 linked?`,
    `Summarize what changed for ${contextActorId ?? 'ACTOR-001'}.`,
    'Show the infrastructure recorded for ACTOR-001.',
    'Which entities have no recorded relationships?',
  ];

  const send = async (text: string) => {
    const question = text.trim();
    if (!question || loading) return;
    setMessages(m => [...m, { role: 'user', content: question, sources: [], type: 'observed', ts: new Date().toISOString() }]);
    setLoading(true);
    setError(null);
    try {
      const answer = await askInvestigation(question, contextActorId, true);
      // The bucket with the most content is the headline category; the full
      // breakdown stays attached so the user can see the separation.
      const headline = !answer.answered
        ? 'observed'
        : answer.inference.available && answer.observed.length === 0
          ? 'interpretation'
          : answer.derived.length > 0 ? 'derived' : 'observed';
      setMessages(m => [...m, { role: 'assistant', content: answer.answer, sources: answer.observed.map(o => o.sourceId).filter((id): id is string => Boolean(id)), type: headline, ts: new Date().toISOString(), answer }]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setMessages(m => [...m, {
        role: 'assistant',
        content: 'The backend could not answer this question. No answer was generated from records.',
        sources: [],
        type: 'observed',
        ts: new Date().toISOString(),
      }]);
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    const question = input;
    setInput('');
    void send(question);
  };

  return (
    <div className="flex flex-col h-[560px] rounded-sm border" style={dw.panel}>
      <div className="px-4 py-3 border-b flex items-center gap-2" style={dw.borderMid}>
        <Bot size={16} style={dw.critical} />
        <span className="font-mono text-xs font-medium" style={dw.text}>AI Investigation Assistant</span>
        <span className="ml-auto font-mono text-[10px]" style={dw.muted}><Sparkle size={10} /> Backend · records only</span>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.map((message, index) => {
          const meta = TYPE_META[message.type];
          const Icon = meta.icon;
          return (
            <div key={index} className={`flex gap-2 max-w-[90%] ${message.role === 'assistant' ? '' : 'ml-auto justify-end'}`}>
              <div style={{ color: message.role === 'assistant' ? 'var(--tw-critical)' : 'var(--tw-burgundy)' }}>
                {message.role === 'assistant' ? <Bot size={14} /> : <User size={14} />}
              </div>
              <div className="space-y-2 min-w-0">
                <div className="text-sm" style={dw.text}>{message.content}</div>

                {message.answer && <AnswerBreakdown answer={message.answer} />}

                {message.sources.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {message.sources.map(source => (
                      <span key={source} className="font-mono text-[9px] px-1.5 py-0.25 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-burgundy)' }}>{source}</span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}
        {loading && (
          <div className="flex gap-2 items-center">
            <Bot size={14} style={dw.critical} />
            <Loader2 size={12} className="animate-spin" style={dw.muted} />
            <span className="font-mono text-[10px]" style={dw.muted}>Querying backend records…</span>
          </div>
        )}
        {error && <p className="font-mono text-[10px]" style={dw.critical}>Backend error: {error}</p>}
      </div>

      <div className="p-3 border-t" style={dw.borderMid}>
        {messages.length <= 1 && (
          <div className="flex flex-wrap gap-1.5 mb-2">
            {suggested.map(question => (
              <button key={question} onClick={() => void send(question)} type="button" disabled={loading}
                className="text-left font-mono text-[10px] px-2.5 py-1.5 rounded-sm border disabled:opacity-50"
                style={{ backgroundColor: 'var(--tw-canvas-mid)', ...dw.borderMid, color: 'var(--tw-text-muted)' }}>
                {question}
              </button>
            ))}
          </div>
        )}
        <form onSubmit={onSubmit} className="flex gap-2">
          <input
            value={input}
            onChange={event => setInput(event.target.value)}
            placeholder="Ask about an actor, handle, or link…"
            className="flex-1 font-mono text-[11px] px-3 py-1.5 rounded-sm focus:outline-none"
            style={{ backgroundColor: 'var(--tw-input-bg)', borderColor: 'var(--tw-input-border)', color: 'var(--tw-text)' }}
            onKeyDown={event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); onSubmit(event as unknown as React.FormEvent); } }}
          />
          <button type="submit" disabled={loading || !input.trim()} className="px-3 rounded-sm border flex items-center" style={{ backgroundColor: 'var(--tw-burgundy)', borderColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}>
            <Send size={12} />
          </button>
        </form>
      </div>
    </div>
  );
}

/** The observed / derived / inference separation, rendered explicitly. */
function AnswerBreakdown({ answer }: { answer: AiAnswer }) {
  return (
    <div className="space-y-2">
      <Section title="OBSERVED DATA" color="var(--tw-low)" icon={Database} count={answer.observed.length}>
        {answer.observed.slice(0, 8).map((fact, index) => (
          <p key={index} className="font-mono text-[9px] leading-snug" style={dw.muted}>
            {fact.sourceId ? <span style={dw.burg}>[{fact.sourceId}]</span> : null} {fact.statement}
          </p>
        ))}
        {answer.observed.length > 8 && <p className="font-mono text-[9px]" style={dw.faint}>+{answer.observed.length - 8} more</p>}
        {answer.observed.length === 0 && <p className="font-mono text-[9px]" style={dw.faint}>No stored record matched this question.</p>}
      </Section>

      {answer.derived.length > 0 && (
        <Section title="DERIVED — computed from stored records" color="var(--tw-info)" icon={GitCompare} count={answer.derived.length}>
          {answer.derived.slice(0, 6).map((item, index) => (
            <p key={index} className="font-mono text-[9px] leading-snug" style={dw.muted}>
              {item.relationshipId ? <span style={dw.burg}>[{item.relationshipId}]</span> : null} {item.statement}
            </p>
          ))}
          {answer.derived.length > 6 && <p className="font-mono text-[9px]" style={dw.faint}>+{answer.derived.length - 6} more</p>}
        </Section>
      )}

      <Section title="AI INFERENCE" color="var(--tw-brass)" icon={Cpu} count={answer.inference.available ? 1 : 0}>
        {answer.inference.available && answer.inference.summary ? (
          <p className="text-[11px] leading-relaxed" style={dw.text}>{answer.inference.summary}</p>
        ) : (
          <p className="font-mono text-[9px]" style={dw.faint}>{answer.inference.note || 'No inference was produced.'}</p>
        )}
        {answer.inference.available && answer.inference.provider && (
          <p className="font-mono text-[9px]" style={dw.faint}>Provider: {answer.inference.provider}</p>
        )}
      </Section>

      <p className="font-mono text-[9px] leading-snug" style={dw.faint}>{answer.disclaimer}</p>
    </div>
  );
}

function Section({ title, color, icon: Icon, count, children }: {
  title: string;
  color: string;
  icon: typeof Database;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <div className="p-2.5 rounded-sm border space-y-1" style={{ backgroundColor: 'var(--tw-canvas-mid)', ...dw.borderMid }}>
      <p className="font-mono text-[9px] tracking-widest uppercase flex items-center gap-1" style={{ color }}>
        <Icon size={10} /> {title} {count > 0 && <span>({count})</span>}
      </p>
      {children}
    </div>
  );
}