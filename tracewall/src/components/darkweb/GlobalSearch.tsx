import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, CornerDownLeft, X, Network } from 'lucide-react';
import { dw } from '../../lib/darkweb/styles';
import { globalSearch, SEARCH_KIND_LABEL, type SearchKind, type SearchResult } from '../../lib/darkweb/globalSearch';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';

const KIND_ORDER: SearchKind[] = [
  'ACTOR',
  'HANDLE',
  'PGP',
  'WALLET',
  'INFRASTRUCTURE',
  'SOURCE',
  'OBSERVATION',
  'RELATIONSHIP',
  'INVESTIGATION',
  'EVIDENCE',
  'ATTACK_TECHNIQUE',
  'CVE',
];

const KIND_COLOR: Record<SearchKind, string> = {
  ACTOR: 'var(--tw-burgundy)',
  HANDLE: 'var(--tw-burgundy)',
  PGP: 'var(--tw-brass)',
  WALLET: 'var(--tw-info)',
  INFRASTRUCTURE: 'var(--tw-info)',
  SOURCE: 'var(--tw-info)',
  OBSERVATION: 'var(--tw-brass)',
  RELATIONSHIP: 'var(--tw-medium)',
  INVESTIGATION: 'var(--tw-low)',
  EVIDENCE: 'var(--tw-moss)',
  ATTACK_TECHNIQUE: 'var(--tw-critical)',
  CVE: 'var(--tw-high)',
};

const SUGGESTIONS = ['shadowfox', 'ghostwire', 'ACTOR-001', 'bc1q', 'relay'];

export function GlobalSearch() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  // Subscribing to the central model keeps results live: `globalSearch` reads the
  // dataset at call time, so the dataset revision is the only extra dependency.
  const { revision } = useIntelligence();

  const result: SearchResult = useMemo(() => globalSearch(query), [query, revision]);

  const grouped = useMemo(() => {
    const map = new Map<SearchKind, typeof result.hits>();
    for (const kind of KIND_ORDER) {
      const hits = result.hits.filter(hit => hit.kind === kind);
      if (hits.length) map.set(kind, hits);
    }
    return map;
  }, [result]);

  useEffect(() => {
    const handleKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setOpen(prev => !prev);
      }
      if (event.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, []);

  useEffect(() => {
    if (open) inputRef.current?.focus();
    else setQuery('');
  }, [open]);

  const go = (path: string) => {
    setOpen(false);
    navigate(path);
  };

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-sm transition-colors"
        style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}
        aria-label="Search dark web intelligence"
      >
        <Search size={13} />
        <span className="font-mono text-xs">Search intelligence…</span>
        <span
          className="font-mono text-[10px] px-1.5 rounded-sm"
          style={{ background: 'var(--tw-border-mid)', color: 'var(--tw-text-faint)' }}
        >
          ⌘K
        </span>
      </button>

      {open && (
        <div
          className="fixed inset-0 z-[90] flex items-start justify-center p-4 pt-[12vh]"
          style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}
          onMouseDown={event => {
            if (event.target === event.currentTarget) setOpen(false);
          }}
        >
          <div
            className="w-full max-w-2xl rounded-sm shadow-2xl overflow-hidden"
            style={{ backgroundColor: 'var(--tw-panel)', border: '1px solid var(--tw-border)' }}
          >
            {/* Input */}
            <div className="flex items-center gap-2 px-4 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <Search size={14} style={dw.burg} />
              <input
                ref={inputRef}
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && result.hits.length) go(result.hits[0].path);
                }}
                placeholder="Threat actor, handle, PGP fingerprint, wallet, domain, source, observation, evidence…"
                className="flex-1 font-mono text-xs focus:outline-none"
                style={{ backgroundColor: 'transparent', color: 'var(--tw-text)' }}
              />
              <button onClick={() => setOpen(false)} className="p-1" style={dw.muted} aria-label="Close search">
                <X size={14} />
              </button>
            </div>

            {/* Body */}
            <div className="max-h-[55vh] overflow-y-auto">
              {!query.trim() && (
                <div className="p-4 space-y-3">
                  <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>
                    Global dark web intelligence search
                  </p>
                  <p className="text-xs leading-relaxed" style={dw.muted}>
                    One search across threat actors, handles, PGP keys, wallets, infrastructure, forums,
                    marketplaces, sources, observations, relationships, evidence and investigations.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {SUGGESTIONS.map(seed => (
                      <button
                        key={seed}
                        type="button"
                        onClick={() => setQuery(seed)}
                        className="font-mono text-[10px] px-2 py-1 rounded-sm border transition-colors"
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
              )}

              {query.trim() && result.entity && (
                <button
                  type="button"
                  onClick={() => go(`/app/darkweb/actors/${result.entity!.primaryActorId}`)}
                  className="w-full text-left px-4 py-3 border-b flex items-center gap-3 transition-colors"
                  style={{ borderColor: 'var(--tw-border-mid)', backgroundColor: 'var(--tw-panel-alt)' }}
                >
                  <Network size={14} style={dw.burg} />
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>
                      Resolved entity
                    </p>
                    <p className="font-mono text-xs" style={dw.text}>
                      {result.entity.primaryActorId} · {result.entity.confidence}% confidence
                    </p>
                    <p className="font-mono text-[10px]" style={dw.faint}>{result.entity.label}</p>
                  </div>
                  <CornerDownLeft size={12} style={dw.muted} />
                </button>
              )}

              {query.trim() && result.total === 0 && (
                <div className="p-8 text-center" style={dw.muted}>
                  <Search size={28} className="mx-auto mb-2" />
                  <p>No intelligence matches “{query}”.</p>
                </div>
              )}

              {query.trim() && result.total > 0 && (
                <>
                  <div className="px-4 py-2 border-b flex items-center justify-between" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>
                      {result.total} result{result.total === 1 ? '' : 's'}
                    </span>
                    <span className="font-mono text-[10px]" style={dw.faint}>↵ to open first</span>
                  </div>
                  {KIND_ORDER.filter(kind => grouped.has(kind)).map(kind => (
                    <div key={kind}>
                      <div
                        className="px-4 py-1.5 font-mono text-[9px] tracking-widest uppercase border-b"
                        style={{ borderColor: 'var(--tw-border-mid)', color: KIND_COLOR[kind] }}
                      >
                        {SEARCH_KIND_LABEL[kind]} ({grouped.get(kind)!.length})
                      </div>
                      {grouped.get(kind)!.map(hit => (
                        <button
                          key={`${hit.kind}-${hit.id}`}
                          type="button"
                          onClick={() => go(hit.path)}
                          className="w-full text-left px-4 py-2.5 border-b transition-colors"
                          style={{ borderColor: 'var(--tw-border-mid)' }}
                          onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
                          onMouseLeave={e => (e.currentTarget.style.backgroundColor = '')}
                        >
                          <div className="flex items-center justify-between gap-3">
                            <p className="font-mono text-xs truncate" style={dw.text}>{hit.title}</p>
                            <span className="font-mono text-[10px] shrink-0" style={dw.faint}>{hit.confidence}%</span>
                          </div>
                          <p className="font-mono text-[10px] truncate" style={dw.burg}>{hit.subtitle}</p>
                          <p className="font-mono text-[10px] truncate" style={dw.muted}>{hit.detail}</p>
                        </button>
                      ))}
                    </div>
                  ))}
                </>
              )}
            </div>

            {/* Footer */}
            <div
              className="px-4 py-2 flex items-center justify-between border-t font-mono text-[9px]"
              style={{ borderColor: 'var(--tw-border-mid)', backgroundColor: 'var(--tw-panel-alt)' }}
            >
              <span style={dw.faint}>Results derived from the collected dataset only</span>
              <span style={dw.faint}>Esc to close</span>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
