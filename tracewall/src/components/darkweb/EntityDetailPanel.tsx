import { dw } from '../../lib/darkweb/styles';
import { X, User, Shield, MousePointer, Key, Wallet, Globe, Server } from 'lucide-react';

interface EntityDetailPanelProps {
  node: { id: string; type: string; data?: Record<string, any> };
  onClose: () => void;
}

export function EntityDetailPanel({ node, onClose }: EntityDetailPanelProps) {
  const meta = node.data?.meta ?? {};
  const confidence = node.data?.confidence;
  const type = node.type;

  const iconForType = (t: string) => {
    switch (t) {
      case 'actor': return Shield;
      case 'handle': return MousePointer;
      case 'pgp': return Key;
      case 'wallet': return Wallet;
      case 'domain': return Globe;
      case 'ip': return Server;
      default: return User;
    }
  };
  const Icon = iconForType(type);

  let detailRows: Array<{ label: string; value: string }> = [{ label: 'Type', value: type }, { label: 'Confidence', value: confidence !== undefined ? `${confidence}%` : '—' }];
  if (type === 'actor') {
    detailRows.push(
      { label: 'Actor ID', value: node.id },
      { label: 'Aliases', value: (meta.aliases as string[] || []).join(', ') },
      { label: 'Platforms', value: (meta.platforms as string[] || []).join(', ') },
    );
  }
  if (meta && typeof meta === 'object' && meta !== null) {
    Object.entries(meta).forEach(([k, v]) => {
      if (['aliases', 'handles', 'platforms', 'actorIds', 'confidence'].includes(k)) return;
      detailRows.push({ label: k.charAt(0).toUpperCase() + k.slice(1), value: Array.isArray(v) ? v.join(', ') : String(v ?? '') });
    });
  }

  return (
    <div className="h-full flex flex-col">
      <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--tw-border-mid)' }}>
        <div className="flex items-center gap-2">
          <span style={{ color: 'var(--tw-burgundy)' }}><Icon size={14} /></span>
          <p className="font-mono text-xs tracking-wider" style={dw.burg}>{node.id}</p>
        </div>
        <button onClick={onClose} className="p-1 rounded-sm" style={{ color: 'var(--tw-text-muted)' }}><X size={12} /></button>
      </div>
      <div className="p-4 overflow-y-auto flex-1">
        <p className="font-serif text-lg mb-3" style={dw.text}>{node.data?.label ?? node.id}</p>
        <div className="space-y-2">
          {detailRows.map(r => r.value && (
            <div key={r.label} className="grid grid-cols-5 gap-1 text-[11px]">
              <span style={dw.faint}>{r.label}</span>
              <span className="font-mono col-span-4 break-words" style={dw.text}>{r.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
