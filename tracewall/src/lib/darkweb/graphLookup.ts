import { threatActors, darkWebHandles, darkWebPgpKeys, darkWebWallets, darkWebInfrastructure, darkWebEvidence, darkWebSources, type DarkWebSource } from './liveData';
import type { Evidence, PgpKey, Wallet, Infrastructure, Handle, ThreatActor } from '../../data/darkWebData';

export function getActorViewById(id: string): ThreatActor | undefined {
  return threatActors.find(a => a.id === id);
}

export function getHandleViewById(id: string): Handle | undefined {
  return darkWebHandles.find(h => h.id === id || h.value.toLowerCase() === id.toLowerCase());
}

export function getEvidenceViewById(id: string): Evidence | undefined {
  return darkWebEvidence.find(e => e.id === id);
}

export function getSourceViewById(id: string): DarkWebSource | undefined {
  return darkWebSources.find(s => s.id === id);
}

export function getPgpViewById(id: string): PgpKey | undefined {
  return darkWebPgpKeys.find(k => k.id === id) ?? darkWebPgpKeys.find(k => k.fingerprint.replace(/\s+/g, '').toUpperCase().startsWith(id.replace(/\s+/g, '').toUpperCase().slice(0, 12)));
}

export function getWalletViewById(id: string): Wallet | undefined {
  return darkWebWallets.find(w => w.id === id || w.address === id || w.address.startsWith(id.slice(0, 12)));
}

export function getInfrastructureViewById(id: string): Infrastructure | undefined {
  return darkWebInfrastructure.find(i => i.id === id || i.value.toLowerCase() === id.toLowerCase());
}

export function getNodeDetail(nodeId: string): { title: string; description?: string; meta?: Record<string, unknown> } | null {
  if (nodeId.startsWith('h_')) return { title: getHandleViewById(nodeId.slice(2))?.value ?? nodeId, description: 'Handle', meta: getHandleViewById(nodeId.slice(2)) as any };
  if (nodeId.startsWith('k_')) return { title: getPgpViewById(nodeId.slice(2))?.fingerprint.slice(0, 16) ?? nodeId, description: 'PGP Key', meta: getPgpViewById(nodeId.slice(2)) as any };
  if (nodeId.startsWith('w_')) return { title: getWalletViewById(nodeId.slice(2))?.address.slice(0, 20) ?? nodeId, description: 'Wallet', meta: getWalletViewById(nodeId.slice(2)) as any };
  if (nodeId.startsWith('i_')) {
    const inf = getInfrastructureViewById(nodeId.slice(2));
    return { title: inf?.value ?? nodeId, description: inf?.type ?? 'Infrastructure', meta: inf as any };
  }
  return null;
}
