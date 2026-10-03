import { Activity, AlertTriangle, Database, FileText, Globe, Key, Link2, MousePointer, Network, Server, Shield, ShoppingCart, UserRound, Wallet, Wifi } from 'lucide-react';
import type { ComponentType } from 'react';

export type EntityType = 'actor' | 'handle' | 'pgp' | 'wallet' | 'domain' | 'ip' | 'tls' | 'infrastructure' | 'nameserver' | 'forum' | 'marketplace' | 'paste' | 'leak' | 'messaging' | 'feed' | 'onion' | 'evidence' | 'persona' | 'relationship';

export function entityIcon(type: EntityType): ComponentType<{ size?: number; className?: string }> {
  switch (type) {
    case 'actor': return Shield;
    case 'handle': return MousePointer;
    case 'pgp': return Key;
    case 'wallet': return Wallet;
    case 'domain':
    case 'onion': return Globe;
    case 'ip': return Wifi;
    case 'tls':
    case 'infrastructure':
    case 'nameserver': return Server;
    case 'forum': return Database;
    case 'marketplace': return ShoppingCart;
    case 'paste': return FileText;
    case 'leak': return AlertTriangle;
    case 'messaging': return Network;
    case 'feed': return Activity;
    case 'evidence': return FileText;
    case 'persona': return UserRound;
    case 'relationship': return Link2;
    default: return MousePointer;
  }
}
