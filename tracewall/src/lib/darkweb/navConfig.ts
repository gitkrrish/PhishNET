// ============================================================
// PhishNet — single source of truth for information architecture.
//
// The masthead dropdowns, the breadcrumb trail and the router
// all read this file, so a page can never appear twice in the
// navigation, and a route can never drift away from its label.
//
// Nothing here touches visual design: it only describes the
// dark-web-centric module structure and the legacy path aliases
// that keep old deep links resolving.
// ============================================================
import {
  Shield,
  Network,
  Search,
  Globe,
  Users,
  FileText,
  AlertTriangle,
  Database,
  Settings as SettingsIcon,
  Radio,
  type LucideIcon,
} from 'lucide-react';

export const HOME_PATH = '/app/briefing';

export interface NavItem {
  label: string;
  path: string;
  description: string;
  icon?: LucideIcon;
  /**
   * Additional paths that resolve to this item. Used for active
   * state and breadcrumbs only — aliases are never rendered as a
   * second entry in the dropdown, so navigation stays unique.
   */
  aliases?: string[];
}

export interface NavGroup {
  id: string;
  label: string;
  icon: LucideIcon;
  items: NavItem[];
}

export const topNavItems: NavItem[] = [
  {
    label: 'Dashboard',
    path: HOME_PATH,
    description: 'Dark web threat intelligence command center',
    icon: Shield,
  },
];

export const navGroups: NavGroup[] = [
  {
    id: 'darkweb',
    label: 'Dark Web Intelligence',
    icon: Network,
    items: [
      {
        label: 'Add Intelligence',
        path: '/app/darkweb/add',
        description: 'Record actors, handles, PGP, wallets, infrastructure and evidence',
        aliases: ['/app/darkweb/collect'],
      },
      {
        label: 'Threat Actors',
        path: '/app/darkweb/actors',
        description: 'Central investigation entities',
      },
      {
        label: 'ATT&CK Intelligence',
        path: '/app/darkweb/attack',
        description: 'Observed techniques, tactic coverage and per-actor mappings',
      },
      {
        label: 'Handle Intelligence',
        path: '/app/darkweb/handles',
        description: 'Identity and alias intelligence across platforms',
      },
      {
        label: 'PGP Intelligence',
        path: '/app/darkweb/pgp-keys',
        description: 'Cryptographic identity keys and their attributions',
        // Legacy detail deep links keyed by fingerprint resolve into the
        // same PGP workspace, so the breadcrumb trail never breaks.
        aliases: ['/app/darkweb/pgp'],
      },
      {
        label: 'Crypto Wallet Intelligence',
        path: '/app/darkweb/wallets',
        description: 'Payment address linking indicators and chain analysis',
      },
      {
        label: 'Observation Intelligence',
        path: '/app/darkweb/observations',
        description: 'Raw collection records and their extraction pipeline',
      },
      {
        label: 'Source Intelligence',
        path: '/app/darkweb/sources',
        description: 'Forums, marketplaces, leak sites and source health',
      },
      {
        label: 'Monitoring & Alerts',
        path: '/app/darkweb/alerts',
        description: 'Continuous collection, exposure tracking and alerting',
        aliases: ['/app/darkweb/exposure'],
      },
      {
        label: 'Identity Correlation',
        path: '/app/darkweb/correlation',
        description: 'Handle, PGP, wallet, behavioral and stylometric correlation',
      },
      {
        label: 'Infrastructure',
        path: '/app/darkweb/infrastructure',
        description: 'Actor infrastructure correlation analysis',
      },
      {
        label: 'Relationships',
        path: '/app/darkweb/graph',
        description: 'Interactive relationship graph',
      },
      {
        label: 'Timeline',
        path: '/app/darkweb/timeline',
        description: 'Investigation event timeline',
      },
      {
        label: 'Evidence',
        path: '/app/darkweb/evidence',
        description: 'Evidence locker and chain of custody',
      },
      {
        label: 'Investigations',
        path: '/app/darkweb/investigations',
        description: 'Dark web investigation cases',
      },
      {
        label: 'AI Analysis',
        path: '/app/darkweb/ai',
        description: 'Entity extraction, attribution and evidence synthesis',
      },
      {
        label: 'Reports',
        path: '/app/darkweb/reports',
        description: 'Investigation reporting and exports',
      },
    ],
  },
  {
    id: 'analysis',
    label: 'Analysis',
    icon: Search,
    items: [
      {
        // This tool is the Email Analyzer. It was mislabelled "Dark Web
        // Analysis", which both misdescribed the tool and hid the fact that
        // the platform had no email analysis entry point. Tool names stay
        // accurate; dark-web focus comes from the platform architecture.
        label: 'Email Analyzer',
        path: '/app/investigate',
        description: 'Analyze suspicious emails, headers, links and indicators',
      },
      {
        label: 'File Analysis',
        path: '/app/file-analysis',
        description: 'Analyze files and attachments for malicious artifacts',
      },
      {
        label: 'URL Analysis',
        path: '/app/url-analysis',
        description: 'Analyze URLs, redirect chains and destination hosts',
      },
      {
        label: 'Infrastructure',
        path: '/app/infrastructure',
        description: 'IP and domain enrichment for infrastructure indicators',
      },
    ],
  },
  {
    id: 'ai-intelligence',
    label: 'AI Intelligence',
    icon: Users,
    items: [
      {
        label: 'AI Feedback',
        path: '/app/campaigns',
        description: 'Share and review dark web investigation experience',
      },
      {
        label: 'AI Threat Intelligence',
        path: '/app/intelligence',
        description: 'Indicator enrichment and dark web correlation',
      },
    ],
  },
  {
    id: 'monitoring-hub',
    label: '24×7 Monitoring',
    icon: Radio,
    items: [
      {
        label: 'Monitoring Hub',
        path: '/app/monitoring/hub',
        description: 'Centralized monitor registry, alerts, run history and health for all tools',
        // /app/monitoring redirects to the hub, so old deep links resolve here.
        aliases: ['/app/monitoring'],
      },
      {
        label: 'All Monitors',
        path: '/app/monitoring/monitors',
        description: 'Unified view of every active, paused and disabled monitor',
      },
      {
        label: 'Monitoring Alerts',
        path: '/app/monitoring/alerts',
        description: 'Centralized alert triage from all monitoring sources',
      },
      {
        label: 'Run History & Health',
        path: '/app/monitoring/health',
        description: 'Collection intervals, source health and scheduler status',
      },
    ],
  },
  {
    id: 'investigations',
    label: 'Investigations',
    icon: FileText,
    items: [
      {
        label: 'Investigation Cases',
        path: '/app/cases',
        description: 'Case management linked to dark web investigations',
      },
    ],
  },
  {
    id: 'response-alerts-evidence',
    label: 'Response, Alerts & Evidence',
    icon: AlertTriangle,  // Using AlertTriangle as it was from Response & Alerts
    items: [
      {
        label: 'Alert Center',
        path: '/app/alerts',
        description: 'Alert triage and response actions',
      },
      {
        label: 'Decision Desk',
        path: '/app/decisions',
        description: 'Response approval queue for dark web threats',
      },
      {
        label: 'Evidence',
        path: '/app/evidence',
        description: 'Evidence repository',
      },
      {
        label: 'Reports',
        path: '/app/reports',
        description: 'Forensic investigation report generation',
      },
    ],
  },
  {
    id: 'admin',
    label: 'Administration',
    icon: SettingsIcon,
    items: [
      {
        label: 'Audit Logs',
        path: '/app/audit',
        description: 'System audit trail',
      },
      {
        label: 'Settings',
        path: '/app/settings',
        description: 'Organization settings',
      },
    ],
  },
];

/**
 * Retired paths → canonical location.
 *
 * The standalone "Dark-Web Monitoring" module is gone. Its monitoring
 * capability now lives in the centralized 24×7 Monitoring section, so old
 * links land on the same functionality under the new name instead of
 * 404-ing.
 *
 * The separate "Threat Protection Center" is retired for the same reason:
 * detection, protection and response are now part of each Dark Web
 * Intelligence module that owns the entity, so `/app/protection` resolves
 * into Threat Actors — the module where a protection review begins.
 */
export const legacyRedirects: Record<string, string> = {
  '/app/exposure': '/app/darkweb/exposure',
  '/app/darkweb/monitoring': '/app/monitoring/monitors',
  '/app/protection': '/app/darkweb/actors',
  '/app/protection/threats': '/app/darkweb/actors',
};

export function itemPaths(item: NavItem): string[] {
  return item.aliases ? [item.path, ...item.aliases] : [item.path];
}

export function normalizePath(pathname: string): string {
  if (!pathname) return HOME_PATH;
  const withoutQuery = pathname.split('?')[0].split('#')[0];
  const trimmed =
    withoutQuery.length > 1 && withoutQuery.endsWith('/')
      ? withoutQuery.slice(0, -1)
      : withoutQuery;
  return legacyRedirects[trimmed] ?? trimmed;
}

export interface NavMatch {
  group?: NavGroup;
  item: NavItem;
  exact: boolean;
  depth: number;
}

/**
 * Longest-prefix match across every nav path. Longest wins so that
 * `/app/darkweb/actors` highlights "Threat Actors" rather than the
 * broader "Dark Web Intelligence" group.
 */
export function findNavMatch(pathname: string): NavMatch | null {
  const normalized = normalizePath(pathname);
  let best: NavMatch | null = null;

  for (const group of navGroups) {
    for (const item of group.items) {
      for (const candidate of itemPaths(item)) {
        const isExact = normalized === candidate;
        const isPrefix = normalized.startsWith(`${candidate}/`);
        if (!isExact && !isPrefix) continue;
        if (!best || candidate.length > best.depth) {
          best = { group, item, exact: isExact, depth: candidate.length };
        }
      }
    }
  }

  for (const item of topNavItems) {
    for (const candidate of itemPaths(item)) {
      const isExact = normalized === candidate;
      const isPrefix = normalized.startsWith(`${candidate}/`);
      if (!isExact && !isPrefix) continue;
      if (!best || candidate.length > best.depth) {
        best = { group: undefined, item, exact: isExact, depth: candidate.length };
      }
    }
  }

  return best;
}

export function isNavItemActive(item: NavItem, pathname: string): boolean {
  return findNavMatch(pathname)?.item === item;
}

export function isNavGroupActive(group: NavGroup, pathname: string): boolean {
  const match = findNavMatch(pathname);
  return !!match && !!match.group && match.group.id === group.id;
}

/** Leaf labels for routes that sit below a nav item (detail pages). */
const detailLabels: Array<[RegExp, string]> = [
  [/^\/app\/darkweb\/actors\/[^/]+$/, 'Actor Profile'],
  [/^\/app\/darkweb\/handles\/[^/]+$/, 'Handle Dossier'],
  [/^\/app\/darkweb\/pgp-keys\/[^/]+$/, 'PGP Key Dossier'],
  [/^\/app\/darkweb\/pgp\/[^/]+$/, 'PGP Key Dossier'],
  [/^\/app\/darkweb\/wallets\/[^/]+$/, 'Wallet Dossier'],
  [/^\/app\/darkweb\/observations\/[^/]+$/, 'Observation Record'],
  [/^\/app\/darkweb\/investigations\/[^/]+$/, 'Investigation Workspace'],
  [/^\/app\/darkweb\/demo$/, 'Demo Investigation'],
  [/^\/app\/cases\/[^/]+$/, 'Case Detail'],
];

/** Explicit sub-view names for routes folded into a nav item. */
const subViewLabels: Record<string, string> = {
  '/app/darkweb/exposure': 'Exposure Ledger',
};

export interface Breadcrumb {
  label: string;
  path: string;
}

export function breadcrumbsFor(pathname: string): Breadcrumb[] {
  const normalized = normalizePath(pathname);
  const match = findNavMatch(normalized);

  if (!match) return [{ label: 'Dashboard', path: HOME_PATH }];

  // Top-level direct items (e.g. Dashboard) are the root themselves.
  if (!match.group) {
    return [{ label: match.item.label, path: match.item.path }];
  }

  const crumbs: Breadcrumb[] = [
    { label: 'Dashboard', path: HOME_PATH },
    { label: match.group.label, path: match.item.path },
  ];

  const isSubView = !!subViewLabels[normalized];
  const isDetail = detailLabels.some(([pattern]) => pattern.test(normalized));

  if (isSubView) {
    crumbs.push({ label: subViewLabels[normalized], path: normalized });
  } else if (isDetail) {
    const label =
      detailLabels.find(([pattern]) => pattern.test(normalized))?.[1] ?? 'Page';
    crumbs.push({ label, path: normalized });
  } else if (!match.exact) {
    crumbs.push({ label: 'Page', path: normalized });
  }

  return crumbs;
}
