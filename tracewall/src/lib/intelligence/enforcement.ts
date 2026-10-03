// ============================================================
// PhishNet — Enforcement capability layer.
//
// The single rule this module enforces: the platform never claims a
// control has been applied unless a configured integration confirms
// it. Everything else follows from that.
//
// Blocking an IP, blocking a domain, quarantining a file and revoking
// a trust anchor are all changes to a system *outside* the platform.
// Where an operator has configured and authorised such an integration,
// the platform can request the change and verify the result. Where one
// has not, the honest output is a labelled recommendation or a pending
// action — never "blocked".
//
// Configuration is read from the deployment's VITE_ENFORCEMENT_*
// settings, which is the same mechanism the rest of the platform uses
// for its external integrations. No backend, database or API contract
// is required for this module to work.
// ============================================================
import type {
  ActionAvailability,
  EnforcementChannel,
  EnforcementChannelKey,
  FactTone,
  ResponseActionKind,
  ResponseActionOption,
  ResponseActionRecord,
  ResponseActionStatus,
} from './types-protection';

// ── Configuration ──────────────────────────────────────────────

interface EnvLike {
  [key: string]: string | boolean | undefined;
}

function env(): EnvLike {
  try {
    return (import.meta.env ?? {}) as unknown as EnvLike;
  } catch {
    return {};
  }
}

function setting(key: string): string | null {
  const value = env()[key];
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/** Explicit operator opt-in. Absent means "not configured". */
function enabled(key: string): boolean {
  const value = setting(key);
  if (!value) return false;
  return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
}

function endpoint(key: string): string | null {
  const value = setting(key);
  return value && !/^(0|false|off|no|disabled)$/i.test(value) ? value : null;
}

interface ChannelSpec {
  key: EnforcementChannelKey;
  label: string;
  controlPlane: string;
  configKey: string;
  endpointKey: string;
  authorization: string;
}

/**
 * Every control plane the platform can talk to, and the deployment
 * setting that connects it. A channel with no setting is simply not
 * available — the catalogue is the honest list of what a deployment
 * could plug in, not a claim that it has.
 */
const CHANNEL_SPECS: ChannelSpec[] = [
  {
    key: 'FIREWALL',
    label: 'Network firewall',
    controlPlane: 'Perimeter / egress firewall rule set',
    configKey: 'VITE_ENFORCEMENT_FIREWALL',
    endpointKey: 'VITE_ENFORCEMENT_FIREWALL_ENDPOINT',
    authorization: 'Change approval on the firewall rule set, with an audit trail the platform can read back.',
  },
  {
    key: 'DNS_SECURITY_GATEWAY',
    label: 'DNS security gateway',
    controlPlane: 'Authoritative resolver category / sinkhole policy',
    configKey: 'VITE_ENFORCEMENT_DNS',
    endpointKey: 'VITE_ENFORCEMENT_DNS_ENDPOINT',
    authorization: 'Authority to move a domain into a blocking or sinkhole category.',
  },
  {
    key: 'SECURE_PROXY',
    label: 'Secure web proxy',
    controlPlane: 'Proxy deny list for URLs and destinations',
    configKey: 'VITE_ENFORCEMENT_PROXY',
    endpointKey: 'VITE_ENFORCEMENT_PROXY_ENDPOINT',
    authorization: 'Authority to deny a URL at the proxy, for all or selected users.',
  },
  {
    key: 'ENDPOINT_PROTECTION',
    label: 'Endpoint protection',
    controlPlane: 'EDR / malware-analysis quarantine',
    configKey: 'VITE_ENFORCEMENT_EDR',
    endpointKey: 'VITE_ENFORCEMENT_EDR_ENDPOINT',
    authorization: 'Authority to quarantine a file or host on managed endpoints.',
  },
  {
    key: 'IDENTITY_TRUST',
    label: 'Identity & trust store',
    controlPlane: 'Key trust anchors, certificate pins and trust revocations',
    configKey: 'VITE_ENFORCEMENT_TRUST',
    endpointKey: 'VITE_ENFORCEMENT_TRUST_ENDPOINT',
    authorization: 'Authority to revoke trust in a key or certificate anchor.',
  },
  {
    key: 'MESSAGE_FILTER',
    label: 'Mail security filter',
    controlPlane: 'Sender, domain and attachment blocking at the mail gateway',
    configKey: 'VITE_ENFORCEMENT_MAIL',
    endpointKey: 'VITE_ENFORCEMENT_MAIL_ENDPOINT',
    authorization: 'Authority to block a sender or domain at the mail gateway.',
  },
  {
    key: 'CHAIN_ANALYTICS',
    label: 'Chain analytics provider',
    controlPlane: 'Exchange / blockchain abuse reporting and address tagging',
    configKey: 'VITE_ENFORCEMENT_CHAIN',
    endpointKey: 'VITE_ENFORCEMENT_CHAIN_ENDPOINT',
    authorization: 'An account with the provider, able to file an abuse or TFS report for an address.',
  },
  {
    key: 'ABUSE_DESK',
    label: 'Provider abuse desk',
    controlPlane: 'Hosting / registrar / platform abuse and takedown requests',
    configKey: 'VITE_ENFORCEMENT_ABUSE',
    endpointKey: 'VITE_ENFORCEMENT_ABUSE_ENDPOINT',
    authorization: 'A verified abuse contact and a lawful basis for the request.',
  },
];

export function enforcementChannels(): EnforcementChannel[] {
  return CHANNEL_SPECS.map(spec => ({
    key: spec.key,
    label: spec.label,
    controlPlane: spec.controlPlane,
    configKey: spec.configKey,
    endpointConfigKey: spec.endpointKey,
    configured: enabled(spec.configKey),
    endpoint: endpoint(spec.endpointKey),
    authorization: spec.authorization,
  }));
}

export function enforcementChannel(key: EnforcementChannelKey): EnforcementChannel {
  const spec = CHANNEL_SPECS.find(channel => channel.key === key)!;
  return {
    key: spec.key,
    label: spec.label,
    controlPlane: spec.controlPlane,
    configKey: spec.configKey,
    endpointConfigKey: spec.endpointKey,
    configured: enabled(spec.configKey),
    endpoint: endpoint(spec.endpointKey),
    authorization: spec.authorization,
  };
}

/** Channels an operator has actually connected. */
export function configuredChannels(): EnforcementChannel[] {
  return enforcementChannels().filter(channel => channel.configured);
}

export function isChannelConfigured(key: EnforcementChannelKey): boolean {
  return enforcementChannel(key).configured;
}

// ── Action catalogue ───────────────────────────────────────────
//
// `valueType` is what the record actually is, because only some
// indicator classes can be enforced. An on-chain wallet address is
// deliberately absent from the blockable set: it is not a control the
// platform can act on, and offering "block wallet" would be a lie.

type ValueType =
  | 'IP'
  | 'DOMAIN'
  | 'URL'
  | 'HANDLE'
  | 'WALLET'
  | 'PGP_KEY'
  | 'FILE'
  | 'ACTOR'
  | 'CVE'
  | 'GENERIC';

interface ActionSpec {
  kind: ResponseActionKind;
  label: string;
  detail: string;
  appliesTo: ValueType[];
  channel: EnforcementChannelKey | null;
  /** Channel-plane changes that alter state outside the platform. */
  enforces: boolean;
  requiresApproval: boolean;
}

const IP_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const HOST_PATTERN = /^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i;

export function classifyIndicatorValue(value: string): ValueType {
  const raw = (value ?? '').trim();
  if (!raw) return 'GENERIC';
  if (/^[a-f0-9]{40}$/i.test(raw) || raw.startsWith('bc1') || /^0x[a-f0-9]{40}$/i.test(raw)) return 'WALLET';
  if (IP_PATTERN.test(raw)) return 'IP';
  if (/^https?:\/\//i.test(raw)) return 'URL';
  if (HOST_PATTERN.test(raw.replace(/^www\./i, ''))) return 'DOMAIN';
  if (/[A-F0-9]{16,}/.test(raw) && /fingerprint/i.test(raw)) return 'PGP_KEY';
  return 'GENERIC';
}

function valueTypeFor(entityType: string, entityValue: string): ValueType {
  switch (entityType) {
    case 'IP':
    case 'DOMAIN':
    case 'URL':
    case 'HANDLE':
    case 'WALLET':
      return entityType as ValueType;
    // A PGP key panel passes the record type; a detected fingerprint passes
    // the value. Both must resolve to the same value type or the key trust
    // workflow silently disappears.
    case 'PGP':
    case 'PGP_KEY':
      return 'PGP_KEY';
    default:
      return classifyIndicatorValue(entityValue);
  }
}

const ACTION_SPECS: ActionSpec[] = [
  {
    kind: 'BLOCK_IP',
    label: 'Block IP address',
    detail: 'Deny this address at the perimeter and egress firewall.',
    appliesTo: ['IP'],
    channel: 'FIREWALL',
    enforces: true,
    requiresApproval: true,
  },
  {
    kind: 'BLOCK_DOMAIN',
    label: 'Block domain',
    detail: 'Move this domain into a blocked category at the DNS security gateway or mail filter.',
    appliesTo: ['DOMAIN'],
    channel: 'DNS_SECURITY_GATEWAY',
    enforces: true,
    requiresApproval: true,
  },
  {
    kind: 'BLOCK_URL',
    label: 'Block URL',
    detail: 'Deny this URL at the secure web proxy.',
    appliesTo: ['URL'],
    channel: 'SECURE_PROXY',
    enforces: true,
    requiresApproval: true,
  },
  {
    kind: 'BLOCK_HANDLE',
    label: 'Restrict account at platform',
    detail: 'Report and request restriction of this identity with its host platform.',
    appliesTo: ['HANDLE'],
    channel: 'MESSAGE_FILTER',
    enforces: true,
    requiresApproval: true,
  },
  {
    kind: 'QUARANTINE_FILE',
    label: 'Quarantine file',
    detail: 'Hold the artefact on managed endpoints and submit it for malware analysis.',
    appliesTo: ['FILE'],
    channel: 'ENDPOINT_PROTECTION',
    enforces: true,
    requiresApproval: true,
  },
  {
    kind: 'REVOKE_TRUST',
    label: 'Revoke trust in key',
    detail: 'Remove this key or certificate anchor from the trust store and request replacement.',
    appliesTo: ['PGP_KEY'],
    channel: 'IDENTITY_TRUST',
    enforces: true,
    requiresApproval: true,
  },
  {
    kind: 'MONITOR_WALLET',
    label: 'Monitor wallet activity',
    detail: 'Alert on new activity from this address. A public chain cannot be frozen by this platform.',
    appliesTo: ['WALLET'],
    channel: null,
    enforces: false,
    requiresApproval: false,
  },
  {
    kind: 'TAKEDOWN_REQUEST',
    label: 'Request takedown',
    detail: 'File an abuse or takedown request with the host, registrar or exchange.',
    appliesTo: ['IP', 'DOMAIN', 'URL', 'HANDLE', 'WALLET'],
    channel: 'ABUSE_DESK',
    enforces: true,
    requiresApproval: true,
  },
  {
    kind: 'PATCH_ASSET',
    label: 'Recommend remediation',
    detail: 'Raise a patching and compensating-control task for the affected asset.',
    appliesTo: ['CVE'],
    channel: null,
    enforces: false,
    requiresApproval: false,
  },
  {
    kind: 'ALERT',
    label: 'Raise alert',
    detail: 'Raise an in-platform alert so triage and the response queue see this entity.',
    appliesTo: ['IP', 'DOMAIN', 'URL', 'HANDLE', 'WALLET', 'PGP_KEY', 'FILE', 'ACTOR', 'CVE', 'GENERIC'],
    channel: null,
    enforces: false,
    requiresApproval: false,
  },
  {
    kind: 'MONITOR',
    label: 'Start monitoring',
    detail: 'Attach a 24×7 monitor to this record using its existing id.',
    appliesTo: ['IP', 'DOMAIN', 'URL', 'HANDLE', 'WALLET', 'PGP_KEY', 'FILE', 'ACTOR', 'CVE', 'GENERIC'],
    channel: null,
    enforces: false,
    requiresApproval: false,
  },
  {
    kind: 'ESCALATE',
    label: 'Escalate for review',
    detail: 'Open a response ticket for this entity and assign it for triage.',
    appliesTo: ['IP', 'DOMAIN', 'URL', 'HANDLE', 'WALLET', 'PGP_KEY', 'FILE', 'ACTOR', 'CVE', 'GENERIC'],
    channel: null,
    enforces: false,
    requiresApproval: false,
  },
  {
    kind: 'LINK_INVESTIGATION',
    label: 'Link to investigation',
    detail: 'Attach this entity to an existing investigation case.',
    appliesTo: ['IP', 'DOMAIN', 'URL', 'HANDLE', 'WALLET', 'PGP_KEY', 'FILE', 'ACTOR', 'CVE', 'GENERIC'],
    channel: null,
    enforces: false,
    requiresApproval: false,
  },
  {
    kind: 'ADD_EVIDENCE',
    label: 'Attach evidence',
    detail: 'Cite an existing evidence item as support for this entity.',
    appliesTo: ['IP', 'DOMAIN', 'URL', 'HANDLE', 'WALLET', 'PGP_KEY', 'FILE', 'ACTOR', 'CVE', 'GENERIC'],
    channel: null,
    enforces: false,
    requiresApproval: false,
  },
];

const AVAILABILITY_LABEL: Record<ActionAvailability, string> = {
  AVAILABLE: 'APPLIED BY INTEGRATION',
  APPROVAL_REQUIRED: 'AWAITING APPROVAL',
  RECOMMENDATION: 'RECOMMENDATION ONLY',
  UNSUPPORTED: 'NOT POSSIBLE FROM HERE',
};

/**
 * Which response actions make sense for this record, and — for each —
 * whether a configured integration can actually perform it.
 *
 * This is the only place availability is decided, so a page can never
 * offer an action it cannot take or imply one it did not.
 */
export function responseActionOptions(entityType: string, entityValue: string): ResponseActionOption[] {
  const kind = valueTypeFor(entityType, entityValue);
  const options: ResponseActionOption[] = [];

  for (const spec of ACTION_SPECS) {
    if (!spec.appliesTo.includes(kind)) continue;

    if (!spec.enforces || !spec.channel) {
      options.push({
        kind: spec.kind,
        label: spec.label,
        detail: spec.detail,
        availability: 'RECOMMENDATION',
        channel: spec.channel,
        availabilityReason:
          'Recorded inside the platform as a tracked action. It does not change any system outside this platform.',
        requiresApproval: spec.requiresApproval,
      });
      continue;
    }

    const channel = enforcementChannel(spec.channel);
    options.push({
      kind: spec.kind,
      label: spec.label,
      detail: spec.detail,
      availability: channel.configured ? 'APPROVAL_REQUIRED' : 'RECOMMENDATION',
      channel: spec.channel,
      availabilityReason: channel.configured
        ? `${channel.label} is configured. The action is held for analyst approval, then sent to ${channel.controlPlane} and confirmed by the integration.`
        : `No ${channel.label} integration is configured (${channel.configKey} is unset), so this stays a recommendation. ${channel.authorization}`,
      requiresApproval: true,
    });
  }

  return options;
}

export function availabilityLabel(availability: ActionAvailability): string {
  return AVAILABILITY_LABEL[availability];
}

export function availabilityTone(availability: ActionAvailability): FactTone {
  switch (availability) {
    case 'AVAILABLE':
      return 'ok';
    case 'APPROVAL_REQUIRED':
      return 'medium';
    case 'RECOMMENDATION':
      return 'muted';
    default:
      return 'muted';
  }
}

// ── Execution ──────────────────────────────────────────────────

export interface ActionAttempt {
  status: ResponseActionStatus;
  /** Sentence stating exactly what happened. */
  detail: string;
  channel: EnforcementChannelKey | null;
  confirmedAt: string | null;
}

/**
 * Request a response action from the integration that owns it.
 *
 * With a configured, reachable integration the platform verifies the
 * result and only then reports enforcement. With no integration the
 * action is recorded as awaiting one — it is never reported as applied.
 */
export async function runEnforcement(
  option: ResponseActionOption,
  context: { entityType: string; entityId: string; entityValue: string; performedBy: string },
): Promise<ActionAttempt> {
  if (!option.channel) {
    return {
      status: 'RECORDED',
      detail: 'Recorded inside the platform. No external control plane is involved in this action.',
      channel: null,
      confirmedAt: null,
    };
  }

  const channel = enforcementChannel(option.channel);
  if (!channel.configured) {
    return {
      status: 'AWAITING_INTEGRATION',
      detail: `${channel.label} is not configured (${channel.configKey} is unset), so nothing was blocked, quarantined or revoked. This is a tracked recommendation pending an authorised integration.`,
      channel: channel.key,
      confirmedAt: null,
    };
  }

  if (!channel.endpoint) {
    return {
      status: 'AWAITING_INTEGRATION',
      detail: `${channel.label} is enabled but exposes no endpoint, so the request could not be sent. Set ${channel.endpointConfigKey} to enable this action.`,
      channel: channel.key,
      confirmedAt: null,
    };
  }

  try {
    const response = await fetch(channel.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: option.kind,
        entityType: context.entityType,
        entityId: context.entityId,
        value: context.entityValue,
        performedBy: context.performedBy,
      }),
    });

    if (!response.ok) {
      return {
        status: 'FAILED',
        detail: `${channel.label} rejected the request (HTTP ${response.status}). The control was not changed.`,
        channel: channel.key,
        confirmedAt: null,
      };
    }

    const body = (await response.json().catch(() => null)) as
      | { applied?: boolean; confirmed?: boolean }
      | null;

    if (body && body.applied === false) {
      return {
        status: 'FAILED',
        detail: `${channel.label} reported that it did not apply the change. The control was not changed.`,
        channel: channel.key,
        confirmedAt: null,
      };
    }

    // A 2xx only means the request was accepted, not that the control
    // actually changed. Reporting "protected" on a status code alone is the
    // one failure mode this layer exists to prevent, so enforcement is
    // claimed only when the integration says so itself.
    const confirmed = body?.confirmed === true || body?.applied === true;
    if (!confirmed) {
      return {
        status: 'SUBMITTED_UNCONFIRMED',
        detail: `${channel.label} accepted the request (HTTP ${response.status}) but did not confirm that the change was applied. The platform will not report this as enforced — verify the control in ${channel.controlPlane} before treating it as protected.`,
        channel: channel.key,
        confirmedAt: null,
      };
    }

    return {
      status: 'ENFORCED_VERIFIED',
      detail: `${channel.label} accepted the request and confirmed the change.`,
      channel: channel.key,
      confirmedAt: new Date().toISOString(),
    };
  } catch (error) {
    return {
      status: 'FAILED',
      detail: `${channel.label} could not be reached: ${error instanceof Error ? error.message : String(error)}. The control was not changed.`,
      channel: channel.key,
      confirmedAt: null,
    };
  }
}

// ── Presentation ───────────────────────────────────────────────

export const STATUS_LABEL: Record<ResponseActionStatus, string> = {
  ENFORCED_VERIFIED: 'ENFORCED · VERIFIED',
  AWAITING_APPROVAL: 'AWAITING APPROVAL',
  AWAITING_INTEGRATION: 'PENDING INTEGRATION',
  SUBMITTED_UNCONFIRMED: 'SENT · UNCONFIRMED',
  FAILED: 'FAILED',
  RECORDED: 'RECORDED IN PLATFORM',
};

export const STATUS_TONE: Record<ResponseActionStatus, FactTone> = {
  ENFORCED_VERIFIED: 'ok',
  AWAITING_APPROVAL: 'medium',
  AWAITING_INTEGRATION: 'muted',
  SUBMITTED_UNCONFIRMED: 'medium',
  FAILED: 'critical',
  RECORDED: 'low',
};

export function statusLabel(status: ResponseActionStatus): string {
  return STATUS_LABEL[status];
}

export function statusTone(status: ResponseActionStatus): FactTone {
  return STATUS_TONE[status];
}

/**
 * One sentence describing what this deployment can and cannot enforce.
 * Shown wherever response actions are offered, so the limit is stated
 * before an analyst acts rather than discovered afterwards.
 */
export function enforcementSummaryLine(): string {
  const configured = configuredChannels();
  if (configured.length === 0) {
    return 'No enforcement integration is configured on this deployment. Response actions are recorded as tracked recommendations and pending actions — nothing is blocked, quarantined or revoked by the platform itself.';
  }
  return `Configured enforcement: ${configured.map(channel => channel.label).join(', ')}. Every other response action stays a recommendation until an integration is connected.`;
}

export type { ResponseActionOption, ResponseActionRecord };