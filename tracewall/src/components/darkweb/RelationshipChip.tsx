import clsx from 'clsx';

interface RelationshipChipProps {
  type: string;
  confidence: number;
  compact?: boolean;
}

const labels: Record<string, string> = {
  SHARED_HANDLE: 'Shared Handle', SHARED_PGP: 'Shared PGP', SHARED_WALLET: 'Shared Wallet',
  SHARED_INFRASTRUCTURE: 'Shared Infra', ASSOCIATED_WITH: 'Associated', OBSERVED_ON: 'Observed On',
  SIMILAR_PERSONA: 'Similar Persona', PERSONA_MIGRATION: 'Persona Migration',
  TEMPORAL_RELATIONSHIP: 'Temporal', TEMPORAL_OVERLAP: 'Temp. Overlap',
  SHARED_BEHAVIOR: 'Shared Behavior', USES_HANDLE: 'Uses Handle',
};

export function RelationshipChip({ type, confidence, compact = false }: RelationshipChipProps) {
  const label = labels[type] ?? type.replace(/_/g, ' ');
  const color = confidence >= 90 ? 'var(--tw-critical)' : confidence >= 75 ? 'var(--tw-high)' : confidence >= 60 ? 'var(--tw-medium)' : 'var(--tw-dust)';
  return (
    <span
      className={clsx('font-mono rounded-sm border', compact ? 'text-[9px] px-1.5 py-0.25' : 'text-[10px] px-2 py-0.5')}
      style={{ color, borderColor: `color-mix(in srgb, ${color} 45%, transparent)`, backgroundColor: `color-mix(in srgb, ${color} 15%, transparent)` }}
    >
      {label}
    </span>
  );
}
