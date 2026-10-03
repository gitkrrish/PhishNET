import { TrendingUp, Users, Zap, ShieldAlert, Clock, BarChart3, Activity, FileText } from 'lucide-react';
import { dw } from '../../lib/darkweb/styles';

interface StatCardProps {
  title: string;
  value: string | number;
  icon?: 'actors' | 'activity' | 'trend' | 'shield' | 'clock' | 'chart' | 'zap' | 'file';
  tone?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'info';
  trend?: number;
  subtitle?: string;
  onClick?: () => void;
}

const icons: Record<NonNullable<StatCardProps['icon']>, React.ComponentType<{ size?: number; className?: string }>> = {
  actors: Users, activity: Activity, trend: TrendingUp, shield: ShieldAlert, clock: Clock, chart: BarChart3, zap: Zap, file: FileText,
};

export function StatCard({ title, value, icon = 'chart', tone = 'default', trend, subtitle, onClick }: StatCardProps) {
  const Icon = icons[icon];
  const toneColor = {
    default: 'var(--tw-burgundy)', critical: 'var(--tw-critical)', high: 'var(--tw-high)',
    medium: 'var(--tw-medium)', low: 'var(--tw-low)', info: 'var(--tw-info)',
  }[tone];
  return (
    <button
      onClick={onClick}
      type="button"
      className="w-full text-left p-5 rounded-sm border transition-all duration-200 hover:translate-y-[-2px]"
      style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)', color: 'var(--tw-text)' }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1 flex-1">
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={dw.muted}>{title}</p>
          <p className="font-serif text-3xl" style={dw.text}>{value}</p>
          {subtitle && <p className="font-mono text-[10px]" style={dw.faint}>{subtitle}</p>}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {trend !== undefined && (
            <span className={`font-mono text-[10px] flex items-center gap-0.5 ${trend >= 0 ? 'text-[var(--tw-low)]' : 'text-[var(--tw-high)]'}`}>
              <TrendingUp size={10} className={trend < 0 ? 'rotate-180' : ''} /> {Math.abs(trend)}%
            </span>
          )}
          <span style={{ color: toneColor }}>{<Icon size={18} />}</span>
        </div>
      </div>
    </button>
  );
}
