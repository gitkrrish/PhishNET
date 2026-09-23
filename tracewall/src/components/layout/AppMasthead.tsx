import { Bell, Search, ChevronDown, Shield, Menu, X, Sun, Moon, FileText, Globe, Users, AlertTriangle, Database, Settings as SettingsIcon } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { useState, useRef, useEffect, useCallback } from 'react';
import { currentAnalyst, alerts } from '../../data/mockData';
import { useTheme } from '../../context/ThemeContext';
import clsx from 'clsx';

// Grouped navigation structure
const navGroups = [
  {
    id: 'overview',
    label: 'Overview',
    icon: Shield,
    items: [
      { label: 'Daily Briefing', path: '/app/briefing', description: 'Security overview and risk posture' },
    ],
  },
  {
    id: 'analysis',
    label: 'Analysis',
    icon: Search,
    items: [
      { label: 'Email Analysis', path: '/app/investigate', description: 'Analyze suspicious emails' },
      { label: 'File Analysis', path: '/app/file-analysis', description: 'Analyze files and attachments' },
      { label: 'URL Analysis', path: '/app/url-analysis', description: 'Analyze URLs and redirect chains' },
      { label: 'Infrastructure', path: '/app/infrastructure', description: 'IP and domain analysis' },
    ],
  },
  {
    id: 'darkweb',
    label: 'Dark-Web Monitoring',
    icon: Shield,
    items: [
      { label: 'Exposure Monitor', path: '/app/exposure', description: 'Credential exposure monitoring' },
    ],
  },
  {
    id: 'intelligence',
    label: 'Threat Intelligence',
    icon: Globe,
    items: [
      { label: 'IOC Workbench', path: '/app/intelligence', description: 'Indicator enrichment and correlation' },
    ],
  },
  {
    id: 'ai-intelligence',
    label: 'AI Feedback',
    icon: Users,
    items: [
      { label: 'AI Feedback', path: '/app/campaigns', description: 'Share and review community cybersecurity experiences' },
    ],
  },
  {
    id: 'investigations',
    label: 'Investigations',
    icon: FileText,
    items: [
      { label: 'Investigation Cases', path: '/app/cases', description: 'Case management and evidence' },
    ],
  },
  {
    id: 'response',
    label: 'Response and Alerts',
    icon: AlertTriangle,
    items: [
      { label: 'Alert Center', path: '/app/alerts', description: 'Alert management and response' },
      { label: 'Decision Desk', path: '/app/decisions', description: 'Response approval queue' },
    ],
  },
  {
    id: 'reports',
    label: 'Reports and Evidence',
    icon: Database,
    items: [
      { label: 'Evidence', path: '/app/evidence', description: 'Evidence repository' },
      { label: 'Reports', path: '/app/reports', description: 'Forensic report generation' },
    ],
  },
  {
    id: 'admin',
    label: 'Administration',
    icon: SettingsIcon,
    items: [
      { label: 'Audit Logs', path: '/app/audit', description: 'System audit trail' },
      { label: 'Settings', path: '/app/settings', description: 'Organization settings' },
    ],
  },
];

const openAlerts = alerts.filter(a => a.status === 'OPEN' || a.status === 'AWAITING_APPROVAL');

export function AppMasthead() {
  const location = useLocation();
  const { isDark, toggleTheme } = useTheme();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [expandedMobileGroups, setExpandedMobileGroups] = useState<Set<string>>(new Set(['overview']));
  const navRef = useRef<HTMLElement>(null);
  // Suppresses hover re-opening immediately after a nav-link click.
  // Without this, onMouseEnter fires again as the DOM repaints under the cursor
  // and the dropdown re-opens over the freshly rendered page content.
  const suppressHoverRef = useRef(false);

  useEffect(() => {
    if (!activeDropdown) return;
    const handleClick = (e: MouseEvent) => {
      const target = e.target as Node;
      if (navRef.current && !navRef.current.contains(target)) {
        setActiveDropdown(null);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [activeDropdown]);

  // Close all dropdowns whenever the route changes so a stale open dropdown
  // can never persist into the newly rendered page.
  useEffect(() => {
    setActiveDropdown(null);
  }, [location.pathname]);

  const clearNavigationState = useCallback(() => {
    setActiveDropdown(null);
    setNotifOpen(false);
    setMobileMenuOpen(false);
    setExpandedMobileGroups(new Set(['overview']));
    suppressHoverRef.current = false;
  }, []);

  const handleDropdownClick = useCallback((groupId: string) => {
    setActiveDropdown(prev => (prev === groupId ? null : groupId));
  }, []);

  const handleNavLinkClick = useCallback(() => {
    clearNavigationState();
    suppressHoverRef.current = true;
    setTimeout(() => {
      suppressHoverRef.current = false;
    }, 300);
  }, [clearNavigationState]);

  const handleGroupMouseEnter = useCallback((groupId: string) => {
    if (suppressHoverRef.current) return;
    setActiveDropdown(groupId);
  }, []);

  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        clearNavigationState();
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [clearNavigationState]);

  return (
    <header
      className="sticky top-0 z-50 border-b"
      style={{
        backgroundColor: 'var(--tw-panel)',
        borderColor: 'var(--tw-border)',
      }}
    >
      {/* ── Top bar ─────────────────────────────────────── */}
      <div className="flex items-center h-14 px-4 lg:px-8 gap-4">
        {/* Logo */}
        <Link to="/" className="flex items-center gap-2 shrink-0 group">
          <div className="w-7 h-7 rounded-sm flex items-center justify-center" style={{ backgroundColor: 'var(--tw-burgundy)' }}>
            <Shield size={14} className="text-[#FBFAF6]" />
          </div>
          <span
            className="font-mono text-sm font-medium tracking-[0.12em] uppercase transition-colors"
            style={{ color: 'var(--tw-text)' }}
          >
            PhishNet
          </span>
        </Link>

        {/* Org name — center */}
        <div className="flex-1 flex justify-center">
          <div className="hidden md:flex items-center gap-2" style={{ color: 'var(--tw-text-muted)' }}>
            <span className="font-mono text-xs tracking-wider">{currentAnalyst.organization}</span>
            <ChevronDown size={12} />
          </div>
        </div>

        {/* Right controls */}
        <div className="flex items-center gap-2">
          {/* Search */}
          <button
            className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-sm transition-colors"
            style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}
          >
            <Search size={13} />
            <span className="font-mono text-xs">Search evidence…</span>
            <span
              className="font-mono text-[10px] px-1.5 rounded-sm"
              style={{ background: 'var(--tw-border-mid)', color: 'var(--tw-text-faint)' }}
            >
              ⌘K
            </span>
          </button>

          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            className="p-2 rounded-sm transition-all duration-200 hover:scale-110"
            style={{ color: 'var(--tw-text-muted)' }}
          >
            {isDark ? (
              <Sun size={16} className="transition-transform duration-300 rotate-0" />
            ) : (
              <Moon size={16} className="transition-transform duration-300 rotate-0" />
            )}
          </button>

          {/* Alerts bell */}
          <div className="relative">
            <button
              onClick={() => setNotifOpen(!notifOpen)}
              className="relative p-2 rounded-sm transition-colors"
              style={{ color: 'var(--tw-text-muted)' }}
              aria-label="Alerts"
            >
              <Bell size={16} />
              {openAlerts.length > 0 && (
                <span
                  className="absolute top-1 right-1 w-2 h-2 rounded-full"
                  style={{ backgroundColor: 'var(--tw-burgundy)' }}
                />
              )}
            </button>
            {notifOpen && (
              <div
                className="absolute right-0 top-full mt-1 w-80 rounded-sm shadow-lg z-50 border"
                style={{
                  backgroundColor: 'var(--tw-panel)',
                  borderColor: 'var(--tw-border)',
                }}
              >
                <div className="px-4 py-2.5 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <span className="font-mono text-xs tracking-widest uppercase" style={{ color: 'var(--tw-text-muted)' }}>
                    Active Alerts
                  </span>
                </div>
                {openAlerts.map(alert => (
                  <div
                    key={alert.id}
                    className="px-4 py-3 border-b cursor-pointer transition-colors"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = '')}
                  >
                    <p className="text-xs font-medium" style={{ color: 'var(--tw-text)' }}>{alert.title}</p>
                    <p className="text-[10px] font-mono mt-0.5" style={{ color: 'var(--tw-text-muted)' }}>
                      {alert.id} · {alert.severity}
                    </p>
                  </div>
                ))}
                <Link
                  to="/app/alerts"
                  className="block px-4 py-2.5 text-xs font-mono transition-colors"
                  style={{ color: 'var(--tw-burgundy)' }}
                  onClick={() => setNotifOpen(false)}
                >
                  View all alerts →
                </Link>
              </div>
            )}
          </div>

          {/* Analyst avatar */}
          <div className="flex items-center gap-2 cursor-pointer">
            <div
              className="w-7 h-7 rounded-sm border flex items-center justify-center"
              style={{
                backgroundColor: 'color-mix(in srgb, var(--tw-burgundy) 22%, transparent)',
                borderColor: 'color-mix(in srgb, var(--tw-burgundy) 45%, transparent)',
              }}
            >
              <span className="font-mono text-xs font-medium" style={{ color: 'var(--tw-burgundy)' }}>
                {currentAnalyst.avatar}
              </span>
            </div>
            <div className="hidden lg:block">
              <p className="text-xs font-medium leading-none" style={{ color: 'var(--tw-text)' }}>
                {currentAnalyst.name}
              </p>
              <p className="font-mono text-[10px] leading-none mt-0.5" style={{ color: 'var(--tw-text-muted)' }}>
                {currentAnalyst.role}
              </p>
            </div>
          </div>

          {/* Mobile menu toggle */}
          <button
            className="md:hidden p-2 rounded-sm"
            style={{ color: 'var(--tw-text-muted)' }}
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Menu"
          >
            {mobileMenuOpen ? <X size={16} /> : <Menu size={16} />}
          </button>
        </div>
      </div>

      {/* ── Section nav ─────────────────────────────────── */}
      <nav
        ref={navRef}
        className="hidden md:flex items-center gap-0 px-8 h-9 border-t"
        style={{ borderColor: 'var(--tw-border-mid)' }}
      >
        {navGroups.map(group => {
          const hasActiveChild = group.items.some(item => location.pathname.startsWith(item.path));
          const isDropdownOpen = activeDropdown === group.id;
          const Icon = group.icon;
          
          return (
            <div 
              key={group.id}
              className="relative shrink-0"
              onMouseEnter={() => handleGroupMouseEnter(group.id)}
              onMouseLeave={() => setActiveDropdown(null)}
            >
              <button
                onClick={() => handleDropdownClick(group.id)}
                className={clsx(
                  'px-3 h-full flex items-center gap-1.5 font-mono text-xs tracking-wide border-b-2 transition-colors',
                )}
                style={{
                  borderBottomColor: hasActiveChild ? 'var(--tw-burgundy)' : 'transparent',
                  color: hasActiveChild ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
                }}
              >
                <Icon size={12} />
                {group.label}
                <ChevronDown size={10} className={clsx('transition-transform', isDropdownOpen && 'rotate-180')} />
              </button>

              {/* Dropdown */}
              {isDropdownOpen && (
                <div
                  className="absolute left-0 top-full mt-0 w-64 rounded-sm shadow-lg z-50 border"
                  style={{
                    backgroundColor: 'var(--tw-panel)',
                    borderColor: 'var(--tw-border)',
                  }}
                >
                  <div className="px-4 py-2.5 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    <span className="font-mono text-[10px] tracking-widest uppercase" style={{ color: 'var(--tw-text-muted)' }}>
                      {group.label}
                    </span>
                  </div>
                  {group.items.map(item => {
                    const active = location.pathname.startsWith(item.path);
                    return (
                      <Link
                        key={item.path}
                        to={item.path}
                        onClick={handleNavLinkClick}
                        className="block px-4 py-2.5 border-b last:border-0 cursor-pointer transition-colors"
                        style={{ 
                          borderColor: 'var(--tw-border-mid)',
                          backgroundColor: active ? 'var(--tw-panel-alt)' : 'transparent',
                          textDecoration: 'none',
                          color: 'inherit',
                        }}
                        onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
                        onMouseLeave={e => (e.currentTarget.style.backgroundColor = active ? 'var(--tw-panel-alt)' : '')}
                      >
                        <div className="flex items-start gap-2">
                          <p className="text-xs font-medium" style={{ color: active ? 'var(--tw-burgundy)' : 'var(--tw-text)' }}>
                            {item.label}
                          </p>
                        </div>
                        {item.description && (
                          <p className="text-[10px] mt-0.5" style={{ color: 'var(--tw-text-muted)' }}>
                            {item.description}
                          </p>
                        )}
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
        <div className="ml-auto pr-0 shrink-0">
          <Link
            to="/app/alerts"
            className="font-mono text-[10px] tracking-widest uppercase flex items-center gap-1.5"
            style={{ color: 'var(--tw-high)' }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full animate-pulse"
              style={{ backgroundColor: 'var(--tw-high)' }}
            />
            {openAlerts.length} Active Alerts
          </Link>
        </div>
      </nav>

      {/* ── Mobile nav dropdown ──────────────────────────── */}
      {mobileMenuOpen && (
        <nav
          className="md:hidden border-t"
          style={{ borderColor: 'var(--tw-border-mid)', backgroundColor: 'var(--tw-panel)' }}
        >
          {navGroups.map(group => {
            const Icon = group.icon;
            const hasActiveChild = group.items.some(item => location.pathname.startsWith(item.path));
            const groupExpanded = expandedMobileGroups.has(group.id);
            
            return (
              <div key={group.id}>
                <button
                  onClick={() => {
                    setExpandedMobileGroups(prev => {
                      const next = new Set(prev);
                      if (next.has(group.id)) {
                        next.delete(group.id);
                      } else {
                        next.add(group.id);
                      }
                      return next;
                    });
                  }}
                  className="w-full flex items-center justify-between px-6 py-3 font-mono text-sm border-l-2 transition-colors"
                  style={{
                    borderLeftColor: hasActiveChild ? 'var(--tw-burgundy)' : 'transparent',
                    color: hasActiveChild ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
                    backgroundColor: hasActiveChild ? 'var(--tw-panel-alt)' : 'transparent',
                  }}
                >
                  <div className="flex items-center gap-2">
                    <Icon size={14} />
                    {group.label}
                  </div>
                  <ChevronDown size={12} className={clsx('transition-transform', groupExpanded && 'rotate-180')} />
                </button>
                
                {groupExpanded && (
                  <div className="pl-12 pr-6 pb-2">
                    {group.items.map(item => {
                      const active = location.pathname.startsWith(item.path);
                      return (
                        <Link
                          key={item.path}
                          to={item.path}
                          onClick={() => setMobileMenuOpen(false)}
                          className="block py-2 font-mono text-xs transition-colors"
                          style={{
                            color: active ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
                          }}
                        >
                          {item.label}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </nav>
      )}
    </header>
  );
}
