import { Link, useLocation } from 'react-router-dom';
import { ChevronRight, Home } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

interface BreadcrumbItem {
  label: string;
  path: string;
}

export function Breadcrumbs() {
  const location = useLocation();
  useTheme();

  // Define navigation hierarchy
  const getBreadcrumbs = (): BreadcrumbItem[] => {
    const path = location.pathname;
    
    // Root/app level
    if (path === '/app' || path === '/app/briefing') {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Daily Briefing', path: '/app/briefing' },
      ];
    }

    // Analysis group
    if (path.startsWith('/app/investigate')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Analysis', path: '/app/investigate' },
        { label: 'Email Analysis', path: '/app/investigate' },
      ];
    }
    if (path.startsWith('/app/file-analysis')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Analysis', path: '/app/investigate' },
        { label: 'File Analysis', path: '/app/file-analysis' },
      ];
    }
    if (path.startsWith('/app/url-analysis')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Analysis', path: '/app/investigate' },
        { label: 'URL Analysis', path: '/app/url-analysis' },
      ];
    }
    if (path.startsWith('/app/infrastructure')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Analysis', path: '/app/investigate' },
        { label: 'Infrastructure', path: '/app/infrastructure' },
      ];
    }

    // Dark-Web Monitoring group
    if (path.startsWith('/app/exposure')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Dark-Web Monitoring', path: '/app/exposure' },
        { label: 'Exposure Monitor', path: '/app/exposure' },
      ];
    }

    // Threat Intelligence group
    if (path.startsWith('/app/intelligence')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Threat Intelligence', path: '/app/intelligence' },
        { label: 'IOC Workbench', path: '/app/intelligence' },
      ];
    }

    // AI Feedback group
    if (path.startsWith('/app/campaigns')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'AI Feedback', path: '/app/campaigns' },
        { label: 'Community Feedback', path: '/app/campaigns' },
      ];
    }

    // Investigations group
    if (path.startsWith('/app/cases')) {
      const parts = path.split('/');
      const caseId = parts[3];
      
      const crumbs: BreadcrumbItem[] = [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Investigations', path: '/app/cases' },
        { label: 'Investigation Cases', path: '/app/cases' },
      ];
      
      if (caseId) {
        crumbs.push({ label: `Case ${caseId}`, path: path });
      }
      
      return crumbs;
    }

    // Response and Alerts group
    if (path.startsWith('/app/alerts')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Response and Alerts', path: '/app/alerts' },
        { label: 'Alert Center', path: '/app/alerts' },
      ];
    }
    if (path.startsWith('/app/decisions')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Response and Alerts', path: '/app/alerts' },
        { label: 'Decision Desk', path: '/app/decisions' },
      ];
    }

    // Reports and Evidence group
    if (path.startsWith('/app/evidence')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Reports and Evidence', path: '/app/evidence' },
        { label: 'Evidence', path: '/app/evidence' },
      ];
    }
    if (path.startsWith('/app/reports')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Reports and Evidence', path: '/app/evidence' },
        { label: 'Reports', path: '/app/reports' },
      ];
    }

    // Administration group
    if (path.startsWith('/app/audit')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Administration', path: '/app/settings' },
        { label: 'Audit Logs', path: '/app/audit' },
      ];
    }
    if (path.startsWith('/app/settings')) {
      return [
        { label: 'Overview', path: '/app/briefing' },
        { label: 'Administration', path: '/app/settings' },
        { label: 'Settings', path: '/app/settings' },
      ];
    }

    // Default fallback
    return [
      { label: 'Overview', path: '/app/briefing' },
    ];
  };

  const breadcrumbs = getBreadcrumbs();

  // Don't show breadcrumbs on landing page or if only one item
  if (breadcrumbs.length <= 1 || location.pathname === '/') {
    return null;
  }

  return (
    <nav
      className="flex items-center gap-2 px-6 lg:px-10 py-3 font-mono text-xs"
      style={{ color: 'var(--tw-text-muted)' }}
      aria-label="Breadcrumb navigation"
    >
      {breadcrumbs.map((crumb, index) => {
        const isLast = index === breadcrumbs.length - 1;
        
        return (
          <div key={`${crumb.path}-${index}`} className="flex items-center gap-2">
            {index === 0 && <Home size={12} />}
            
            {index > 0 && <ChevronRight size={12} />}
            
            {isLast ? (
              <span
                className="font-medium"
                style={{ color: 'var(--tw-text)' }}
              >
                {crumb.label}
              </span>
            ) : (
              <Link
                to={crumb.path}
                className="transition-colors hover:text-[var(--tw-burgundy)]"
                style={{ color: 'var(--tw-text-muted)' }}
              >
                {crumb.label}
              </Link>
            )}
          </div>
        );
      })}
    </nav>
  );
}
