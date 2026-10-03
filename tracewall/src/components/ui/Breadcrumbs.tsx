import { Link, useLocation } from 'react-router-dom';
import { ChevronRight, Home } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { breadcrumbsFor } from '../../lib/darkweb/navConfig';

export function Breadcrumbs() {
  const location = useLocation();
  useTheme();

  const breadcrumbs = breadcrumbsFor(location.pathname);

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
