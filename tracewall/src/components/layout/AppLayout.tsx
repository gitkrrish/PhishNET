import { Outlet } from 'react-router-dom';
import { AppMasthead } from './AppMasthead';
import { Breadcrumbs } from '../ui/Breadcrumbs';

export function AppLayout() {
  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--tw-canvas)' }}>
      <AppMasthead />
      <Breadcrumbs />
      <main className="page-enter">
        <Outlet />
      </main>
    </div>
  );
}
