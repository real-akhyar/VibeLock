import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Shield,
  GitBranch,
  Key,
  Settings,
  Activity,
  Bug,
  BarChart3,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/vulnerabilities', icon: Shield, label: 'Vulnerabilities' },
  { to: '/repositories', icon: GitBranch, label: 'Repositories' },
  { to: '/github-setup', icon: Settings, label: 'GitHub Setup' },
  { to: '/api-keys', icon: Key, label: 'API Keys' },
  { to: '/feedback', icon: Bug, label: 'Feedback' },
  { to: '/health', icon: Activity, label: 'Health' },
];

export default function Sidebar() {
  const location = useLocation();

  return (
    <aside className="w-64 h-screen bg-surface-900 border-r border-surface-700 flex flex-col fixed left-0 top-0">
      <div className="p-5 border-b border-surface-700">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-brand-600 rounded-lg flex items-center justify-center">
            <BarChart3 className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight">VibeLock</h1>
            <p className="text-xs text-surface-400">Security Dashboard</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {navItems.map(({ to, icon: Icon, label }) => {
          const active = location.pathname === to || (to !== '/' && location.pathname.startsWith(to));
          return (
            <NavLink
              key={to}
              to={to}
              className={cn(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                active
                  ? 'bg-brand-600/20 text-brand-400'
                  : 'text-surface-400 hover:text-surface-200 hover:bg-surface-800',
              )}
            >
              <Icon className="w-4 h-4" />
              {label}
            </NavLink>
          );
        })}
      </nav>

      <div className="p-4 border-t border-surface-700">
        <div className="flex items-center gap-2 text-xs text-surface-500">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          System Online
        </div>
      </div>
    </aside>
  );
}