import { cn } from '@/lib/utils';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  trend?: string;
  className?: string;
}

export default function StatCard({ label, value, icon, trend, className }: StatCardProps) {
  return (
    <div className={cn('card flex items-start justify-between', className)}>
      <div>
        <p className="stat-label">{label}</p>
        <p className="stat-value mt-1">{value}</p>
        {trend && <p className="text-xs text-surface-400 mt-1">{trend}</p>}
      </div>
      <div className="p-2 bg-surface-800 rounded-lg">{icon}</div>
    </div>
  );
}