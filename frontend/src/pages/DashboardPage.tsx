import DashboardOverview from '@/components/DashboardOverview';

export default function DashboardPage() {
  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-bold">Dashboard</h2>
        <p className="text-surface-400 text-sm mt-1">Overview of your security posture</p>
      </div>
      <DashboardOverview />
    </div>
  );
}