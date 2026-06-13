import VulnerabilityTable from '@/components/VulnerabilityTable';

export default function VulnerabilitiesPage() {
  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-bold">Vulnerabilities</h2>
        <p className="text-surface-400 text-sm mt-1">Browse and filter all detected vulnerabilities</p>
      </div>
      <VulnerabilityTable />
    </div>
  );
}