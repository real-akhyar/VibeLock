import { Routes, Route } from 'react-router-dom';
import Sidebar from '@/components/Sidebar';
import DashboardPage from '@/pages/DashboardPage';
import VulnerabilitiesPage from '@/pages/VulnerabilitiesPage';
import VulnerabilityDetailPage from '@/pages/VulnerabilityDetailPage';
import RepositoriesPage from '@/pages/RepositoriesPage';
import GitHubSetupPage from '@/pages/GitHubSetupPage';
import ApiKeysPage from '@/pages/ApiKeysPage';
import FeedbackPage from '@/pages/FeedbackPage';
import HealthPage from '@/pages/HealthPage';

export default function App() {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 ml-64 p-8">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="/vulnerabilities/:id" element={<VulnerabilityDetailPage />} />
          <Route path="/repositories" element={<RepositoriesPage />} />
          <Route path="/github-setup" element={<GitHubSetupPage />} />
          <Route path="/api-keys" element={<ApiKeysPage />} />
          <Route path="/feedback" element={<FeedbackPage />} />
          <Route path="/health" element={<HealthPage />} />
        </Routes>
      </main>
    </div>
  );
}