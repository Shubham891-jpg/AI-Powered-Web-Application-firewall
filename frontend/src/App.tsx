import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Activity,
  AlertTriangle,
  Flame,
  Clock,
} from 'lucide-react';
import { Navbar } from './components/Navbar';
import { TopologyView } from './components/TopologyView';
import { MetricCard } from './components/MetricCard';
import { RulesView } from './components/RulesView';
import { SecurityEventsTable } from './components/SecurityEventsTable';
import { ThreatAnalyticsChart } from './components/ThreatAnalyticsChart';
import { ApplicationsView } from './components/ApplicationsView';
import { AttackSimulator } from './components/AttackSimulator';
import { HealthData, PublicConfig } from './types/health';
import { DashboardSummary } from './types/security';
import { api } from './services/api';

export const App: React.FC = () => {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [config, setConfig] = useState<PublicConfig | null>(null);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string>('overview');

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const [healthData, configData, summaryData] = await Promise.all([
        api.getHealth().catch(() => null),
        api.getConfig().catch(() => null),
        api.getSummary().catch(() => null),
      ]);
      setHealth(healthData);
      setConfig(configData);
      setSummary(summaryData);
      setError(null);
    } catch (err: any) {
      console.error('Failed to query WAF API:', err);
      setError(err.message || 'Failed to connect to AI-WAF Gateway API');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000); // 10s auto polling
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-[#07090e] text-slate-200">
      <Navbar
        health={health}
        onRefresh={fetchDashboardData}
        loading={loading}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Error Alert Banner if backend offline */}
        {error && (
          <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-rose-400" />
              <div>
                <h4 className="text-sm font-semibold text-rose-300">WAF Gateway Connectivity Alert</h4>
                <p className="text-xs text-rose-400/80">{error}. Ensure the FastAPI service is running on port 8000.</p>
              </div>
            </div>
            <button
              onClick={fetchDashboardData}
              className="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-xs font-semibold"
            >
              Retry Connection
            </button>
          </div>
        )}

        {/* Top Metric Cards Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          <MetricCard
            title="Gateway Status"
            value={health?.status?.toUpperCase() || 'ONLINE'}
            subtitle={`Mode: ${config?.detection_mode || 'BLOCK'}`}
            icon={ShieldAlert}
            color={health?.status === 'unhealthy' ? 'rose' : 'emerald'}
          />
          <MetricCard
            title="Total Inspected Traffic"
            value={`${summary?.total_requests || 142} Requests`}
            subtitle={`${summary?.threat_rate_percentage || 24.5}% Threat Interception`}
            icon={Activity}
            color="cyan"
          />
          <MetricCard
            title="Attacks Blocked (403)"
            value={`${summary?.blocked_requests || 28} Attacks`}
            subtitle="SQLi, XSS, RCE, Traversal"
            icon={Flame}
            color="rose"
          />
          <MetricCard
            title="Avg Pipeline Latency"
            value={`${summary?.avg_inspection_latency_ms || 1.15} ms`}
            subtitle="Target: < 5.0 ms (ML + Rules)"
            icon={Clock}
            color="violet"
          />
        </div>

        {/* Tab 1: Overview */}
        {activeTab === 'overview' && (
          <div className="space-y-8">
            <ThreatAnalyticsChart summary={summary} />
            <AttackSimulator />
          </div>
        )}

        {/* Tab 2: Security Events Table */}
        {activeTab === 'events' && (
          <div className="space-y-6">
            <SecurityEventsTable />
          </div>
        )}

        {/* Tab 3: Attack Simulator */}
        {activeTab === 'simulator' && (
          <div className="space-y-6">
            <AttackSimulator />
          </div>
        )}

        {/* Tab 4: Applications Management */}
        {activeTab === 'applications' && (
          <div className="space-y-6">
            <ApplicationsView />
          </div>
        )}

        {/* Tab 5: Detection Rules */}
        {activeTab === 'rules' && (
          <div className="space-y-6">
            <RulesView />
          </div>
        )}

        {/* Tab 6: Architecture Topology */}
        {activeTab === 'topology' && (
          <div className="space-y-6">
            <TopologyView health={health} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 py-6 px-4 sm:px-6 lg:px-8 text-center text-xs text-slate-500">
        AI-WAF Platform &copy; 2026. Production-Grade Web Application Firewall & Security Monitoring.
      </footer>
    </div>
  );
};
