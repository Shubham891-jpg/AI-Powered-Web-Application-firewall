import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Server,
  Zap,
  Database,
  Activity,
  AlertTriangle,
  Send,
  Lock,
  CheckCircle2,
  XCircle,
  Clock,
  Terminal,
} from 'lucide-react';
import { Navbar } from './components/Navbar';
import { TopologyView } from './components/TopologyView';
import { MetricCard } from './components/MetricCard';
import { StatusBadge } from './components/StatusBadge';
import { RulesView } from './components/RulesView';
import { HealthData, PublicConfig } from './types/health';
import { api } from './services/api';

export const App: React.FC = () => {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [config, setConfig] = useState<PublicConfig | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string>('overview');

  // Interactive Live Probe Test Console
  const [probePath, setProbePath] = useState<string>('/search?q=normal');
  const [probeResponse, setProbeResponse] = useState<any>(null);
  const [probing, setProbing] = useState<boolean>(false);

  const fetchHealthAndConfig = async () => {
    try {
      setLoading(true);
      const [healthData, configData] = await Promise.all([
        api.getHealth(),
        api.getConfig(),
      ]);
      setHealth(healthData);
      setConfig(configData);
      setError(null);
    } catch (err: any) {
      console.error('Failed to query WAF API:', err);
      setError(err.message || 'Failed to connect to AI-WAF Gateway API');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealthAndConfig();
    const interval = setInterval(fetchHealthAndConfig, 10000); // 10s auto polling
    return () => clearInterval(interval);
  }, []);

  const handleRunProbe = async (pathOverride?: string) => {
    const target = pathOverride || probePath;
    try {
      setProbing(true);
      const res = await fetch(target, {
        method: 'GET',
      });
      const data = await res.json().catch(() => ({ status_text: res.statusText }));
      setProbeResponse({
        status: res.status,
        headers: {
          'x-request-id': res.headers.get('x-request-id'),
          'x-waf-action': res.headers.get('x-waf-action') || 'ALLOW',
        },
        body: data,
      });
    } catch (e: any) {
      setProbeResponse({
        status: 500,
        error: e.message,
      });
    } finally {
      setProbing(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#07090e] text-slate-200">
      <Navbar
        health={health}
        onRefresh={fetchHealthAndConfig}
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
              onClick={fetchHealthAndConfig}
              className="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-xs font-semibold"
            >
              Retry Connection
            </button>
          </div>
        )}

        {/* Top Metric Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          <MetricCard
            title="Gateway Status"
            value={health?.status?.toUpperCase() || 'OFFLINE'}
            subtitle={`Mode: ${config?.detection_mode || 'BLOCK'}`}
            icon={ShieldAlert}
            color={health?.status === 'healthy' ? 'emerald' : 'amber'}
          />
          <MetricCard
            title="Avg Inspection Latency"
            value="1.2 ms"
            subtitle="Target: < 5.0 ms (ML + Rules)"
            icon={Zap}
            color="cyan"
          />
          <MetricCard
            title="Protected Upstream"
            value={health?.components.upstream.status?.toUpperCase() || 'UNKNOWN'}
            subtitle={config?.upstream_url || 'http://protected-demo-app:3000'}
            icon={Server}
            color={health?.components.upstream.status === 'healthy' ? 'emerald' : 'rose'}
          />
          <MetricCard
            title="Active Rules"
            value="4 Rules Loaded"
            subtitle="SQLi, XSS, RCE, Traversal"
            icon={Lock}
            color="violet"
          />
        </div>

        {activeTab === 'rules' && <RulesView />}

        {activeTab === 'topology' && (
          <div className="space-y-6">
            <TopologyView health={health} />
          </div>
        )}

        {(activeTab === 'overview' || (activeTab !== 'rules' && activeTab !== 'topology')) && (
          <>
            {/* Architecture Topology View */}
            <TopologyView health={health} />

        {/* Subsystem Health Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Redis Card */}
          <div className="glass-panel rounded-xl p-5 border border-slate-800">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  <Zap className="w-4 h-4" />
                </div>
                <div>
                  <h4 className="font-semibold text-slate-200 text-sm">Redis Rate Limiter</h4>
                  <p className="text-[11px] text-slate-400">Sliding Window Counter Cache</p>
                </div>
              </div>
              <StatusBadge status={health?.components.redis.status || 'degraded'} size="sm" />
            </div>
            <div className="space-y-2 text-xs text-slate-400">
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span>Latency</span>
                <span className="font-mono text-slate-200">{health?.components.redis.latency_ms ?? '--'} ms</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span>Rate Limit Policy</span>
                <span className="font-mono text-slate-200">{config?.rate_limiting.requests ?? 100} req / {config?.rate_limiting.window_seconds ?? 60}s</span>
              </div>
              <div className="flex justify-between py-1">
                <span>Status Detail</span>
                <span className="truncate max-w-[160px] text-right font-mono text-[11px] text-slate-300">
                  {health?.components.redis.details.message || 'Connecting...'}
                </span>
              </div>
            </div>
          </div>

          {/* PostgreSQL Card */}
          <div className="glass-panel rounded-xl p-5 border border-slate-800">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20">
                  <Database className="w-4 h-4" />
                </div>
                <div>
                  <h4 className="font-semibold text-slate-200 text-sm">PostgreSQL Storage</h4>
                  <p className="text-[11px] text-slate-400">Security Events & Audit Database</p>
                </div>
              </div>
              <StatusBadge status={health?.components.database.status || 'degraded'} size="sm" />
            </div>
            <div className="space-y-2 text-xs text-slate-400">
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span>Query Latency</span>
                <span className="font-mono text-slate-200">{health?.components.database.latency_ms ?? '--'} ms</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span>Pool Status</span>
                <span className="font-mono text-slate-200">AsyncPool (10 connections)</span>
              </div>
              <div className="flex justify-between py-1">
                <span>Status Detail</span>
                <span className="truncate max-w-[160px] text-right font-mono text-[11px] text-slate-300">
                  {health?.components.database.details.message || 'Connecting...'}
                </span>
              </div>
            </div>
          </div>

          {/* Detection Engine Card */}
          <div className="glass-panel rounded-xl p-5 border border-slate-800">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <div>
                  <h4 className="font-semibold text-slate-200 text-sm">Threat Decision Matrix</h4>
                  <p className="text-[11px] text-slate-400">Score Range: 0 - 100</p>
                </div>
              </div>
              <StatusBadge status="healthy" size="sm" />
            </div>
            <div className="space-y-2 text-xs text-slate-400">
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span>Allow Threshold</span>
                <span className="font-mono text-emerald-400">0 - {config?.thresholds.allow ?? 29}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span>Flag Threshold</span>
                <span className="font-mono text-amber-400">{(config?.thresholds.allow ?? 29) + 1} - {config?.thresholds.flag ?? 69}</span>
              </div>
              <div className="flex justify-between py-1">
                <span>Block Threshold</span>
                <span className="font-mono text-rose-400">{config?.thresholds.block ?? 70} - 100</span>
              </div>
            </div>
          </div>
        </div>

        {/* Live Traffic Inspector & Diagnostic Test Console */}
        <div className="glass-panel rounded-2xl p-6 border border-slate-800 space-y-5">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Terminal className="w-5 h-5 text-cyan-400" />
                Live Traffic Simulation & Policy Tester
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Dispatch test HTTP requests through the AI-WAF reverse proxy to verify transparent forwarding or real-time blocking.
              </p>
            </div>
          </div>

          {/* Quick Presets */}
          <div className="flex flex-wrap gap-2 items-center">
            <span className="text-xs text-slate-400 mr-2">Quick Probes:</span>
            <button
              onClick={() => {
                setProbePath('/search?q=laptop');
                handleRunProbe('/search?q=laptop');
              }}
              className="px-3 py-1 rounded-lg text-xs font-semibold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/20 transition-all flex items-center gap-1.5"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              Legitimate Query (ALLOW)
            </button>
            <button
              onClick={() => {
                setProbePath('/search?q=1%27%20UNION%20SELECT%20username,%20password%20FROM%20users--');
                handleRunProbe('/search?q=1%27%20UNION%20SELECT%20username,%20password%20FROM%20users--');
              }}
              className="px-3 py-1 rounded-lg text-xs font-semibold bg-rose-500/10 text-rose-300 border border-rose-500/30 hover:bg-rose-500/20 transition-all flex items-center gap-1.5"
            >
              <XCircle className="w-3.5 h-3.5" />
              SQL Injection (BLOCK)
            </button>
            <button
              onClick={() => {
                setProbePath('/search?q=%2527%2520OR%25201%253D1');
                handleRunProbe('/search?q=%2527%2520OR%25201%253D1');
              }}
              className="px-3 py-1 rounded-lg text-xs font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/30 hover:bg-amber-500/20 transition-all flex items-center gap-1.5"
            >
              <XCircle className="w-3.5 h-3.5" />
              Double-Encoded SQLi (P2 Unwrapped)
            </button>
            <button
              onClick={() => {
                setProbePath('/search?q=%26lt;script%26gt;alert(1)%26lt;/script%26gt;');
                handleRunProbe('/search?q=%26lt;script%26gt;alert(1)%26lt;/script%26gt;');
              }}
              className="px-3 py-1 rounded-lg text-xs font-semibold bg-rose-500/10 text-rose-300 border border-rose-500/30 hover:bg-rose-500/20 transition-all flex items-center gap-1.5"
            >
              <XCircle className="w-3.5 h-3.5" />
              HTML Entity XSS (P2 Decoded)
            </button>
            <button
              onClick={() => {
                setProbePath('/files?filename=../../etc/passwd');
                handleRunProbe('/files?filename=../../etc/passwd');
              }}
              className="px-3 py-1 rounded-lg text-xs font-semibold bg-rose-500/10 text-rose-300 border border-rose-500/30 hover:bg-rose-500/20 transition-all flex items-center gap-1.5"
            >
              <XCircle className="w-3.5 h-3.5" />
              Path Traversal (BLOCK)
            </button>
            <button
              onClick={() => {
                setProbePath('/files?filename=report.pdf%00.exe');
                handleRunProbe('/files?filename=report.pdf%00.exe');
              }}
              className="px-3 py-1 rounded-lg text-xs font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/30 hover:bg-amber-500/20 transition-all flex items-center gap-1.5"
            >
              <AlertTriangle className="w-3.5 h-3.5" />
              Null-Byte Probe (%00)
            </button>
          </div>

          {/* Custom URL Input Bar */}
          <div className="flex gap-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={probePath}
                onChange={(e) => setProbePath(e.target.value)}
                placeholder="/search?q=..."
                className="w-full bg-slate-900/80 border border-slate-700/80 rounded-xl px-4 py-2.5 text-sm font-mono text-cyan-300 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50"
              />
            </div>
            <button
              onClick={() => handleRunProbe()}
              disabled={probing}
              className="px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs uppercase tracking-wider flex items-center gap-2 transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              {probing ? 'Inspecting...' : 'Send Request'}
            </button>
          </div>

          {/* Probe Response Output Console */}
          {probeResponse && (
            <div className="mt-4 p-4 rounded-xl bg-[#04060a] border border-slate-800 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between pb-2 border-b border-slate-900">
                <div className="flex items-center gap-3">
                  <span className="text-slate-400">Response Status:</span>
                  <span
                    className={`font-bold px-2 py-0.5 rounded ${
                      probeResponse.status === 200
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : probeResponse.status === 403
                        ? 'bg-rose-500/20 text-rose-400'
                        : 'bg-amber-500/20 text-amber-400'
                    }`}
                  >
                    HTTP {probeResponse.status}
                  </span>
                  {probeResponse.headers?.['x-waf-action'] && (
                    <span className="text-[11px] text-slate-400">
                      WAF Action: <strong className="text-cyan-400">{probeResponse.headers['x-waf-action']}</strong>
                    </span>
                  )}
                </div>
                {probeResponse.headers?.['x-request-id'] && (
                  <span className="text-[11px] text-slate-400 truncate max-w-[200px]">
                    ID: {probeResponse.headers['x-request-id']}
                  </span>
                )}
              </div>
              <pre className="text-slate-300 overflow-x-auto p-2 bg-slate-950/60 rounded">
                {JSON.stringify(probeResponse.body || probeResponse, null, 2)}
              </pre>
            </div>
          )}
        </div>
        </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 py-6 px-4 sm:px-6 lg:px-8 text-center text-xs text-slate-400">
        AI-WAF Platform &copy; 2026. Production-Grade Web Application Firewall & Security Monitoring.
      </footer>
    </div>
  );
};
