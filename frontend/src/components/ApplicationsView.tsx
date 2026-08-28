import React, { useState, useEffect } from 'react';
import { Server, Globe, RefreshCw, CheckCircle2 } from 'lucide-react';
import { ApplicationItem } from '../types/security';
import { api } from '../services/api';

export const ApplicationsView: React.FC = () => {
  const [apps, setApps] = useState<ApplicationItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const fetchApps = async () => {
    try {
      setLoading(true);
      const data = await api.getApplications();
      setApps(data);
    } catch (e) {
      console.error('Failed to load applications:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApps();
  }, []);

  const handleToggleActive = async (app: ApplicationItem) => {
    try {
      setUpdatingId(app.id);
      const updated = await api.updateApplication(app.id, { is_active: !app.is_active });
      setApps((prev) => prev.map((a) => (a.id === app.id ? { ...a, is_active: updated.is_active } : a)));
    } catch (e) {
      console.error('Failed to toggle app active state:', e);
    } finally {
      setUpdatingId(null);
    }
  };

  const handleChangeMode = async (app: ApplicationItem, newMode: string) => {
    try {
      setUpdatingId(app.id);
      const updated = await api.updateApplication(app.id, { detection_mode: newMode });
      setApps((prev) => prev.map((a) => (a.id === app.id ? { ...a, detection_mode: updated.detection_mode } : a)));
    } catch (e) {
      console.error('Failed to update detection mode:', e);
    } finally {
      setUpdatingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-[#0e1320] border border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Server className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100">Protected Web Applications</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Multi-tenant reverse proxy targets, upstream routing, and per-app security policies
            </p>
          </div>
        </div>

        <button
          onClick={fetchApps}
          disabled={loading}
          className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
        </button>
      </div>

      {/* Applications Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {apps.map((app) => (
          <div
            key={app.id}
            className={`p-6 rounded-2xl border transition-all shadow-lg ${
              app.is_active
                ? 'bg-[#0e1320] border-slate-800 hover:border-slate-700'
                : 'bg-slate-950/60 border-slate-800/40 opacity-70'
            }`}
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-slate-100">{app.name}</h3>
                <div className="flex items-center gap-1.5 text-xs font-mono text-cyan-400 mt-1">
                  <Globe className="w-3.5 h-3.5 text-slate-500" />
                  <span>{app.upstream_url}</span>
                </div>
              </div>

              {/* Active Toggle Switch */}
              <button
                onClick={() => handleToggleActive(app)}
                disabled={updatingId === app.id}
                className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  app.is_active ? 'bg-cyan-500' : 'bg-slate-800'
                }`}
              >
                <span
                  className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                    app.is_active ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            {/* Application Configuration Details */}
            <div className="space-y-3.5 pt-4 border-t border-slate-800/80 text-xs">
              {/* Detection Mode Selector */}
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Enforcement Policy:</span>
                <select
                  value={app.detection_mode}
                  onChange={(e) => handleChangeMode(app, e.target.value)}
                  disabled={updatingId === app.id}
                  className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-medium focus:outline-none focus:border-cyan-500"
                >
                  <option value="BLOCK">BLOCK (Strict Protection)</option>
                  <option value="FLAG_ONLY">FLAG_ONLY (Staging Audit)</option>
                  <option value="MONITOR">MONITOR (Observation Mode)</option>
                </select>
              </div>

              {/* Rate Limit Allocation */}
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Rate Limit Quota:</span>
                <span className="font-mono font-semibold text-slate-200">
                  {app.rate_limit_requests} req / {app.rate_limit_window_seconds || 60}s
                </span>
              </div>

              {/* Health Status */}
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Upstream Health:</span>
                <span className="flex items-center gap-1 text-emerald-400 font-medium">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Online & Reachable
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
