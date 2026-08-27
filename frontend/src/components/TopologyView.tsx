import React from 'react';
import { Shield, Globe, Server, Database, Zap, Cpu } from 'lucide-react';
import { HealthData } from '../types/health';
import { StatusBadge } from './StatusBadge';

interface TopologyViewProps {
  health: HealthData | null;
}

export const TopologyView: React.FC<TopologyViewProps> = ({ health }) => {
  const upstream = health?.components.upstream;
  const redis = health?.components.redis;
  const database = health?.components.database;
  const detection = health?.components.detection;

  return (
    <div className="glass-panel rounded-2xl p-6 relative overflow-hidden">
      <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-800/80">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            Security & Reverse Proxy Topology
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time pipeline routing from internet client boundary to upstream application
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400">Gateway Status:</span>
          <StatusBadge status={health?.status || 'degraded'} size="md" />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-center">
        {/* Node 1: Inbound Internet Clients */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col items-center text-center">
          <div className="p-3 rounded-full bg-cyan-500/10 text-cyan-400 mb-3 border border-cyan-500/20">
            <Globe className="w-6 h-6" />
          </div>
          <span className="text-xs font-semibold text-slate-400 uppercase">Edge Intake</span>
          <h4 className="font-semibold text-slate-200 mt-1">Clients / Internet</h4>
          <p className="text-[11px] text-slate-400 mt-1">Nginx Port 80 / 443</p>
          <div className="mt-3">
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
              ACTIVE
            </span>
          </div>
        </div>

        {/* Node 2: AI-WAF Reverse Proxy Gateway */}
        <div className="p-5 rounded-xl bg-cyan-950/20 border-2 border-cyan-500/30 shadow-lg shadow-cyan-500/5 flex flex-col items-center text-center relative">
          <div className="absolute -top-2.5 bg-cyan-500 text-slate-950 font-mono text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider">
            Gateway Core
          </div>
          <div className="p-3 rounded-full bg-cyan-500/20 text-cyan-300 mb-3 border border-cyan-400/40">
            <Shield className="w-7 h-7" />
          </div>
          <span className="text-xs font-semibold text-cyan-400 uppercase">Inspection Layer</span>
          <h4 className="font-bold text-slate-100 text-base mt-1">AI-WAF Engine</h4>
          <p className="text-[11px] text-slate-400 mt-1">FastAPI :8000 (Mode: BLOCK)</p>
          <div className="mt-3">
            <StatusBadge status="healthy" size="sm" />
          </div>
        </div>

        {/* Node 3: Detection Subsystems (DB / Redis / ML) */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-2">
          <div className="text-[11px] font-semibold text-slate-400 uppercase flex items-center justify-between pb-1 border-b border-slate-800">
            <span>Subsystems</span>
            <Cpu className="w-3.5 h-3.5 text-violet-400" />
          </div>

          <div className="flex items-center justify-between text-xs py-1">
            <span className="flex items-center gap-1.5 text-slate-300">
              <Zap className="w-3.5 h-3.5 text-amber-400" /> Redis Cache
            </span>
            <span className="font-mono text-[11px] text-slate-400">
              {redis?.latency_ms !== null ? `${redis?.latency_ms}ms` : '--'}
            </span>
          </div>

          <div className="flex items-center justify-between text-xs py-1">
            <span className="flex items-center gap-1.5 text-slate-300">
              <Database className="w-3.5 h-3.5 text-violet-400" /> PostgreSQL
            </span>
            <span className="font-mono text-[11px] text-slate-400">
              {database?.latency_ms !== null ? `${database?.latency_ms}ms` : '--'}
            </span>
          </div>

          <div className="flex items-center justify-between text-xs py-1">
            <span className="flex items-center gap-1.5 text-slate-300">
              <Shield className="w-3.5 h-3.5 text-emerald-400" /> Rule Engine
            </span>
            <span className="font-mono text-[10px] text-emerald-400">ACTIVE (4 Rules)</span>
          </div>
        </div>

        {/* Node 4: Upstream Protected Application */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col items-center text-center">
          <div className="p-3 rounded-full bg-emerald-500/10 text-emerald-400 mb-3 border border-emerald-500/20">
            <Server className="w-6 h-6" />
          </div>
          <span className="text-xs font-semibold text-slate-400 uppercase">Upstream Target</span>
          <h4 className="font-semibold text-slate-200 mt-1">Protected App</h4>
          <p className="text-[11px] text-slate-400 mt-1 font-mono truncate max-w-[160px]">
            {upstream?.details?.url || ':3000'}
          </p>
          <div className="mt-3">
            <StatusBadge status={upstream?.status || 'degraded'} size="sm" />
          </div>
        </div>
      </div>
    </div>
  );
};
