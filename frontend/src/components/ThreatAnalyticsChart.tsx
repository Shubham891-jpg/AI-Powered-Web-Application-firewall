import React from 'react';
import { PieChart, Activity } from 'lucide-react';
import { DashboardSummary } from '../types/security';

interface ThreatAnalyticsChartProps {
  summary: DashboardSummary | null;
}

export const ThreatAnalyticsChart: React.FC<ThreatAnalyticsChartProps> = ({ summary }) => {
  const distribution = summary?.attack_distribution || {
    SQL_INJECTION: 4,
    CROSS_SITE_SCRIPTING: 3,
    COMMAND_INJECTION: 2,
    PATH_TRAVERSAL: 2,
    RATE_LIMIT_EXCEEDED: 1,
  };

  const totalThreats = Object.values(distribution).reduce((a, b) => a + b, 0);

  const categoryColors: Record<string, { bg: string; text: string; bar: string }> = {
    SQL_INJECTION: { bg: 'bg-rose-500/20', text: 'text-rose-400', bar: 'bg-rose-500' },
    CROSS_SITE_SCRIPTING: { bg: 'bg-amber-500/20', text: 'text-amber-400', bar: 'bg-amber-500' },
    COMMAND_INJECTION: { bg: 'bg-purple-500/20', text: 'text-purple-400', bar: 'bg-purple-500' },
    PATH_TRAVERSAL: { bg: 'bg-cyan-500/20', text: 'text-cyan-400', bar: 'bg-cyan-500' },
    RATE_LIMIT_EXCEEDED: { bg: 'bg-orange-500/20', text: 'text-orange-400', bar: 'bg-orange-500' },
  };

  // Mock hourly timeline data points for SVG chart
  const timelinePoints = [
    { time: '10:00', allow: 45, flag: 8, block: 12 },
    { time: '11:00', allow: 60, flag: 12, block: 18 },
    { time: '12:00', allow: 80, flag: 15, block: 25 },
    { time: '13:00', allow: 55, flag: 9, block: 14 },
    { time: '14:00', allow: 90, flag: 20, block: 32 },
    { time: '15:00', allow: 70, flag: 11, block: 19 },
    { time: '16:00', allow: 85, flag: 14, block: 22 },
  ];

  const maxTraffic = Math.max(...timelinePoints.map((p) => p.allow + p.flag + p.block));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* 1. Request Flow Timeline Chart (SVG) */}
      <div className="lg:col-span-2 p-6 rounded-2xl bg-[#0e1320] border border-slate-800 flex flex-col justify-between shadow-xl">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                Real-Time Request Flow & Threat Interception
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Continuous traffic volume and enforcement actions</p>
            </div>
          </div>
          <div className="flex items-center gap-4 text-xs">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              Allowed
            </span>
            <span className="flex items-center gap-1.5 text-amber-400">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
              Flagged
            </span>
            <span className="flex items-center gap-1.5 text-rose-400">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
              Blocked
            </span>
          </div>
        </div>

        {/* Timeline Bar Chart */}
        <div className="h-44 flex items-end justify-between gap-3 pt-6 border-b border-slate-800/80 pb-2">
          {timelinePoints.map((pt, i) => {
            const total = pt.allow + pt.flag + pt.block;
            const heightPercent = (total / maxTraffic) * 100;
            const blockPercent = (pt.block / total) * 100;
            const flagPercent = (pt.flag / total) * 100;
            const allowPercent = (pt.allow / total) * 100;

            return (
              <div key={i} className="flex-1 flex flex-col items-center gap-2 group h-full justify-end">
                <div
                  className="w-full max-w-[32px] rounded-lg overflow-hidden flex flex-col-reverse transition-all group-hover:brightness-125"
                  style={{ height: `${heightPercent}%` }}
                >
                  <div className="bg-emerald-500/80 w-full" style={{ height: `${allowPercent}%` }} />
                  <div className="bg-amber-500/80 w-full" style={{ height: `${flagPercent}%` }} />
                  <div className="bg-rose-500/80 w-full" style={{ height: `${blockPercent}%` }} />
                </div>
                <span className="text-[10px] font-mono text-slate-500 group-hover:text-slate-300 transition-colors">
                  {pt.time}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* 2. Threat Category Distribution Breakdown */}
      <div className="p-6 rounded-2xl bg-[#0e1320] border border-slate-800 flex flex-col justify-between shadow-xl">
        <div>
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
              <PieChart className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                Threat Classification
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">{totalThreats} total attacks intercepted</p>
            </div>
          </div>

          <div className="space-y-4">
            {Object.entries(distribution).map(([cat, count]) => {
              const pct = totalThreats > 0 ? ((count / totalThreats) * 100).toFixed(0) : '0';
              const conf = categoryColors[cat] || {
                bg: 'bg-slate-800',
                text: 'text-slate-300',
                bar: 'bg-slate-500',
              };

              return (
                <div key={cat} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-medium text-slate-300">{cat.replace(/_/g, ' ')}</span>
                    <span className={`font-mono font-bold ${conf.text}`}>
                      {count} ({pct}%)
                    </span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden border border-slate-800">
                    <div
                      className={`h-full ${conf.bar} rounded-full transition-all duration-500`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
