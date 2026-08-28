import React, { useState, useEffect } from 'react';
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Eye,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { SecurityEventItem } from '../types/security';
import { api } from '../services/api';
import { EventDetailModal } from './EventDetailModal';

export const SecurityEventsTable: React.FC = () => {
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);

  // Filters
  const [search, setSearch] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [actionFilter, setActionFilter] = useState<string>('ALL');
  const [page, setPage] = useState<number>(0);
  const pageSize = 10;

  const fetchEvents = async () => {
    try {
      setLoading(true);
      const data = await api.getSecurityEvents({
        category: categoryFilter !== 'ALL' ? categoryFilter : undefined,
        action: actionFilter !== 'ALL' ? actionFilter : undefined,
        search: search.trim() || undefined,
        limit: pageSize,
        offset: page * pageSize,
      });
      setEvents(data.events);
      setTotal(data.total);
    } catch (e) {
      console.error('Failed to load security events:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [categoryFilter, actionFilter, page]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(0);
    fetchEvents();
  };

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'BLOCK':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/40">
            <ShieldAlert className="w-3.5 h-3.5" />
            BLOCK
          </span>
        );
      case 'FLAG':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/40">
            <AlertTriangle className="w-3.5 h-3.5" />
            FLAG
          </span>
        );
      case 'RATE_LIMITED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold rounded-lg bg-orange-500/20 text-orange-400 border border-orange-500/40">
            <Flame className="w-3.5 h-3.5" />
            LIMITED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
            <ShieldCheck className="w-3.5 h-3.5" />
            ALLOW
          </span>
        );
    }
  };

  const getRiskScoreBar = (score: number) => {
    let color = 'bg-emerald-500';
    let textColor = 'text-emerald-400';
    if (score >= 70) {
      color = 'bg-rose-500';
      textColor = 'text-rose-400';
    } else if (score >= 30) {
      color = 'bg-amber-500';
      textColor = 'text-amber-400';
    }

    return (
      <div className="flex items-center gap-2">
        <div className="w-16 h-2 rounded-full bg-slate-800 overflow-hidden">
          <div className={`h-full ${color}`} style={{ width: `${score}%` }} />
        </div>
        <span className={`text-xs font-mono font-bold ${textColor}`}>{score}</span>
      </div>
    );
  };

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="space-y-6">
      {/* Search & Filter Header Bar */}
      <div className="p-4 rounded-2xl bg-[#0e1320] border border-slate-800 flex flex-col md:flex-row gap-4 justify-between items-center">
        {/* Search */}
        <form onSubmit={handleSearchSubmit} className="relative w-full md:w-80">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search IP, path, category, ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 text-xs rounded-xl bg-slate-900 border border-slate-700/80 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
          />
        </form>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
          {/* Action Filter */}
          <div className="flex items-center rounded-xl bg-slate-900 border border-slate-800 p-1">
            {['ALL', 'BLOCK', 'FLAG', 'ALLOW'].map((act) => (
              <button
                key={act}
                onClick={() => {
                  setActionFilter(act);
                  setPage(0);
                }}
                className={`px-3 py-1 text-xs font-medium rounded-lg transition-colors ${
                  actionFilter === act
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {act}
              </button>
            ))}
          </div>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => {
              setCategoryFilter(e.target.value);
              setPage(0);
            }}
            className="px-3 py-1.5 text-xs rounded-xl bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Threat Categories</option>
            <option value="SQL_INJECTION">SQL Injection</option>
            <option value="CROSS_SITE_SCRIPTING">Cross-Site Scripting</option>
            <option value="COMMAND_INJECTION">Command Injection</option>
            <option value="PATH_TRAVERSAL">Path Traversal</option>
            <option value="RATE_LIMIT_EXCEEDED">Rate Limit Exceeded</option>
            <option value="NORMAL">Normal Traffic</option>
          </select>

          {/* Refresh Button */}
          <button
            onClick={fetchEvents}
            disabled={loading}
            className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Events Data Table */}
      <div className="rounded-2xl bg-[#0e1320] border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-900/80 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3.5 px-4">Action</th>
                <th className="py-3.5 px-4">Risk Score</th>
                <th className="py-3.5 px-4">Category</th>
                <th className="py-3.5 px-4">Method & Path</th>
                <th className="py-3.5 px-4">Client IP</th>
                <th className="py-3.5 px-4">Primary Reason</th>
                <th className="py-3.5 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
                      <span>Loading security events...</span>
                    </div>
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    No security events found matching current criteria.
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr
                    key={ev.id}
                    className="hover:bg-slate-800/30 transition-colors group cursor-pointer"
                    onClick={() => setSelectedEvent(ev)}
                  >
                    <td className="py-3 px-4 whitespace-nowrap">{getActionBadge(ev.action)}</td>
                    <td className="py-3 px-4 whitespace-nowrap">{getRiskScoreBar(ev.risk_score)}</td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono font-medium text-slate-300">
                      {ev.attack_category}
                    </td>
                    <td className="py-3 px-4 font-mono max-w-xs truncate">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 mr-2">
                        {ev.http_method}
                      </span>
                      <span className="text-slate-200">{ev.path}</span>
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan-400 whitespace-nowrap">{ev.client_ip}</td>
                    <td className="py-3 px-4 text-slate-400 max-w-sm truncate">{ev.primary_reason}</td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(ev);
                        }}
                        className="p-1.5 rounded-lg bg-slate-800/60 hover:bg-cyan-500/20 hover:text-cyan-300 text-slate-400 transition-colors"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Table Footer with Pagination */}
        <div className="px-6 py-3.5 bg-slate-900/60 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing <span className="font-semibold text-slate-200">{events.length}</span> of{' '}
            <span className="font-semibold text-slate-200">{total}</span> events
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span>
              Page {page + 1} of {Math.max(1, totalPages)}
            </span>
            <button
              onClick={() => setPage((p) => (p + 1 < totalPages ? p + 1 : p))}
              disabled={page + 1 >= totalPages}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Forensic Detail Modal */}
      {selectedEvent && (
        <EventDetailModal event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}
    </div>
  );
};
