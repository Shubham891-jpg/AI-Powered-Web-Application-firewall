import React from 'react';
import {
  X,
  ShieldAlert,
  BrainCircuit,
  Sliders,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Clock,
  Copy,
} from 'lucide-react';
import { SecurityEventItem } from '../types/security';

interface EventDetailModalProps {
  event: SecurityEventItem | null;
  onClose: () => void;
}

export const EventDetailModal: React.FC<EventDetailModalProps> = ({ event, onClose }) => {
  if (!event) return null;

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'BLOCK':
        return <span className="px-3 py-1 text-xs font-semibold uppercase tracking-wider rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/40">Blocked (HTTP 403)</span>;
      case 'FLAG':
        return <span className="px-3 py-1 text-xs font-semibold uppercase tracking-wider rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/40">Flagged (Audited)</span>;
      case 'RATE_LIMITED':
        return <span className="px-3 py-1 text-xs font-semibold uppercase tracking-wider rounded-full bg-orange-500/20 text-orange-400 border border-orange-500/40">Rate Limited (HTTP 429)</span>;
      default:
        return <span className="px-3 py-1 text-xs font-semibold uppercase tracking-wider rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">Allowed (HTTP 200)</span>;
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-rose-400';
    if (score >= 30) return 'text-amber-400';
    return 'text-emerald-400';
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="bg-[#0b0f19] border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
        {/* Header */}
        <div className="sticky top-0 z-10 bg-[#0b0f19]/95 backdrop-blur-md px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-slate-100">Security Inspection Forensics</h3>
                {getActionBadge(event.action)}
              </div>
              <p className="text-xs font-mono text-slate-400 mt-0.5">Correlation ID: {event.request_id}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-xl text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6">
          {/* Top Quick Stats Banner */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-[#111624] border border-slate-800/80">
              <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Composite Risk</div>
              <div className={`text-2xl font-bold font-mono mt-1 ${getRiskColor(event.risk_score)}`}>
                {event.risk_score} / 100
              </div>
            </div>

            <div className="p-4 rounded-xl bg-[#111624] border border-slate-800/80">
              <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Attack Category</div>
              <div className="text-sm font-bold text-slate-200 mt-2 truncate">
                {event.attack_category}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-[#111624] border border-slate-800/80">
              <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Client Source IP</div>
              <div className="text-sm font-mono font-bold text-cyan-400 mt-2">
                {event.client_ip}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-[#111624] border border-slate-800/80">
              <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Pipeline Latency</div>
              <div className="text-sm font-mono font-bold text-slate-200 mt-2 flex items-center gap-1.5">
                <Clock className="w-4 h-4 text-slate-500" />
                {event.processing_latency_ms.toFixed(2)} ms
              </div>
            </div>
          </div>

          {/* Primary Reason Alert */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Primary Enforcement Reason</span>
              <p className="text-sm text-slate-200 mt-0.5 font-medium">{event.primary_reason}</p>
            </div>
          </div>

          {/* Multi-Vector Analysis Breakdown (Rules + ML) */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Supervised ML Classification Card */}
            <div className="p-5 rounded-xl bg-[#111624] border border-slate-800 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 text-indigo-400 mb-3">
                  <BrainCircuit className="w-5 h-5" />
                  <h4 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Supervised ML Prediction</h4>
                </div>
                {event.ml_prediction ? (
                  <div className="space-y-3 text-xs font-mono">
                    <div className="flex justify-between py-1 border-b border-slate-800">
                      <span className="text-slate-400">Class:</span>
                      <span className="text-indigo-300 font-bold">{event.ml_prediction.predicted_class}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800">
                      <span className="text-slate-400">Probability:</span>
                      <span className="text-indigo-300 font-bold">{(event.ml_prediction.confidence * 100).toFixed(1)}%</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800">
                      <span className="text-slate-400">Model Version:</span>
                      <span className="text-slate-300">{event.ml_prediction.model_version || '1.0.0'}</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-slate-400">Inference Time:</span>
                      <span className="text-slate-300">{(event.ml_prediction.latency_ms || 0.55).toFixed(2)} ms</span>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic">No ML inference recorded.</p>
                )}
              </div>
            </div>

            {/* Deterministic Rule Engine Matches */}
            <div className="p-5 rounded-xl bg-[#111624] border border-slate-800 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 text-rose-400 mb-3">
                  <Flame className="w-5 h-5" />
                  <h4 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Deterministic Rule Matches</h4>
                </div>
                {event.matched_rules && event.matched_rules.length > 0 ? (
                  <div className="space-y-2">
                    {event.matched_rules.map((rule, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs">
                        <div className="flex justify-between items-center mb-1">
                          <span className="font-mono font-bold text-rose-400">{rule.rule_id}</span>
                          <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 font-mono text-[10px]">
                            {rule.confidence} (+{rule.score} pts)
                          </span>
                        </div>
                        <p className="text-slate-300">{rule.name}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-xs text-emerald-400 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>No malicious rule patterns triggered.</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Contextual Heuristic Penalties */}
          {event.contextual_penalties && event.contextual_penalties.length > 0 && (
            <div className="p-4 rounded-xl bg-[#111624] border border-slate-800">
              <div className="flex items-center gap-2 text-amber-400 mb-3 text-sm font-bold uppercase tracking-wider">
                <Sliders className="w-4 h-4" />
                <span>Contextual Threat Penalties</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {event.contextual_penalties.map((penalty, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex justify-between items-center text-xs font-mono">
                    <span className="text-slate-300">{penalty.factor}</span>
                    <span className="text-amber-400 font-bold">+{penalty.penalty_points} pts</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Request Payloads (Raw vs Normalized) */}
          <div className="space-y-3">
            <div className="flex items-center justify-between text-sm font-bold text-slate-200">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <span>Inspection Payload Representation</span>
              </div>
              <button
                onClick={() => copyToClipboard(event.normalized_payload || event.path)}
                className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Normalized</span>
              </button>
            </div>
            <div className="p-3.5 rounded-xl bg-[#07090e] border border-slate-800/80 font-mono text-xs text-slate-300 overflow-x-auto break-all">
              <div className="text-[10px] uppercase text-slate-500 mb-1">Normalized Inspection String (UTF-8 NFKC & Canonicalized):</div>
              <div className="text-cyan-300">{event.normalized_payload || event.path}</div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 bg-[#0b0f19]/95 backdrop-blur-md px-6 py-4 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 text-sm font-medium rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
};
