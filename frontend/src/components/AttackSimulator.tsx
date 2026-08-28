import React, { useState } from 'react';
import {
  Terminal,
  Send,
  Zap,
  Flame,
  Clock,
  Radio,
  FileCode,
} from 'lucide-react';

interface ProbePreset {
  name: string;
  category: string;
  method: string;
  path: string;
  body?: string;
  description: string;
  danger: 'safe' | 'suspicious' | 'critical';
}

const PRESETS: ProbePreset[] = [
  {
    name: 'Normal Browsing',
    category: 'BENIGN',
    method: 'GET',
    path: '/products?category=electronics&limit=10',
    description: 'Legitimate e-commerce query. Must pass cleanly with ALLOW (HTTP 200).',
    danger: 'safe',
  },
  {
    name: 'SQL Injection (UNION)',
    category: 'SQLI',
    method: 'GET',
    path: "/products?search=%27%20UNION%20SELECT%20username,password%20FROM%20users--",
    description: 'High-confidence SQL tautology attack. Guaranteed immediate BLOCK (HTTP 403).',
    danger: 'critical',
  },
  {
    name: 'Cross-Site Scripting (XSS)',
    category: 'XSS',
    method: 'POST',
    path: '/api/feedback',
    body: '{"message": "<script>alert(document.cookie)</script>"}',
    description: 'Script payload injection into JSON body. Triggers high-confidence XSS block.',
    danger: 'critical',
  },
  {
    name: 'Command Injection (RCE)',
    category: 'RCE',
    method: 'POST',
    path: '/api/ping',
    body: '{"host": "127.0.0.1; cat /etc/passwd"}',
    description: 'Shell chaining operator exploitation targeting sensitive operating system files.',
    danger: 'critical',
  },
  {
    name: 'Path Traversal Probe',
    category: 'TRAVERSAL',
    method: 'GET',
    path: '/download?file=../../../../etc/shadow',
    description: 'Directory climb traversal probe seeking root credential hashes.',
    danger: 'critical',
  },
  {
    name: 'Double-Encoded Evasion',
    category: 'EVASION',
    method: 'GET',
    path: '/search?q=%25%32%37%25%32%30%55%4e%49%4f%4e%25%32%30%53%45%4c%45%43%54',
    description: 'Recursive double-URL encoding. Tests multi-pass decoding and evasion penalties.',
    danger: 'suspicious',
  },
];

export const AttackSimulator: React.FC = () => {
  const [selectedPreset, setSelectedPreset] = useState<ProbePreset>(PRESETS[0]);
  const [method, setMethod] = useState<string>(PRESETS[0].method);
  const [path, setPath] = useState<string>(PRESETS[0].path);
  const [body, setBody] = useState<string>(PRESETS[0].body || '');
  const [loading, setLoading] = useState<boolean>(false);
  const [response, setResponse] = useState<any>(null);

  // Burst Flooder State
  const [bursting, setBursting] = useState<boolean>(false);
  const [burstResults, setBurstResults] = useState<{ total: number; allowed: number; blocked: number } | null>(null);

  const applyPreset = (preset: ProbePreset) => {
    setSelectedPreset(preset);
    setMethod(preset.method);
    setPath(preset.path);
    setBody(preset.body || '');
    setResponse(null);
  };

  const handleSendProbe = async () => {
    try {
      setLoading(true);
      const t0 = performance.now();

      const options: RequestInit = {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-Security-Probe': 'AI-WAF-Dashboard-Simulator',
        },
      };
      if (method !== 'GET' && method !== 'HEAD' && body) {
        options.body = body;
      }

      const res = await fetch(path, options);
      const latency = (performance.now() - t0).toFixed(2);
      const data = await res.json().catch(() => ({ raw: res.statusText }));

      setResponse({
        status: res.status,
        statusText: res.statusText,
        latencyMs: latency,
        headers: {
          'X-WAF-Action': res.headers.get('x-waf-action') || 'ALLOW',
          'X-WAF-Risk-Score': res.headers.get('x-waf-risk-score') || '0',
          'X-WAF-Category': res.headers.get('x-waf-category') || 'NORMAL',
          'X-Request-ID': res.headers.get('x-request-id') || 'sim-probe',
        },
        body: data,
      });
    } catch (e: any) {
      setResponse({
        status: 500,
        error: e.message,
      });
    } finally {
      setLoading(false);
    }
  };

  const handleRunBurstTest = async () => {
    setBursting(true);
    setBurstResults(null);
    let allowed = 0;
    let blocked = 0;

    const count = 30; // 30 rapid requests to trigger burst limit
    const promises = Array.from({ length: count }).map(async () => {
      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'burst_test' }),
        });
        if (res.status === 429) {
          blocked++;
        } else {
          allowed++;
        }
      } catch {
        blocked++;
      }
    });

    await Promise.all(promises);
    setBurstResults({ total: count, allowed, blocked });
    setBursting(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-6 rounded-2xl bg-[#0e1320] border border-slate-800 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            <Zap className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100">Interactive Attack Simulator & Live Prober</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Launch real-time security vectors against the AI-WAF reverse proxy to verify live multi-tier detection
            </p>
          </div>
        </div>

        {/* Rapid Burst Test Button */}
        <button
          onClick={handleRunBurstTest}
          disabled={bursting}
          className="px-4 py-2 text-xs font-bold rounded-xl bg-orange-500/20 hover:bg-orange-500/30 text-orange-400 border border-orange-500/40 flex items-center gap-2 transition-colors disabled:opacity-50"
        >
          <Flame className={`w-4 h-4 ${bursting ? 'animate-bounce' : ''}`} />
          <span>{bursting ? 'Firing 30 Requests...' : 'Trigger Burst Flood (30 req)'}</span>
        </button>
      </div>

      {/* Burst Result Notification */}
      {burstResults && (
        <div className="p-4 rounded-xl bg-orange-500/10 border border-orange-500/30 flex items-center justify-between text-xs animate-fade-in">
          <div className="flex items-center gap-2.5 text-orange-300">
            <Flame className="w-4 h-4 text-orange-400 shrink-0" />
            <span>
              Burst Simulation Complete: <strong>{burstResults.total}</strong> requests fired.{' '}
              <strong className="text-rose-400">{burstResults.blocked}</strong> throttled (HTTP 429),{' '}
              <strong className="text-emerald-400">{burstResults.allowed}</strong> permitted.
            </span>
          </div>
        </div>
      )}

      {/* Presets Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {PRESETS.map((p, i) => (
          <button
            key={i}
            onClick={() => applyPreset(p)}
            className={`p-3 rounded-xl border text-left transition-all ${
              selectedPreset.name === p.name
                ? 'bg-cyan-500/10 border-cyan-500/60 shadow-md shadow-cyan-500/5'
                : 'bg-[#0e1320] border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="text-xs font-bold text-slate-200 truncate">{p.name}</div>
            <div className="text-[10px] font-mono text-cyan-400 mt-1">{p.category}</div>
          </button>
        ))}
      </div>

      {/* Probe Console & Response Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Request Crafting Console */}
        <div className="p-6 rounded-2xl bg-[#0e1320] border border-slate-800 space-y-4 shadow-xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-300">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>HTTP Request Crafting</span>
            </div>
            <span className="text-[11px] font-medium text-slate-400">{selectedPreset.description}</span>
          </div>

          <div className="flex gap-2">
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="px-3 py-2 text-xs rounded-xl bg-slate-900 border border-slate-700 text-slate-200 font-mono font-bold focus:outline-none focus:border-cyan-500"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>
            <input
              type="text"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              className="flex-1 px-4 py-2 text-xs rounded-xl bg-slate-900 border border-slate-700 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

          {method !== 'GET' && method !== 'HEAD' && (
            <div>
              <label className="text-[10px] font-mono uppercase text-slate-500 block mb-1.5">JSON Payload Body:</label>
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                rows={3}
                className="w-full p-3 text-xs rounded-xl bg-slate-900 border border-slate-700 text-slate-200 font-mono focus:outline-none focus:border-cyan-500 resize-none"
              />
            </div>
          )}

          <button
            onClick={handleSendProbe}
            disabled={loading}
            className="w-full py-2.5 px-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
          >
            <Send className="w-4 h-4" />
            <span>{loading ? 'Dispatching Probe to WAF Proxy...' : 'Transmit Request to WAF'}</span>
          </button>
        </div>

        {/* Live Response Telemetry */}
        <div className="p-6 rounded-2xl bg-[#0e1320] border border-slate-800 flex flex-col justify-between shadow-xl">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-300">
                <Radio className="w-4 h-4 text-rose-400" />
                <span>WAF Telemetry & Response</span>
              </div>
              {response && (
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span
                    className={`px-2 py-0.5 rounded font-bold ${
                      response.status === 200
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : response.status === 403
                        ? 'bg-rose-500/20 text-rose-400'
                        : 'bg-orange-500/20 text-orange-400'
                    }`}
                  >
                    HTTP {response.status}
                  </span>
                  <span className="text-slate-400 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {response.latencyMs}ms
                  </span>
                </div>
              )}
            </div>

            {response ? (
              <div className="space-y-3 font-mono text-xs">
                {/* WAF Injected Headers */}
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
                  <div className="text-[10px] uppercase text-slate-500">Security Telemetry Headers:</div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">X-WAF-Action:</span>
                    <span
                      className={`font-bold ${
                        response.headers['X-WAF-Action'] === 'BLOCK'
                          ? 'text-rose-400'
                          : response.headers['X-WAF-Action'] === 'FLAG'
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {response.headers['X-WAF-Action']}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">X-WAF-Risk-Score:</span>
                    <span className="text-slate-200">{response.headers['X-WAF-Risk-Score']} / 100</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">X-WAF-Category:</span>
                    <span className="text-slate-200">{response.headers['X-WAF-Category']}</span>
                  </div>
                </div>

                {/* Response Body Snippet */}
                <div className="p-3 rounded-xl bg-[#07090e] border border-slate-800 text-[11px] overflow-x-auto max-h-36">
                  <div className="text-[10px] uppercase text-slate-500 mb-1">Payload Content:</div>
                  <pre className="text-slate-300 break-all">{JSON.stringify(response.body, null, 2)}</pre>
                </div>
              </div>
            ) : (
              <div className="h-44 flex flex-col items-center justify-center text-slate-500 text-xs text-center">
                <FileCode className="w-8 h-8 mb-2 opacity-40 text-slate-600" />
                <span>Select a preset or enter a custom path to transmit an inspection probe.</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
