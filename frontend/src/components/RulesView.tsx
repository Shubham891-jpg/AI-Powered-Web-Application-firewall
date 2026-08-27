import React from 'react';
import { Sliders, Shield, Terminal, FileCode, ChevronRight, CheckCircle } from 'lucide-react';
import { StatusBadge } from './StatusBadge';

export interface RuleItem {
  id: string;
  name: string;
  category: string;
  score: number;
  confidence: string;
  description: string;
  tiers: string[];
}

const RULES_DATA: RuleItem[] = [
  {
    id: 'SQLI-001',
    name: 'Advanced SQL Injection Detector',
    category: 'SQL_INJECTION',
    score: 85,
    confidence: 'HIGH_CONFIDENCE',
    description: 'Detects structural SQL syntax clauses, boolean tautologies, stacked statements, and DB fingerprinting.',
    tiers: [
      'Structural Clauses: UNION SELECT, SELECT FROM, INSERT INTO, ORDER BY n',
      'Boolean Tautologies: \' OR 1=1, \' OR \'a\'=\'a\', HAVING 1=1',
      'Stacked Destructive: ; DROP TABLE, ; EXEC xp_cmdshell, WAITFOR DELAY',
      'Fingerprint & Comments: SLEEP(), BENCHMARK(), --, #, /*...*/',
    ],
  },
  {
    id: 'XSS-001',
    name: 'Context-Aware Cross-Site Scripting Detector',
    category: 'CROSS_SITE_SCRIPTING',
    score: 85,
    confidence: 'HIGH_CONFIDENCE',
    description: 'Inspects dangerous markup, DOM inline event handlers, script pseudo-protocols, and DOM exfiltration calls.',
    tiers: [
      'Dangerous Markup: <script>, <iframe>, <object>, <svg onload=...>, <base>',
      'DOM Event Handlers: onload=, onerror=, onclick=, onmouseover= with script invocations',
      'Pseudo-Protocols: javascript:..., data:text/html;base64,...',
      'DOM Manipulation: document.cookie, document.location, eval(), alert()',
    ],
  },
  {
    id: 'RCE-001',
    name: 'Advanced OS Command Injection Detector',
    category: 'COMMAND_INJECTION',
    score: 90,
    confidence: 'HIGH_CONFIDENCE',
    description: 'Detects shell chaining operators, subshell substitutions, interpreter pipes, and reverse shell probes.',
    tiers: [
      'Chaining Operators: ; whoami, && cat /etc/passwd, | uname -a, & id',
      'Substitutions: $(cmd), `cmd`, ${IFS} environment evasion',
      'Piping & Redirection: > /dev/tcp/ip/port, 2>&1, | bash, | sh',
      'Direct Process Execution: /bin/sh, powershell.exe, cmd.exe',
    ],
  },
  {
    id: 'TRAV-001',
    name: 'Advanced Path Traversal & File Escape Detector',
    category: 'PATH_TRAVERSAL',
    score: 85,
    confidence: 'HIGH_CONFIDENCE',
    description: 'Detects relative dot-dot sequences, URL-encoded variations, mixed separators, and sensitive system probes.',
    tiers: [
      'Relative Sequences: ../, ..\\, ....//, /../',
      'Encoded Sequences: %2e%2e%2f, %252e%252e%252f, overlong UTF-8',
      'High-Value Targets: /etc/passwd, /etc/shadow, windows/win.ini, /proc/self/environ',
      'Separator Obfuscation: Mixed forward and backslash escape patterns',
    ],
  },
];

export const RulesView: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="glass-panel rounded-2xl p-6 border border-slate-800">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Sliders className="w-5 h-5 text-cyan-400" />
              Active Inspection Rules Engine
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Deterministic, multi-layered syntactic and token-based detection rules operating at wire speed
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2.5 py-1 rounded-full">
              4 Rules Active
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 mt-6">
          {RULES_DATA.map((rule) => (
            <div
              key={rule.id}
              className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/30 transition-all space-y-3"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950/60 border border-cyan-500/30 px-2 py-0.5 rounded">
                      {rule.id}
                    </span>
                    <h3 className="text-base font-semibold text-slate-100">{rule.name}</h3>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{rule.description}</p>
                </div>
                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <span className="text-[10px] uppercase font-mono text-slate-400 block">Severity Score</span>
                    <span className="text-sm font-bold font-mono text-rose-400">{rule.score} / 100</span>
                  </div>
                  <StatusBadge status="healthy" size="sm" />
                </div>
              </div>

              {/* Tiers list */}
              <div className="pt-2 border-t border-slate-800/60">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-2">
                  Detection Tiers & Heuristics:
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {rule.tiers.map((tier, idx) => (
                    <div
                      key={idx}
                      className="text-xs font-mono text-slate-300 bg-slate-950/60 px-3 py-1.5 rounded border border-slate-800/80 flex items-center gap-2"
                    >
                      <CheckCircle className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span className="truncate">{tier}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
