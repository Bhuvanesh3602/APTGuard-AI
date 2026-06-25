'use client';

import { useState } from 'react';

type Domain = 'it' | 'ot' | 'identity' | 'network' | 'cloud';

interface WeakSignal {
  id: string;
  time: string;
  domain: Domain;
  source: string;
  description: string;
  ownScore: number; // how suspicious it looks in isolation (low = weak)
  mitreTactic: string;
  mitreId: string;
}

interface Campaign {
  id: string;
  name: string;
  actor: string;
  sector: string;
  confidence: number;
  fusedScore: number;
  currentStage: string;
  predictedNext: string;
  signals: WeakSignal[];
  recommendation: string;
}

const DOMAIN_CFG: Record<Domain, { label: string; color: string; icon: string }> = {
  it: { label: 'IT', color: 'text-blue-400 bg-blue-400/10', icon: '💻' },
  ot: { label: 'OT', color: 'text-red-400 bg-red-400/10', icon: '🏭' },
  identity: { label: 'Identity', color: 'text-purple-400 bg-purple-400/10', icon: '🔑' },
  network: { label: 'Network', color: 'text-green-400 bg-green-400/10', icon: '🌐' },
  cloud: { label: 'Cloud', color: 'text-cyan-400 bg-cyan-400/10', icon: '☁️' },
};

// Each signal is individually weak (low own-score) and would be dismissed by a
// siloed tool. Fused across IT+OT+identity into one campaign they reveal a
// coordinated Volt Typhoon grid intrusion.
const CAMPAIGNS: Campaign[] = [
  {
    id: 'CAMP-001',
    name: 'Power Grid OT Pre-Positioning',
    actor: 'Volt Typhoon',
    sector: 'Power Grid (PGCIL)',
    confidence: 92,
    fusedScore: 9.6,
    currentStage: 'Lateral Movement → Impair Process Control',
    predictedNext: 'T0826 Loss of Availability (substation trip) within 24–72h',
    recommendation: 'OT-SAFE: apply IT→OT DMZ block + Modbus DPI. Escalate to NCIIPC. Do NOT isolate PLC host.',
    signals: [
      { id: 's1', time: '23:40 IST', domain: 'identity', source: 'AD logs', description: 'Service account svc_backup logs in interactively (first time ever)', ownScore: 3.1, mitreTactic: 'Valid Accounts', mitreId: 'T1078' },
      { id: 's2', time: '00:10 IST', domain: 'it', source: 'EDR', description: 'LOTL recon: netsh, ipconfig, net view on jump host (no malware)', ownScore: 2.8, mitreTactic: 'System Network Config Discovery', mitreId: 'T1016' },
      { id: 's3', time: '00:55 IST', domain: 'network', source: 'NetFlow', description: 'RDP from IT subnet to OT DMZ engineering workstation', ownScore: 4.2, mitreTactic: 'Remote Services', mitreId: 'T1021.001' },
      { id: 's4', time: '01:23 IST', domain: 'ot', source: 'Modbus DPI', description: 'First-ever FC-16 write to PLC holding register 4096', ownScore: 5.0, mitreTactic: 'Unauthorized Command Message', mitreId: 'T0855' },
    ],
  },
  {
    id: 'CAMP-002',
    name: 'CBSE Exam Data Exfiltration',
    actor: 'APT36 (Transparent Tribe)',
    sector: 'Education (CBSE)',
    confidence: 87,
    fusedScore: 9.2,
    currentStage: 'Collection → Exfiltration',
    predictedNext: 'T1486 Ransomware deployment (double-extortion) within 72h',
    recommendation: 'Block foreign ASN egress; DLP quarantine on result DB; file CERT-In CAT-9 report.',
    signals: [
      { id: 's5', time: '23:48 IST', domain: 'identity', source: 'Email gateway', description: 'Spear-phish with macro doc opened by exam coordinator', ownScore: 3.5, mitreTactic: 'Phishing', mitreId: 'T1566.001' },
      { id: 's6', time: '23:50 IST', domain: 'it', source: 'EDR', description: 'winword.exe spawns powershell -enc (macro execution)', ownScore: 4.0, mitreTactic: 'PowerShell', mitreId: 'T1059.001' },
      { id: 's7', time: '02:14 IST', domain: 'identity', source: 'UEBA', description: 'Coordinator reads 540k records off-hours (8.4σ deviation)', ownScore: 4.8, mitreTactic: 'Data from Information Repositories', mitreId: 'T1213' },
      { id: 's8', time: '02:55 IST', domain: 'network', source: 'NetFlow', description: '4.7 GB egress to 103.76.228.95 (Pakistan ASN)', ownScore: 4.5, mitreTactic: 'Exfiltration Over C2', mitreId: 'T1041' },
    ],
  },
];

function StageProgress({ current }: { current: string }) {
  const stages = ['Recon', 'Initial Access', 'Execution', 'Persistence', 'Lateral Mvmt', 'Collection', 'Exfil/Impact'];
  // crude: highlight up to whichever keyword appears
  const activeIdx = current.toLowerCase().includes('impact') || current.toLowerCase().includes('exfil') ? 6
    : current.toLowerCase().includes('collection') ? 5
    : current.toLowerCase().includes('lateral') ? 4 : 2;
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {stages.map((s, i) => (
        <span key={s} className={`text-xs px-2 py-0.5 rounded ${i <= activeIdx ? 'bg-red-600 text-white' : 'bg-gray-700 text-gray-400'}`}>{s}</span>
      ))}
    </div>
  );
}

export function CorrelationView() {
  const [selected, setSelected] = useState<Campaign>(CAMPAIGNS[0]);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Cross-Signal Correlation</h1>
        <p className="text-gray-400 text-sm mt-1">
          Fuses weak signals across heterogeneous IT, OT, identity and network telemetry into a single attack-progression
          timeline mapped to MITRE ATT&CK. Individually each signal is below alert threshold — together they reveal a
          coordinated campaign and <span className="text-yellow-400">predict the next move</span>.
        </p>
      </div>

      {/* Campaign selector */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {CAMPAIGNS.map(c => (
          <button
            key={c.id}
            onClick={() => setSelected(c)}
            className={`text-left p-4 rounded-lg border transition-all ${selected.id === c.id ? 'border-blue-500 bg-blue-500/10' : 'border-gray-700 bg-gray-900 hover:border-gray-500'}`}
          >
            <div className="flex items-start justify-between">
              <div>
                <p className="text-white font-semibold">{c.name}</p>
                <p className="text-xs text-gray-400">{c.actor} · {c.sector}</p>
              </div>
              <div className="text-right">
                <p className="text-xl font-bold text-red-400">{c.fusedScore}</p>
                <p className="text-xs text-gray-500">fused score</p>
              </div>
            </div>
            <div className="flex items-center gap-2 mt-2">
              <span className="text-xs text-gray-400">{c.signals.length} fused signals</span>
              <span className="text-xs text-purple-400">{c.confidence}% confidence</span>
            </div>
          </button>
        ))}
      </div>

      {/* Selected campaign detail */}
      <div className="bg-gray-900 border border-blue-500/20 rounded-lg p-5 space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-lg font-bold text-white">{selected.name}</h2>
            <p className="text-sm text-gray-400">{selected.actor} · {selected.sector}</p>
          </div>
          <div className="text-right">
            <p className="text-2xl font-bold text-red-400">{selected.fusedScore}/10</p>
            <p className="text-xs text-gray-400">{selected.confidence}% attribution confidence</p>
          </div>
        </div>

        {/* Stage */}
        <div>
          <p className="text-xs text-gray-400 uppercase tracking-wider mb-2">Attack Progression — {selected.currentStage}</p>
          <StageProgress current={selected.currentStage} />
        </div>

        {/* Fused timeline */}
        <div>
          <p className="text-xs text-gray-400 uppercase tracking-wider mb-2">Fused Weak-Signal Timeline</p>
          <div className="space-y-2">
            {selected.signals.map((sig, i) => {
              const cfg = DOMAIN_CFG[sig.domain];
              return (
                <div key={sig.id} className="flex items-start gap-3">
                  <div className="flex flex-col items-center shrink-0">
                    <div className={`w-7 h-7 rounded-full flex items-center justify-center text-sm ${cfg.color}`}>{cfg.icon}</div>
                    {i < selected.signals.length - 1 && <div className="w-0.5 h-5 bg-gray-700 mt-1" />}
                  </div>
                  <div className="flex-1 min-w-0 pb-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs text-gray-500 font-mono">{sig.time}</span>
                      <span className={`text-xs px-1.5 py-0.5 rounded font-semibold ${cfg.color}`}>{cfg.label}</span>
                      <span className="text-xs text-gray-400">{sig.source}</span>
                      <span className="text-xs font-mono text-blue-400">{sig.mitreId}</span>
                    </div>
                    <p className="text-sm text-gray-200 mt-0.5">{sig.description}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-xs text-gray-500">Isolated score:</span>
                      <div className="w-20 h-1 bg-gray-700 rounded-full overflow-hidden">
                        <div className="h-full bg-gray-500 rounded-full" style={{ width: `${sig.ownScore * 10}%` }} />
                      </div>
                      <span className="text-xs text-gray-500">{sig.ownScore}/10 (below alert threshold)</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Fusion result */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-3 bg-red-900/10 border border-red-700/30 rounded">
            <p className="text-xs text-red-400 font-semibold uppercase mb-1">Predicted Next Move</p>
            <p className="text-sm text-red-200">{selected.predictedNext}</p>
          </div>
          <div className="p-3 bg-green-900/10 border border-green-700/30 rounded">
            <p className="text-xs text-green-400 font-semibold uppercase mb-1">Recommended Containment</p>
            <p className="text-sm text-green-200">{selected.recommendation}</p>
          </div>
        </div>

        <div className="p-2 bg-blue-900/10 border border-blue-700/30 rounded text-xs text-blue-300">
          Fusion logic: {selected.signals.length} signals each scoring &lt;5/10 in isolation → graph correlation on shared
          entities + temporal proximity + MITRE chain continuity → fused score {selected.fusedScore}/10. This is how
          low-and-slow APTs are caught weeks earlier.
        </div>
      </div>

      <div className="text-center text-xs text-gray-600 pb-2">
        Cross-signal fusion · graph correlation on shared entities · MITRE ATT&CK chain continuity · IT/OT convergence · next-stage prediction
      </div>
    </div>
  );
}
