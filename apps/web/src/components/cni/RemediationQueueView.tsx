'use client';

import { useState } from 'react';

interface RemediationItem {
  id: string;
  asset: string;
  sector: string;
  cve: string;
  cveDescription: string;
  baseCvss: number;
  priorityScore: number;
  exploitedInWild: boolean;
  internetFacing: boolean;
  eolAsset: boolean;
  threatActorInterest: string[];
  topologyExposure: string;
  patchAvailable: boolean;
  recommendedAction: string;
  effortDays: number;
}

// Risk-ranked queue: priority = base CVSS x exploitability x topology exposure
// x EoL amplification x threat-actor interest. Government teams can't patch
// everything — this orders WHAT to fix first.
const QUEUE: RemediationItem[] = [
  {
    id: 'REM-001',
    asset: 'PGCIL-PLC-GRID01 (Siemens S7-300)',
    sector: 'Power Grid',
    cve: 'CVE-2019-13945',
    cveDescription: 'Siemens S7 SIMATIC auth bypass — direct PLC access without credentials',
    baseCvss: 8.8,
    priorityScore: 98.5,
    exploitedInWild: false,
    internetFacing: false,
    eolAsset: true,
    threatActorInterest: ['Volt Typhoon'],
    topologyExposure: 'Reachable from compromised IT-OT DMZ; one hop from substation control',
    patchAvailable: false,
    recommendedAction: 'OT-SAFE virtual patch: Modbus DPI rule at DMZ boundary (never isolate PLC host)',
    effortDays: 1,
  },
  {
    id: 'REM-002',
    asset: 'AIIMS-EHR-SRV01 (Windows Server 2008)',
    sector: 'Healthcare',
    cve: 'CVE-2017-0144',
    cveDescription: 'EternalBlue — SMBv1 remote code execution',
    baseCvss: 8.1,
    priorityScore: 96.2,
    exploitedInWild: true,
    internetFacing: false,
    eolAsset: true,
    threatActorInterest: ['Lazarus India', 'LockBit affiliates'],
    topologyExposure: 'EHR core; lateral SMB path to 34 clinical ward PCs',
    patchAvailable: false,
    recommendedAction: 'Disable SMBv1 via GPO; segment EHR admin VLAN; migrate off Server 2008',
    effortDays: 5,
  },
  {
    id: 'REM-003',
    asset: 'CBSE-EXAM-DB01 (Ubuntu 18.04)',
    sector: 'Education',
    cve: 'CVE-2021-3156',
    cveDescription: 'Sudo "Baron Samedit" heap overflow — local privilege escalation to root',
    baseCvss: 7.8,
    priorityScore: 91.7,
    exploitedInWild: true,
    internetFacing: true,
    eolAsset: true,
    threatActorInterest: ['APT36'],
    topologyExposure: 'Internet-facing result API; holds 2.3M student PII records',
    patchAvailable: true,
    recommendedAction: 'Patch sudo to 1.9.5p2; enable DLP on result DB; block foreign ASNs',
    effortDays: 2,
  },
  {
    id: 'REM-004',
    asset: 'NIC-PORTAL (Apache HTTP 2.2)',
    sector: 'Govt IT',
    cve: 'CVE-2018-11776',
    cveDescription: 'Apache Struts 2 remote code execution',
    baseCvss: 9.8,
    priorityScore: 88.4,
    exploitedInWild: true,
    internetFacing: true,
    eolAsset: true,
    threatActorInterest: ['SideCopy'],
    topologyExposure: 'Public government portal; 12 instances behind shared LB',
    patchAvailable: true,
    recommendedAction: 'Upgrade Struts/Apache; deploy WAF virtual patch as interim',
    effortDays: 3,
  },
  {
    id: 'REM-005',
    asset: 'MINISTRY-WS fleet (Windows 7)',
    sector: 'Govt IT',
    cve: 'CVE-2019-0708',
    cveDescription: 'BlueKeep — RDP pre-auth wormable RCE',
    baseCvss: 9.8,
    priorityScore: 84.1,
    exploitedInWild: true,
    internetFacing: false,
    eolAsset: true,
    threatActorInterest: ['SideCopy', 'APT36'],
    topologyExposure: '214 endpoints; RDP enabled across flat subnet',
    patchAvailable: false,
    recommendedAction: 'Disable RDP where unused; NLA enforce; prioritise Win7 → Win11 migration',
    effortDays: 14,
  },
  {
    id: 'REM-006',
    asset: 'BSNL-CORE-RTR (Cisco IOS 12.x)',
    sector: 'Telecom',
    cve: 'CVE-2018-0171',
    cveDescription: 'Cisco Smart Install remote code execution',
    baseCvss: 9.8,
    priorityScore: 79.3,
    exploitedInWild: true,
    internetFacing: true,
    eolAsset: true,
    threatActorInterest: ['Volt Typhoon'],
    topologyExposure: 'Core routing; 34 devices with Smart Install exposed',
    patchAvailable: false,
    recommendedAction: 'Disable Smart Install (no IP igmp); ACL mgmt plane; plan IOS-XE refresh',
    effortDays: 7,
  },
];

function PriorityBar({ score }: { score: number }) {
  const color = score >= 95 ? 'bg-red-500' : score >= 85 ? 'bg-orange-500' : score >= 75 ? 'bg-yellow-500' : 'bg-blue-500';
  return (
    <div className="w-full h-1.5 bg-gray-700 rounded-full overflow-hidden">
      <div className={`h-full ${color} rounded-full`} style={{ width: `${score}%` }} />
    </div>
  );
}

export function RemediationQueueView() {
  const [selected, setSelected] = useState<RemediationItem | null>(QUEUE[0]);
  const [sortBy, setSortBy] = useState<'priority' | 'effort'>('priority');

  const sorted = [...QUEUE].sort((a, b) =>
    sortBy === 'priority' ? b.priorityScore - a.priorityScore : a.effortDays - b.effortDays
  );
  const exploited = QUEUE.filter(q => q.exploitedInWild).length;
  const noPatch = QUEUE.filter(q => !q.patchAvailable).length;
  const quickWins = QUEUE.filter(q => q.effortDays <= 2).length;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Vulnerability Prioritisation Queue</h1>
        <p className="text-gray-400 text-sm mt-1">
          AI maps asset inventory against live CVE feeds, contextualises exploitability by network topology and observed
          threat-actor interest, and produces a dynamic risk-ranked remediation queue — because government teams
          <span className="text-yellow-400"> cannot patch everything at once</span>.
        </p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">In Queue</p>
          <p className="text-2xl font-bold text-white">{QUEUE.length}</p>
          <p className="text-gray-500 text-xs mt-1">Risk-ranked CVEs</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Exploited in Wild</p>
          <p className="text-2xl font-bold text-red-400">{exploited}</p>
          <p className="text-gray-500 text-xs mt-1">CISA KEV / active</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">No Patch (EoL)</p>
          <p className="text-2xl font-bold text-orange-400">{noPatch}</p>
          <p className="text-gray-500 text-xs mt-1">Need virtual patching</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Quick Wins</p>
          <p className="text-2xl font-bold text-green-400">{quickWins}</p>
          <p className="text-gray-500 text-xs mt-1">≤2 days effort</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Queue */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-white font-semibold">Remediation Queue</h2>
            <div className="flex items-center gap-1 text-xs">
              <span className="text-gray-400 mr-1">Sort:</span>
              <button onClick={() => setSortBy('priority')} className={`px-2 py-1 rounded ${sortBy === 'priority' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400'}`}>Priority</button>
              <button onClick={() => setSortBy('effort')} className={`px-2 py-1 rounded ${sortBy === 'effort' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400'}`}>Quick wins</button>
            </div>
          </div>
          <div className="space-y-3">
            {sorted.map((item, idx) => (
              <button
                key={item.id}
                onClick={() => setSelected(selected?.id === item.id ? null : item)}
                className={`w-full text-left p-3 rounded border transition-all ${selected?.id === item.id ? 'border-blue-500 bg-blue-500/5' : 'border-gray-700 bg-gray-800 hover:border-gray-500'}`}
              >
                <div className="flex items-start gap-3">
                  <div className="flex flex-col items-center shrink-0 w-8">
                    <span className="text-lg font-bold text-white">{idx + 1}</span>
                    <span className="text-xs text-gray-500">rank</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono text-blue-400 bg-blue-400/10 px-1.5 py-0.5 rounded">{item.cve}</span>
                      {item.exploitedInWild && <span className="text-xs bg-red-600 text-white px-1.5 py-0.5 rounded font-semibold">KEV</span>}
                      {item.internetFacing && <span className="text-xs bg-orange-500/20 text-orange-400 px-1.5 py-0.5 rounded">Internet-facing</span>}
                      {item.eolAsset && <span className="text-xs bg-red-900/30 text-red-400 px-1.5 py-0.5 rounded">EoL</span>}
                    </div>
                    <p className="text-sm text-white mt-1 truncate">{item.asset}</p>
                    <p className="text-xs text-gray-400">{item.sector} · CVSS {item.baseCvss} · {item.effortDays}d effort</p>
                    <div className="flex items-center gap-2 mt-2">
                      <PriorityBar score={item.priorityScore} />
                      <span className="text-xs font-bold text-white shrink-0">{item.priorityScore}</span>
                    </div>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Detail */}
        <div>
          {selected ? (
            <div className="bg-gray-900 border border-blue-500/30 rounded-lg p-4 sticky top-4">
              <h3 className="text-white font-semibold text-sm mb-3">Why this rank?</h3>
              <div className="space-y-2 text-xs">
                <div><p className="text-gray-400">Asset</p><p className="text-white">{selected.asset}</p></div>
                <div><p className="text-gray-400">{selected.cve}</p><p className="text-gray-200">{selected.cveDescription}</p></div>
                <div className="grid grid-cols-2 gap-2">
                  <div><p className="text-gray-400">Base CVSS</p><p className="text-white font-bold">{selected.baseCvss}</p></div>
                  <div><p className="text-gray-400">Priority</p><p className="text-red-400 font-bold">{selected.priorityScore}</p></div>
                </div>
                <div className="pt-2 border-t border-gray-700">
                  <p className="text-gray-400 mb-1">Scoring factors</p>
                  <ul className="space-y-1">
                    <li className="flex justify-between"><span className="text-gray-300">Exploited in wild</span><span className={selected.exploitedInWild ? 'text-red-400' : 'text-gray-500'}>{selected.exploitedInWild ? '×1.5' : '×1.0'}</span></li>
                    <li className="flex justify-between"><span className="text-gray-300">Internet-facing</span><span className={selected.internetFacing ? 'text-orange-400' : 'text-gray-500'}>{selected.internetFacing ? '×1.4' : '×1.0'}</span></li>
                    <li className="flex justify-between"><span className="text-gray-300">EoL amplifier</span><span className={selected.eolAsset ? 'text-red-400' : 'text-gray-500'}>{selected.eolAsset ? '×2.2' : '×1.0'}</span></li>
                    <li className="flex justify-between"><span className="text-gray-300">Threat-actor interest</span><span className="text-purple-400">{selected.threatActorInterest.length > 0 ? `×1.3` : '×1.0'}</span></li>
                  </ul>
                </div>
                <div className="pt-2 border-t border-gray-700">
                  <p className="text-gray-400">Threat actors targeting</p>
                  <div className="flex flex-wrap gap-1 mt-0.5">
                    {selected.threatActorInterest.map(t => <span key={t} className="bg-red-900/20 text-red-300 px-1.5 py-0.5 rounded">{t}</span>)}
                  </div>
                </div>
                <div><p className="text-gray-400">Topology exposure</p><p className="text-gray-200">{selected.topologyExposure}</p></div>
                <div className="p-2 bg-green-900/10 border border-green-700/30 rounded">
                  <p className="text-green-400 font-semibold mb-0.5">Recommended action</p>
                  <p className="text-green-200">{selected.recommendedAction}</p>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 text-sm text-gray-500 text-center py-8">
              Select a queue item to see its priority breakdown.
            </div>
          )}
        </div>
      </div>

      <div className="text-center text-xs text-gray-600 pb-2">
        Prioritisation = CVSS × exploitability × topology exposure × EoL amplification × threat-actor interest · CISA KEV · NVD · CERT-In
      </div>
    </div>
  );
}
