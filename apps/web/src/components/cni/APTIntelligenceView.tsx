'use client';

import { useState } from 'react';

interface APTActor {
  id: string;
  name: string;
  alias: string;
  origin: string;
  targetSectors: string[];
  confidence: number;
  activeIncidents: number;
  lastSeen: string;
  primaryTactics: string[];
  knownTools: string[];
  indicatorsCount: number;
  killChainStage: number;
  description: string;
  recentActivity: string;
}

interface TTPMapping {
  techniqueId: string;
  technique: string;
  tactic: string;
  actors: string[];
  detections: number;
}

interface IOC {
  type: string;
  value: string;
  actor: string;
  confidence: number;
  firstSeen: string;
}

const APT_ACTORS: APTActor[] = [
  {
    id: 'apt36',
    name: 'APT36',
    alias: 'Transparent Tribe / ProjectM',
    origin: 'Pakistan-linked',
    targetSectors: ['Education (CBSE)', 'Defence', 'Govt IT', 'Telecom'],
    confidence: 87,
    activeIncidents: 3,
    lastSeen: '2h ago',
    primaryTactics: ['Initial Access', 'Execution', 'Persistence', 'Exfiltration'],
    knownTools: ['Crimson RAT', 'ObliqueRAT', 'CapraRAT', 'ElizaRAT'],
    indicatorsCount: 147,
    killChainStage: 9,
    description: 'Pakistan-attributed APT targeting Indian defence, education (especially exam boards), and government networks. Uses spear-phishing with Crimson RAT payloads. Known for long-dwell campaigns with multi-stage exfiltration.',
    recentActivity: 'Active campaign against CBSE exam coordination network. Exfiltrated 2.3M student PII records via C2 at 103.76.228.95. Post-exfil ransomware deployment predicted within 72h.',
  },
  {
    id: 'sidecopy',
    name: 'SideCopy',
    alias: 'APT-C-24',
    origin: 'Pakistan-linked',
    targetSectors: ['Defence (DRDO)', 'Govt IT (NIC)', 'Paramilitary'],
    confidence: 79,
    activeIncidents: 2,
    lastSeen: '6h ago',
    primaryTactics: ['Initial Access', 'Execution', 'Collection', 'Exfiltration'],
    knownTools: ['ActionRAT', 'MargulasRAT', 'AllaKore', 'Reverse RAT'],
    indicatorsCount: 93,
    killChainStage: 7,
    description: 'SideCopy mimics SideWinder TTPs to confuse attribution. Targets Indian defence and paramilitary organizations. Delivers malware via LNK files and Office macros hosted on compromised government-themed websites.',
    recentActivity: 'Detected exfiltrating classified documents from DRDO-adjacent network. Uses multi-stage LNK → HTA → PowerShell dropper chain. C2 infrastructure rotated every 72h.',
  },
  {
    id: 'volt-typhoon',
    name: 'Volt Typhoon',
    alias: 'Bronze Silhouette / VANGUARD PANDA',
    origin: 'China-linked',
    targetSectors: ['Power Grid (NTPC/PGCIL)', 'Telecom', 'Maritime'],
    confidence: 92,
    activeIncidents: 1,
    lastSeen: '1h ago',
    primaryTactics: ['Discovery', 'Lateral Movement', 'Command & Control', 'Pre-Positioning'],
    knownTools: ['netsh', 'ipconfig', 'wmic', 'FRP', 'Chisel'],
    indicatorsCount: 214,
    killChainStage: 8,
    description: 'Chinese state-sponsored APT focused on pre-positioning in critical infrastructure for potential disruptive operations. Uses Living-off-the-Land (LOTL) techniques exclusively — no custom malware, making detection difficult. Active in India power grid since late 2025.',
    recentActivity: 'SAFETY_CRITICAL: Unauthorized Modbus FC-16 write to PGCIL substation PLC register 4096. IT→OT DMZ lateral movement confirmed via compromised engineering workstation. OT-SAFE response applied: DMZ firewall rule added, host isolation explicitly avoided.',
  },
  {
    id: 'lazarus-india',
    name: 'Lazarus (India Ops)',
    alias: 'Hidden Cobra / ZINC',
    origin: 'DPRK-linked',
    targetSectors: ['Healthcare (AIIMS pattern)', 'Cryptocurrency', 'Defence'],
    confidence: 68,
    activeIncidents: 1,
    lastSeen: '12h ago',
    primaryTactics: ['Initial Access', 'Execution', 'Impact', 'Financial Motivation'],
    knownTools: ['LockBit 3.0 (affiliate)', 'Maui ransomware', 'DTrack', 'BlindingCan'],
    indicatorsCount: 61,
    killChainStage: 6,
    description: 'DPRK-linked operations targeting India healthcare for financial gain and intelligence collection. Uses EternalBlue against EoL Windows infrastructure. AIIMS Delhi (2022) breach pattern — deploys ransomware post-data-exfiltration for double extortion.',
    recentActivity: 'Healthcare network reconnaissance matching AIIMS-class EHR targeting pattern. EternalBlue probe against Windows Server 2008 nodes (CVSS 7.5 → 16.5 amplified). Ransomware deployment not yet observed; pre-positioning phase.',
  },
];

const TTP_MAPPINGS: TTPMapping[] = [
  { techniqueId: 'T1566.001', technique: 'Spear-Phishing Attachment', tactic: 'Initial Access', actors: ['APT36', 'SideCopy'], detections: 23 },
  { techniqueId: 'T1059.001', technique: 'PowerShell', tactic: 'Execution', actors: ['APT36', 'Volt Typhoon'], detections: 47 },
  { techniqueId: 'T1190', technique: 'Exploit Public-Facing App (EternalBlue)', tactic: 'Initial Access', actors: ['Lazarus India'], detections: 8 },
  { techniqueId: 'T1016', technique: 'System Network Config Discovery', tactic: 'Discovery', actors: ['Volt Typhoon'], detections: 31 },
  { techniqueId: 'T0855', technique: 'Unauthorized Command Message', tactic: 'Impair Process Control', actors: ['Volt Typhoon'], detections: 3 },
  { techniqueId: 'T1041', technique: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', actors: ['APT36', 'SideCopy'], detections: 19 },
  { techniqueId: 'T1486', technique: 'Data Encrypted for Impact', tactic: 'Impact', actors: ['Lazarus India', 'APT36'], detections: 5 },
  { techniqueId: 'T1021.001', technique: 'Remote Desktop Protocol', tactic: 'Lateral Movement', actors: ['Volt Typhoon'], detections: 12 },
];

const IOCS: IOC[] = [
  { type: 'IP', value: '103.76.228.95', actor: 'APT36', confidence: 91, firstSeen: '2026-06-22' },
  { type: 'Domain', value: 'cbse-results.gov.in.updates[.]xyz', actor: 'APT36', confidence: 88, firstSeen: '2026-06-21' },
  { type: 'Hash (SHA256)', value: 'a3f8d2...crimsonrat.dll', actor: 'APT36', confidence: 95, firstSeen: '2026-06-20' },
  { type: 'IP', value: '45.77.149.102', actor: 'SideCopy', confidence: 76, firstSeen: '2026-06-18' },
  { type: 'Domain', value: 'drdo-portal.servehttp[.]com', actor: 'SideCopy', confidence: 82, firstSeen: '2026-06-19' },
  { type: 'IP', value: '192.168.10.47', actor: 'Volt Typhoon', confidence: 69, firstSeen: '2026-06-24' },
];

const ORIGIN_COLOR: Record<string, string> = {
  'Pakistan-linked': 'text-orange-400 bg-orange-400/10 border-orange-400/20',
  'China-linked': 'text-red-400 bg-red-400/10 border-red-400/20',
  'DPRK-linked': 'text-purple-400 bg-purple-400/10 border-purple-400/20',
};

const KILL_CHAIN_STAGES = ['Recon', 'Weapon', 'Delivery', 'Exploit', 'Install', 'C2', 'Discovery', 'Lateral', 'Collection', 'Exfil', 'Impact'];

export function APTIntelligenceView() {
  const [selectedActor, setSelectedActor] = useState<APTActor>(APT_ACTORS[2]);
  const [activeTab, setActiveTab] = useState<'profile' | 'ttps' | 'iocs'>('profile');

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">India APT Intelligence</h1>
        <p className="text-gray-400 text-sm mt-1">
          AI-driven TTP-level attribution for India CNI threat actors. Sources: CERT-In advisories (RAG), MITRE ATT&CK for ICS,
          NCIIPC bulletins, open-source intelligence feeds.
        </p>
      </div>

      {/* Actor Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {APT_ACTORS.map(actor => (
          <button
            key={actor.id}
            onClick={() => setSelectedActor(actor)}
            className={`text-left p-4 rounded-lg border transition-all ${
              selectedActor.id === actor.id
                ? 'border-blue-500 bg-blue-500/10'
                : 'border-gray-700 bg-gray-900 hover:border-gray-500'
            }`}
          >
            <div className="flex items-start justify-between mb-2">
              <div>
                <p className="text-white font-bold text-sm">{actor.name}</p>
                <p className="text-gray-400 text-xs">{actor.alias}</p>
              </div>
              <span className={`text-xs px-1.5 py-0.5 rounded border ${ORIGIN_COLOR[actor.origin]}`}>
                {actor.origin.split('-')[0]}
              </span>
            </div>
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-400">Confidence</span>
                <span className={`font-semibold ${actor.confidence >= 85 ? 'text-red-400' : actor.confidence >= 70 ? 'text-orange-400' : 'text-yellow-400'}`}>
                  {actor.confidence}%
                </span>
              </div>
              <div className="h-1 bg-gray-700 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${actor.confidence >= 85 ? 'bg-red-500' : actor.confidence >= 70 ? 'bg-orange-500' : 'bg-yellow-500'}`}
                  style={{ width: `${actor.confidence}%` }}
                />
              </div>
              <div className="flex items-center justify-between text-xs mt-1">
                <span className="text-gray-400">{actor.activeIncidents} active incidents</span>
                <span className="text-gray-500">{actor.lastSeen}</span>
              </div>
            </div>
          </button>
        ))}
      </div>

      {/* Detail Panel */}
      <div className="bg-gray-900 border border-blue-500/20 rounded-lg p-5">
        <div className="flex items-start justify-between mb-4">
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-xl font-bold text-white">{selectedActor.name}</h2>
              <span className={`text-xs px-2 py-0.5 rounded border ${ORIGIN_COLOR[selectedActor.origin]}`}>
                {selectedActor.origin}
              </span>
            </div>
            <p className="text-gray-400 text-sm">{selectedActor.alias}</p>
          </div>
          <div className="text-right">
            <p className={`text-3xl font-bold ${selectedActor.confidence >= 85 ? 'text-red-400' : 'text-orange-400'}`}>
              {selectedActor.confidence}%
            </p>
            <p className="text-gray-400 text-xs">Attribution Confidence</p>
          </div>
        </div>

        {/* Kill Chain */}
        <div className="mb-4">
          <p className="text-xs text-gray-400 uppercase tracking-wider mb-2">Kill Chain Progress — {KILL_CHAIN_STAGES[selectedActor.killChainStage - 1]}</p>
          <div className="flex items-center gap-1 flex-wrap">
            {KILL_CHAIN_STAGES.map((stage, i) => (
              <span key={stage} className={`text-xs px-2 py-0.5 rounded ${
                i < selectedActor.killChainStage
                  ? selectedActor.id === 'volt-typhoon' ? 'bg-red-700 text-white' :
                    selectedActor.id === 'apt36' ? 'bg-orange-600 text-white' :
                    'bg-yellow-700 text-white'
                  : 'bg-gray-700 text-gray-400'
              }`}>{stage}</span>
            ))}
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-4 border-b border-gray-700">
          {(['profile', 'ttps', 'iocs'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`pb-2 text-sm capitalize px-1 border-b-2 transition-colors ${
                activeTab === tab ? 'border-blue-400 text-blue-400' : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              {tab === 'ttps' ? 'TTPs' : tab === 'iocs' ? 'IOCs' : 'Profile'}
            </button>
          ))}
        </div>

        {activeTab === 'profile' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-3">
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wider mb-1">Target Sectors</p>
                <div className="flex flex-wrap gap-1">
                  {selectedActor.targetSectors.map(s => (
                    <span key={s} className="text-xs bg-gray-800 text-gray-300 border border-gray-600 px-2 py-0.5 rounded">{s}</span>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wider mb-1">Known Tools</p>
                <div className="flex flex-wrap gap-1">
                  {selectedActor.knownTools.map(t => (
                    <span key={t} className="text-xs bg-red-900/20 text-red-300 border border-red-700/30 px-2 py-0.5 rounded font-mono">{t}</span>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wider mb-1">Primary Tactics</p>
                <div className="flex flex-wrap gap-1">
                  {selectedActor.primaryTactics.map(t => (
                    <span key={t} className="text-xs bg-blue-900/20 text-blue-300 border border-blue-700/30 px-2 py-0.5 rounded">{t}</span>
                  ))}
                </div>
              </div>
              <div className="flex gap-4">
                <div>
                  <p className="text-xs text-gray-400">IOC Count</p>
                  <p className="text-white font-semibold">{selectedActor.indicatorsCount}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400">Last Seen</p>
                  <p className="text-white font-semibold">{selectedActor.lastSeen}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400">Active Incidents</p>
                  <p className={`font-semibold ${selectedActor.activeIncidents > 0 ? 'text-red-400' : 'text-green-400'}`}>
                    {selectedActor.activeIncidents}
                  </p>
                </div>
              </div>
            </div>
            <div className="space-y-3">
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wider mb-1">Actor Description</p>
                <p className="text-sm text-gray-300">{selectedActor.description}</p>
              </div>
              <div className="p-3 bg-yellow-900/10 border border-yellow-700/30 rounded">
                <p className="text-xs text-yellow-400 font-semibold uppercase mb-1">Recent Activity</p>
                <p className="text-sm text-yellow-200">{selectedActor.recentActivity}</p>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'ttps' && (
          <div className="space-y-2">
            {TTP_MAPPINGS.filter(t => t.actors.includes(selectedActor.name)).map((ttp, i) => (
              <div key={i} className="flex items-center justify-between p-2 bg-gray-800 rounded border border-gray-700 text-sm">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-blue-400 text-xs bg-blue-900/20 px-1.5 py-0.5 rounded w-20 text-center">{ttp.techniqueId}</span>
                  <div>
                    <p className="text-white text-xs font-medium">{ttp.technique}</p>
                    <p className="text-gray-400 text-xs">{ttp.tactic}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-xs text-gray-300">{ttp.detections} detections</p>
                  <div className="flex gap-1 mt-0.5">
                    {ttp.actors.map(a => <span key={a} className="text-xs text-gray-500">{a}</span>)}
                  </div>
                </div>
              </div>
            ))}
            {TTP_MAPPINGS.filter(t => t.actors.includes(selectedActor.name)).length === 0 && (
              <p className="text-gray-500 text-sm">No TTP mappings loaded for this actor yet.</p>
            )}
          </div>
        )}

        {activeTab === 'iocs' && (
          <div className="space-y-2">
            {IOCS.filter(ioc => ioc.actor === selectedActor.name).map((ioc, i) => (
              <div key={i} className="flex items-center justify-between p-2 bg-gray-800 rounded border border-gray-700 text-xs">
                <div className="flex items-center gap-3">
                  <span className="text-gray-400 bg-gray-700 px-1.5 py-0.5 rounded w-20 text-center">{ioc.type}</span>
                  <span className="text-white font-mono">{ioc.value}</span>
                </div>
                <div className="flex items-center gap-4">
                  <span className="text-gray-400">{ioc.firstSeen}</span>
                  <span className={`font-semibold ${ioc.confidence >= 85 ? 'text-red-400' : 'text-orange-400'}`}>{ioc.confidence}%</span>
                </div>
              </div>
            ))}
            {IOCS.filter(ioc => ioc.actor === selectedActor.name).length === 0 && (
              <p className="text-gray-500 text-sm">No IOCs linked to this actor in current window.</p>
            )}
          </div>
        )}
      </div>

      {/* All TTPs cross-reference */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h2 className="text-white font-semibold mb-3">Cross-Actor TTP Heat Map</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left text-gray-400 py-2 pr-4">Technique</th>
                <th className="text-left text-gray-400 py-2 pr-4">Tactic</th>
                {APT_ACTORS.map(a => <th key={a.id} className="text-center text-gray-400 py-2 px-2">{a.name}</th>)}
                <th className="text-center text-gray-400 py-2 px-2">Detections</th>
              </tr>
            </thead>
            <tbody>
              {TTP_MAPPINGS.map((ttp, i) => (
                <tr key={i} className="border-b border-gray-800">
                  <td className="py-2 pr-4">
                    <span className="font-mono text-blue-400">{ttp.techniqueId}</span>
                    <span className="text-gray-300 ml-2">{ttp.technique}</span>
                  </td>
                  <td className="text-gray-400 py-2 pr-4">{ttp.tactic}</td>
                  {APT_ACTORS.map(a => (
                    <td key={a.id} className="text-center py-2 px-2">
                      {ttp.actors.includes(a.name) ? <span className="text-red-400 font-bold">●</span> : <span className="text-gray-700">○</span>}
                    </td>
                  ))}
                  <td className="text-center py-2 px-2 text-gray-300">{ttp.detections}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="text-center text-xs text-gray-600 pb-2">
        Sources: CERT-In Advisory RAG · MITRE ATT&CK v14 · MITRE ATT&CK for ICS · NCIIPC Bulletins · OSINT
      </div>
    </div>
  );
}
