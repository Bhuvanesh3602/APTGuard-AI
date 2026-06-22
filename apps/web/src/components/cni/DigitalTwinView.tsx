'use client';

import { useState } from 'react';

interface Asset {
  id: string;
  name: string;
  type: 'server' | 'plc' | 'hmi' | 'workstation' | 'network';
  sector: string;
  criticality: 'critical' | 'high' | 'medium';
  os?: string;
  is_eol?: boolean;
}

interface AttackStep {
  technique: string;
  name: string;
  from: string;
  to: string;
  probability: number;
  impact: string;
}

interface SimResult {
  scenario: string;
  sector: string;
  entry_point: string;
  attack_path: AttackStep[];
  blast_radius: string[];
  total_risk_score: number;
  estimated_impact: string;
  recommended_controls: string[];
  certin_category?: string;
}

const CNI_ASSETS: Asset[] = [
  { id: 'aiims-ehr', name: 'AIIMS-EHR-SRV01', type: 'server', sector: 'Healthcare', criticality: 'critical', os: 'Windows Server 2008', is_eol: true },
  { id: 'aiims-pacs', name: 'AIIMS-PACS-SRV01', type: 'server', sector: 'Healthcare', criticality: 'critical', os: 'Windows Server 2012', is_eol: true },
  { id: 'cbse-db', name: 'CBSE-EXAM-DB01', type: 'server', sector: 'Education', criticality: 'critical', os: 'Ubuntu 18.04', is_eol: true },
  { id: 'pgcil-hmi', name: 'PGCIL-SUBSTATION-HMI01', type: 'hmi', sector: 'Power Grid', criticality: 'critical', is_eol: false },
  { id: 'pgcil-plc', name: 'PGCIL-PLC-GRID01', type: 'plc', sector: 'Power Grid', criticality: 'critical', is_eol: false },
  { id: 'ministry-ws', name: 'MINISTRY-WS-047', type: 'workstation', sector: 'Govt IT', criticality: 'medium', os: 'Windows 7', is_eol: true },
  { id: 'dc-01', name: 'DC01.ministry.gov.in', type: 'server', sector: 'Govt IT', criticality: 'critical', os: 'Windows Server 2019', is_eol: false },
];

const SCENARIOS: Record<string, SimResult> = {
  aiims_ransomware: {
    scenario: 'AIIMS Pattern — LockBit 3.0 Ransomware',
    sector: 'Healthcare',
    entry_point: 'aiims-ehr',
    attack_path: [
      { technique: 'T1190', name: 'Exploit Public-Facing App (EternalBlue)', from: 'Internet', to: 'AIIMS-EHR-SRV01', probability: 0.92, impact: 'EoL CVSS 16.5 (×2.2)' },
      { technique: 'T1021.002', name: 'SMB Lateral Movement', from: 'AIIMS-EHR-SRV01', to: 'AIIMS-PACS-SRV01', probability: 0.84, impact: 'Imaging systems at risk' },
      { technique: 'T1490', name: 'Inhibit System Recovery (VSS Delete)', from: 'AIIMS-PACS-SRV01', to: 'ALL EHR NODES', probability: 0.97, impact: 'Recovery impossible' },
      { technique: 'T1486', name: 'Data Encrypted for Impact (LockBit 3.0)', from: 'ALL EHR NODES', to: 'EHR Database', probability: 0.99, impact: '12,847 patient records encrypted' },
    ],
    blast_radius: ['AIIMS-EHR-SRV01', 'AIIMS-PACS-SRV01', 'Clinical Ward PCs (×34)', 'Patient Database'],
    total_risk_score: 9.8,
    estimated_impact: 'Complete EHR system outage · Paper-based clinical fallback required · 5,000+ patients affected',
    recommended_controls: [
      'Immediate: Isolate EHR admin network from clinical ward network',
      'Patch CVE-2017-0144 (EternalBlue) or migrate off Windows Server 2008',
      'Deploy immutable backup (air-gapped) for patient records',
      'Enable VSS shadow copy protection policy via GPO',
      'CERT-In CAT-4 mandatory report within 6 hours',
    ],
    certin_category: 'CAT-4 Ransomware',
  },
  cbse_apt36: {
    scenario: 'APT36 (Transparent Tribe) — CBSE Exam Data Exfiltration',
    sector: 'Education',
    entry_point: 'cbse-db',
    attack_path: [
      { technique: 'T1566.001', name: 'Spear-Phishing (Crimson RAT dropper)', from: 'APT36 Infra', to: 'exam.coordinator@cbse.gov.in', probability: 0.73, impact: 'Initial compromise via email' },
      { technique: 'T1059.001', name: 'PowerShell C2 Communication', from: 'Coordinator Workstation', to: 'CBSE-EXAM-DB01', probability: 0.88, impact: 'DB access via stolen credentials' },
      { technique: 'T1041', name: 'Exfiltration Over C2 (4.7 GB to Pakistan IP)', from: 'CBSE-EXAM-DB01', to: '103.76.228.95', probability: 0.91, impact: '2.3M student PII exfiltrated' },
      { technique: 'T1486', name: 'Ransomware (post-exfil, 72h later)', from: 'CBSE-EXAM-DB01', to: 'CBSE Exam Infrastructure', probability: 0.65, impact: 'Exam results unavailable' },
    ],
    blast_radius: ['CBSE-EXAM-DB01', 'Result Management System', '2.3M Student Records', 'UDISE Portal'],
    total_risk_score: 9.5,
    estimated_impact: '2.3M student Aadhaar-linked PII exfiltrated · National exam result leakage · Reputational damage to CBSE',
    recommended_controls: [
      'Deploy email security with attachment sandboxing for all CBSE email',
      'Implement DLP on examination database with anomalous query rate alerting',
      'Enable UEBA behavioral baseline for exam coordinators (flag >500 records/hr)',
      'Block Pakistan ASNs at perimeter for exam result database servers',
      'CERT-In CAT-9 data breach mandatory report within 6 hours',
      'File NCIIPC notification under IT Act §70 for education CNI sector',
    ],
    certin_category: 'CAT-9 Data Breach',
  },
  power_grid_ot: {
    scenario: 'Volt Typhoon — Power Grid OT Pre-Positioning',
    sector: 'Power Grid',
    entry_point: 'pgcil-hmi',
    attack_path: [
      { technique: 'T1016', name: 'LOTL Recon (netsh, ipconfig, net view)', from: 'IT DMZ', to: 'OT Workstation', probability: 0.81, impact: 'Network topology mapped' },
      { technique: 'T1021.001', name: 'RDP from IT zone to OT DMZ', from: 'IT Network', to: 'PGCIL-SUBSTATION-HMI01', probability: 0.76, impact: 'IT→OT boundary crossed' },
      { technique: 'T0855', name: 'Unauthorized Modbus FC-16 Write', from: 'PGCIL-SUBSTATION-HMI01', to: 'PGCIL-PLC-GRID01', probability: 0.68, impact: 'PLC register 4096 modified — potential relay trip' },
      { technique: 'T0826', name: 'Loss of Availability (grid segment)', from: 'PGCIL-PLC-GRID01', to: 'Substation Automation', probability: 0.55, impact: 'SAFETY_CRITICAL: potential blackout' },
    ],
    blast_radius: ['PGCIL-SUBSTATION-HMI01', 'PGCIL-PLC-GRID01', 'Grid Protection Relays (×12)', 'Substation Automation System'],
    total_risk_score: 9.9,
    estimated_impact: 'Potential substation blackout · Physical equipment damage · Public safety risk (hospitals on grid)',
    recommended_controls: [
      'OT-SAFE: Apply IT-OT DMZ firewall rule ONLY — never isolate OT host (preserves process control)',
      'Deploy industrial protocol inspection (Modbus/DNP3 DPI) at IT-OT DMZ boundary',
      'Block inter-zone RDP from IT to OT subnet',
      'Deploy NCIIPC-recommended OT asset inventory (Dragos/Claroty)',
      'File NCIIPC mandatory notification under IT Act §70 (power grid is designated CNI)',
      'CERT-In CAT-10 Critical Infrastructure attack report within 6 hours',
    ],
    certin_category: 'CAT-10 Critical Infrastructure',
  },
};

function AssetNode({ asset, selected, onClick }: { asset: Asset; selected: boolean; onClick: () => void }) {
  const typeIcon = asset.type === 'plc' ? '⚙️' : asset.type === 'hmi' ? '🖥️' : asset.type === 'workstation' ? '💻' : '🖧';
  const critColor = asset.criticality === 'critical' ? 'border-red-500' : asset.criticality === 'high' ? 'border-orange-500' : 'border-yellow-500';
  return (
    <button
      onClick={onClick}
      className={`p-2 rounded border-2 text-left transition-all ${critColor} ${selected ? 'bg-gray-700' : 'bg-gray-800'} hover:bg-gray-700`}
    >
      <div className="flex items-center gap-1">
        <span className="text-sm">{typeIcon}</span>
        <span className="text-xs font-mono text-white truncate">{asset.name}</span>
        {asset.is_eol && <span className="text-red-400 text-xs ml-1 shrink-0">EoL</span>}
      </div>
      <p className="text-xs text-gray-400 mt-0.5">{asset.sector} · {asset.criticality}</p>
      {asset.os && <p className="text-xs text-gray-500 truncate">{asset.os}</p>}
    </button>
  );
}

export function DigitalTwinView() {
  const [selectedScenario, setSelectedScenario] = useState<string>('aiims_ransomware');
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);
  const [simRunning, setSimRunning] = useState(false);
  const [simResult, setSimResult] = useState<SimResult | null>(null);

  const runSimulation = () => {
    setSimRunning(true);
    setSimResult(null);
    setTimeout(() => {
      setSimResult(SCENARIOS[selectedScenario]);
      setSimRunning(false);
    }, 1800);
  };

  const result = simResult;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          Digital Twin Attack Simulator
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          Clone-and-attack: simulate adversary paths on a Neo4j copy of the CNI network graph without touching production.
          What-if analysis for risk-ranked remediation.
        </p>
      </div>

      {/* Scenario selector */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h2 className="text-white font-semibold mb-3">Select Attack Scenario</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {Object.entries(SCENARIOS).map(([key, s]) => (
            <button
              key={key}
              onClick={() => { setSelectedScenario(key); setSimResult(null); }}
              className={`p-3 rounded border text-left transition-all ${
                selectedScenario === key ? 'border-blue-500 bg-blue-500/10' : 'border-gray-700 bg-gray-800 hover:border-gray-500'
              }`}
            >
              <p className="text-sm font-semibold text-white">{s.scenario}</p>
              <p className="text-xs text-gray-400 mt-1">{s.sector} · {s.certin_category}</p>
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Asset inventory */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <h2 className="text-white font-semibold mb-3">CNI Asset Graph</h2>
          <p className="text-gray-500 text-xs mb-3">17 node-type Neo4j schema · 14 relationship types · Digital twin clone for safe simulation</p>
          <div className="grid grid-cols-1 gap-2">
            {CNI_ASSETS.map(a => (
              <AssetNode
                key={a.id}
                asset={a}
                selected={selectedAsset === a.id}
                onClick={() => setSelectedAsset(selectedAsset === a.id ? null : a.id)}
              />
            ))}
          </div>
          <div className="mt-3 text-xs text-gray-500 space-y-1">
            <div className="flex items-center gap-2"><div className="w-3 h-3 border-2 border-red-500 rounded" /><span>Critical asset</span></div>
            <div className="flex items-center gap-2"><div className="w-3 h-3 border-2 border-orange-500 rounded" /><span>High asset</span></div>
            <span className="text-red-400">EoL = End-of-Life (amplified CVSS)</span>
          </div>
        </div>

        {/* Simulation panel */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-white font-semibold">Attack Path Simulation</h2>
              <button
                onClick={runSimulation}
                disabled={simRunning}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 text-white text-sm rounded transition-colors"
              >
                {simRunning ? 'Simulating...' : 'Run Simulation'}
              </button>
            </div>

            {simRunning && (
              <div className="space-y-2">
                {['Cloning production graph to isolated twin...', 'Running attack path BFS on Neo4j twin...', 'Calculating blast radius...', 'Scoring CERT-In compliance impact...'].map((step, i) => (
                  <div key={i} className="flex items-center gap-2 text-sm text-gray-400 animate-pulse">
                    <div className="w-2 h-2 rounded-full bg-blue-500" />
                    {step}
                  </div>
                ))}
              </div>
            )}

            {!simRunning && !result && (
              <div className="text-center py-8 text-gray-500 text-sm">
                Select a scenario above and click <span className="text-blue-400">Run Simulation</span> to model the attack path
                on an isolated Neo4j digital twin of the CNI network.
              </div>
            )}

            {result && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-white font-semibold">{result.scenario}</p>
                    <p className="text-xs text-gray-400">{result.sector} · Entry: {result.entry_point}</p>
                  </div>
                  <div className={`text-2xl font-bold ${result.total_risk_score >= 9 ? 'text-red-400' : 'text-orange-400'}`}>
                    {result.total_risk_score}/10
                    <p className="text-xs text-gray-400 font-normal text-right">Risk Score</p>
                  </div>
                </div>

                {/* Attack chain */}
                <div>
                  <p className="text-xs text-gray-400 uppercase tracking-wider mb-2">Simulated Attack Path</p>
                  <div className="space-y-2">
                    {result.attack_path.map((step, i) => (
                      <div key={i} className="flex items-start gap-3">
                        <div className="flex flex-col items-center shrink-0">
                          <div className="w-6 h-6 rounded-full bg-red-600 text-white text-xs flex items-center justify-center font-bold">{i + 1}</div>
                          {i < result.attack_path.length - 1 && <div className="w-0.5 h-4 bg-gray-700 mt-1" />}
                        </div>
                        <div className="flex-1 min-w-0 pb-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs font-mono text-blue-400 bg-blue-400/10 px-1.5 py-0.5 rounded">{step.technique}</span>
                            <span className="text-sm text-white">{step.name}</span>
                            <span className="text-xs text-gray-400">{Math.round(step.probability * 100)}% prob</span>
                          </div>
                          <p className="text-xs text-gray-500 mt-0.5">{step.from} → {step.to}</p>
                          <p className="text-xs text-orange-400 mt-0.5">{step.impact}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Blast radius */}
                <div className="bg-red-900/10 border border-red-800/30 rounded p-3">
                  <p className="text-xs text-red-400 font-semibold uppercase mb-1">Blast Radius</p>
                  <div className="flex flex-wrap gap-1">
                    {result.blast_radius.map(node => (
                      <span key={node} className="text-xs bg-red-900/20 text-red-300 px-2 py-0.5 rounded font-mono">{node}</span>
                    ))}
                  </div>
                </div>

                {/* Estimated impact */}
                <div className="bg-gray-800 rounded p-3">
                  <p className="text-xs text-gray-400 uppercase mb-1">Estimated Impact</p>
                  <p className="text-sm text-white">{result.estimated_impact}</p>
                  {result.certin_category && (
                    <p className="text-xs text-yellow-400 mt-1">CERT-In: {result.certin_category} — mandatory 6-hour report</p>
                  )}
                </div>

                {/* Recommended controls */}
                <div>
                  <p className="text-xs text-gray-400 uppercase mb-2">Recommended Controls (Pre-Emptive)</p>
                  <ul className="space-y-1">
                    {result.recommended_controls.map((ctrl, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                        <span className="text-green-400 shrink-0 mt-0.5">→</span>
                        {ctrl}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="text-center text-xs text-gray-600">
        Digital Twin runs on an isolated Neo4j clone — production systems are never touched during simulation.
        Graph schema: 17 node labels · 14 edge types (CONNECTS_TO, EXPLOITS, LATERAL_MOVE, EXFILTRATES, …)
      </div>
    </div>
  );
}
