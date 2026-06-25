'use client';

import { useState } from 'react';

interface EOLAsset {
  id: string;
  product: string;
  vendor: string;
  version: string;
  eolDate: string;
  sector: string;
  location: string;
  systemsAffected: number;
  baseCvss: number;
  amplifiedCvss: number;
  amplifier: number;
  patchAvailable: boolean;
  cveCount: number;
  criticalCves: number;
  exploitedInWild: boolean;
  category: 'os' | 'server' | 'ics' | 'network' | 'application';
}

interface CVEEntry {
  cveId: string;
  cvss: number;
  amplified: number;
  description: string;
  exploited: boolean;
  assets: string[];
}

const EOL_ASSETS: EOLAsset[] = [
  {
    id: 'win7-ministry',
    product: 'Windows 7 SP1',
    vendor: 'Microsoft',
    version: '6.1.7601',
    eolDate: '2020-01-14',
    sector: 'Govt IT (Ministry of Finance)',
    location: 'New Delhi',
    systemsAffected: 214,
    baseCvss: 7.5,
    amplifiedCvss: 16.5,
    amplifier: 2.2,
    patchAvailable: false,
    cveCount: 48,
    criticalCves: 12,
    exploitedInWild: true,
    category: 'os',
  },
  {
    id: 'ws2008-aiims',
    product: 'Windows Server 2008 R2',
    vendor: 'Microsoft',
    version: '6.1.7600',
    eolDate: '2020-01-14',
    sector: 'Healthcare (AIIMS EHR)',
    location: 'New Delhi',
    systemsAffected: 43,
    baseCvss: 7.5,
    amplifiedCvss: 16.5,
    amplifier: 2.2,
    patchAvailable: false,
    cveCount: 61,
    criticalCves: 17,
    exploitedInWild: true,
    category: 'server',
  },
  {
    id: 's7300-pgcil',
    product: 'Siemens S7-300 PLC',
    vendor: 'Siemens',
    version: 'firmware V3.3.17',
    eolDate: '2023-10-01',
    sector: 'Power Grid (PGCIL Substation)',
    location: 'Uttar Pradesh',
    systemsAffected: 8,
    baseCvss: 8.1,
    amplifiedCvss: 20.25,
    amplifier: 2.5,
    patchAvailable: false,
    cveCount: 14,
    criticalCves: 6,
    exploitedInWild: false,
    category: 'ics',
  },
  {
    id: 'apache22-gov',
    product: 'Apache HTTP Server 2.2',
    vendor: 'Apache Foundation',
    version: '2.2.34',
    eolDate: '2018-01-01',
    sector: 'Govt IT (NIC Portal)',
    location: 'Multiple',
    systemsAffected: 12,
    baseCvss: 9.8,
    amplifiedCvss: 13.7,
    amplifier: 1.4,
    patchAvailable: true,
    cveCount: 38,
    criticalCves: 9,
    exploitedInWild: true,
    category: 'application',
  },
  {
    id: 'ubuntu1804-cbse',
    product: 'Ubuntu Linux 18.04 LTS',
    vendor: 'Canonical',
    version: '18.04.6',
    eolDate: '2023-04-30',
    sector: 'Education (CBSE DB Servers)',
    location: 'New Delhi',
    systemsAffected: 27,
    baseCvss: 7.8,
    amplifiedCvss: 12.5,
    amplifier: 1.6,
    patchAvailable: true,
    cveCount: 22,
    criticalCves: 4,
    exploitedInWild: false,
    category: 'os',
  },
  {
    id: 'cisco-ios-12',
    product: 'Cisco IOS 12.x',
    vendor: 'Cisco',
    version: '12.4(25g)',
    eolDate: '2016-01-31',
    sector: 'Telecom (BSNL Core)',
    location: 'Multiple States',
    systemsAffected: 34,
    baseCvss: 8.6,
    amplifiedCvss: 17.2,
    amplifier: 2.0,
    patchAvailable: false,
    cveCount: 29,
    criticalCves: 8,
    exploitedInWild: true,
    category: 'network',
  },
];

const TOP_CVES: CVEEntry[] = [
  { cveId: 'CVE-2017-0144', cvss: 8.1, amplified: 17.8, description: 'EternalBlue — SMBv1 RCE. Exploited by WannaCry and NotPetya. Trivially weaponizable against unpatched Windows 7/2008.', exploited: true, assets: ['Windows 7 SP1', 'Windows Server 2008 R2'] },
  { cveId: 'CVE-2019-0708', cvss: 9.8, amplified: 21.6, description: 'BlueKeep — RDP pre-auth RCE. Wormable. Multiple PoC exploits public. CISA KEV listed.', exploited: true, assets: ['Windows 7 SP1', 'Windows Server 2008 R2'] },
  { cveId: 'CVE-2021-34527', cvss: 8.8, amplified: 19.4, description: 'PrintNightmare — Windows Print Spooler RCE. Remote unauthenticated SYSTEM access. Actively exploited.', exploited: true, assets: ['Windows 7 SP1', 'Windows Server 2008 R2'] },
  { cveId: 'CVE-2023-38831', cvss: 7.8, amplified: 12.5, description: 'WinRAR code execution. APT36 known to use in spear-phishing campaigns against CBSE targets.', exploited: true, assets: ['Windows 7 SP1'] },
  { cveId: 'CVE-2018-11776', cvss: 9.8, amplified: 13.7, description: 'Apache Struts 2 RCE. Exploited in Equifax breach pattern. NIC portal infrastructure at risk.', exploited: true, assets: ['Apache HTTP Server 2.2'] },
  { cveId: 'CVE-2019-13945', cvss: 8.8, amplified: 22.0, description: 'Siemens S7 SIMATIC auth bypass. Direct PLC access without credentials. OT-SAFETY critical.', exploited: false, assets: ['Siemens S7-300 PLC'] },
];

const CATEGORY_LABELS: Record<EOLAsset['category'], string> = {
  os: 'Operating System',
  server: 'Server Software',
  ics: 'ICS/OT Device',
  network: 'Network Device',
  application: 'Application',
};

const SECTOR_TOTALS = [
  { sector: 'Govt IT', systems: 226, critScore: 16.5, color: 'bg-blue-500' },
  { sector: 'Healthcare', systems: 43, critScore: 16.5, color: 'bg-red-500' },
  { sector: 'Power Grid', systems: 8, critScore: 20.25, color: 'bg-yellow-500' },
  { sector: 'Education', systems: 27, critScore: 12.5, color: 'bg-orange-500' },
  { sector: 'Telecom', systems: 34, critScore: 17.2, color: 'bg-purple-500' },
];

function AmplifiedCvssBar({ base, amplified }: { base: number; amplified: number }) {
  return (
    <div className="relative h-4 bg-gray-700 rounded-full overflow-hidden">
      <div className="absolute left-0 top-0 h-full bg-orange-500 rounded-full" style={{ width: `${(base / 25) * 100}%` }} />
      <div className="absolute left-0 top-0 h-full bg-red-500/50 rounded-full" style={{ width: `${(amplified / 25) * 100}%` }} />
      <div className="absolute inset-0 flex items-center justify-between px-2 text-xs">
        <span className="text-white font-mono font-bold">{amplified.toFixed(1)}</span>
        <span className="text-gray-300 text-xs">base {base}</span>
      </div>
    </div>
  );
}

export function EOLRiskMapView() {
  const [selectedAsset, setSelectedAsset] = useState<EOLAsset | null>(null);
  const [sortBy, setSortBy] = useState<'amplified' | 'systems' | 'cves'>('amplified');

  const totalSystems = EOL_ASSETS.reduce((s, a) => s + a.systemsAffected, 0);
  const exploitedCount = EOL_ASSETS.filter(a => a.exploitedInWild).length;
  const noPatches = EOL_ASSETS.filter(a => !a.patchAvailable).length;
  const maxAmplified = Math.max(...EOL_ASSETS.map(a => a.amplifiedCvss));

  const sorted = [...EOL_ASSETS].sort((a, b) => {
    if (sortBy === 'amplified') return b.amplifiedCvss - a.amplifiedCvss;
    if (sortBy === 'systems') return b.systemsAffected - a.systemsAffected;
    return b.criticalCves - a.criticalCves;
  });

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">End-of-Life Asset Risk Map</h1>
        <p className="text-gray-400 text-sm mt-1">
          EoL asset CVSS amplification scoring: base score × EoL multiplier (1.4–2.5×).
          India govt networks: &gt;70% EoL rate (NCSP 2023). EoL assets receive <span className="text-red-400 font-semibold">zero patches permanently</span>.
        </p>
      </div>

      {/* KPI Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">EoL Systems At Risk</p>
          <p className="text-2xl font-bold text-orange-400">{totalSystems}</p>
          <p className="text-gray-500 text-xs mt-1">Across 5 CNI sectors</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Max Amplified CVSS</p>
          <p className="text-2xl font-bold text-red-400">{maxAmplified.toFixed(1)}</p>
          <p className="text-gray-500 text-xs mt-1">×2.5 OT amplifier</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Exploited In Wild</p>
          <p className="text-2xl font-bold text-red-400">{exploitedCount}/{EOL_ASSETS.length}</p>
          <p className="text-gray-500 text-xs mt-1">Active exploitation observed</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">No Patch Available</p>
          <p className="text-2xl font-bold text-red-400">{noPatches}/{EOL_ASSETS.length}</p>
          <p className="text-gray-500 text-xs mt-1">Permanently unpatched</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Asset Risk List */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-white font-semibold">EoL Asset Inventory</h2>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-gray-400">Sort:</span>
              {(['amplified', 'systems', 'cves'] as const).map(s => (
                <button
                  key={s}
                  onClick={() => setSortBy(s)}
                  className={`px-2 py-1 rounded ${sortBy === s ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}
                >
                  {s === 'amplified' ? 'CVSS' : s === 'systems' ? 'Systems' : 'CVEs'}
                </button>
              ))}
            </div>
          </div>
          <div className="space-y-3">
            {sorted.map(asset => (
              <button
                key={asset.id}
                onClick={() => setSelectedAsset(selectedAsset?.id === asset.id ? null : asset)}
                className={`w-full text-left p-3 rounded border transition-all ${
                  selectedAsset?.id === asset.id
                    ? 'border-blue-500 bg-blue-500/5'
                    : 'border-gray-700 bg-gray-800 hover:border-gray-500'
                }`}
              >
                <div className="flex items-start justify-between gap-3 mb-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded">{CATEGORY_LABELS[asset.category]}</span>
                      {!asset.patchAvailable && <span className="text-xs bg-red-900/30 text-red-400 border border-red-700/30 px-1.5 py-0.5 rounded">No Patch</span>}
                      {asset.exploitedInWild && <span className="text-xs bg-red-600 text-white px-1.5 py-0.5 rounded font-semibold">Actively Exploited</span>}
                    </div>
                    <p className="text-sm text-white font-medium mt-1">{asset.product} {asset.version}</p>
                    <p className="text-xs text-gray-400">{asset.sector} · {asset.systemsAffected} systems</p>
                    <p className="text-xs text-gray-500">EoL: {asset.eolDate} · {asset.cveCount} CVEs ({asset.criticalCves} critical)</p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className={`text-xl font-bold ${asset.amplifiedCvss >= 20 ? 'text-red-400' : asset.amplifiedCvss >= 16 ? 'text-red-400' : asset.amplifiedCvss >= 12 ? 'text-orange-400' : 'text-yellow-400'}`}>
                      {asset.amplifiedCvss.toFixed(1)}
                    </p>
                    <p className="text-xs text-gray-500">×{asset.amplifier} amplified</p>
                  </div>
                </div>
                <AmplifiedCvssBar base={asset.baseCvss} amplified={asset.amplifiedCvss} />
              </button>
            ))}
          </div>
        </div>

        {/* Right Panel */}
        <div className="space-y-4">
          {/* Asset Detail */}
          {selectedAsset ? (
            <div className="bg-gray-900 border border-blue-500/30 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-white font-semibold text-sm">Asset Detail</h3>
                <button onClick={() => setSelectedAsset(null)} className="text-gray-500 hover:text-gray-300 text-xs">✕</button>
              </div>
              <div className="space-y-2 text-xs">
                <div><p className="text-gray-400">Product</p><p className="text-white">{selectedAsset.product} {selectedAsset.version}</p></div>
                <div><p className="text-gray-400">Vendor</p><p className="text-white">{selectedAsset.vendor}</p></div>
                <div><p className="text-gray-400">EoL Date</p><p className="text-red-400 font-semibold">{selectedAsset.eolDate}</p></div>
                <div><p className="text-gray-400">Sector / Location</p><p className="text-white">{selectedAsset.sector} · {selectedAsset.location}</p></div>
                <div><p className="text-gray-400">Systems at Risk</p><p className="text-orange-400 font-semibold">{selectedAsset.systemsAffected}</p></div>
                <div>
                  <p className="text-gray-400">CVSS Amplification</p>
                  <p className="text-white">{selectedAsset.baseCvss} (base) × {selectedAsset.amplifier} = <span className="text-red-400 font-bold">{selectedAsset.amplifiedCvss.toFixed(1)}</span></p>
                </div>
                <div><p className="text-gray-400">Total CVEs</p><p className="text-white">{selectedAsset.cveCount} ({selectedAsset.criticalCves} critical)</p></div>
                <div>
                  <p className="text-gray-400">Patch Available</p>
                  <p className={selectedAsset.patchAvailable ? 'text-green-400' : 'text-red-400 font-semibold'}>
                    {selectedAsset.patchAvailable ? 'Yes — apply immediately' : 'NO — vendor EOL, no patches ever'}
                  </p>
                </div>
                <div>
                  <p className="text-gray-400">Exploited in Wild</p>
                  <p className={selectedAsset.exploitedInWild ? 'text-red-400 font-semibold' : 'text-gray-400'}>
                    {selectedAsset.exploitedInWild ? 'YES — active exploitation confirmed' : 'Not confirmed'}
                  </p>
                </div>
              </div>
              {!selectedAsset.patchAvailable && (
                <div className="mt-3 p-2 bg-red-900/20 border border-red-700/30 rounded text-xs text-red-300">
                  <p className="font-semibold mb-1">Recommended Remediation</p>
                  <p>1. Network isolate from internet-facing systems immediately</p>
                  <p>2. Schedule hardware replacement within 90 days</p>
                  <p>3. Deploy virtual patching (WAF/IPS rules) as interim control</p>
                  <p>4. File asset in CERT-In inventory per NCSP 2023 §4.2</p>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
              <h3 className="text-white font-semibold mb-3 text-sm">Risk by Sector</h3>
              <div className="space-y-3">
                {SECTOR_TOTALS.map(s => (
                  <div key={s.sector}>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="text-gray-300">{s.sector}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-gray-400">{s.systems} systems</span>
                        <span className={`font-semibold ${s.critScore >= 20 ? 'text-red-400' : s.critScore >= 16 ? 'text-orange-400' : 'text-yellow-400'}`}>
                          CVSS {s.critScore}
                        </span>
                      </div>
                    </div>
                    <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                      <div className={`h-full ${s.color} rounded-full`} style={{ width: `${Math.min((s.critScore / 25) * 100, 100)}%` }} />
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-3 pt-3 border-t border-gray-700 text-xs">
                <p className="text-gray-400 mb-1">Amplifier Scale</p>
                <div className="space-y-1">
                  <div className="flex items-center gap-2"><div className="w-12 h-1.5 bg-yellow-500 rounded" /><span className="text-gray-400">×1.4 (App 6m–2y EoL)</span></div>
                  <div className="flex items-center gap-2"><div className="w-12 h-1.5 bg-orange-500 rounded" /><span className="text-gray-400">×1.6–2.0 (OS/Server)</span></div>
                  <div className="flex items-center gap-2"><div className="w-12 h-1.5 bg-red-500 rounded" /><span className="text-gray-400">×2.2–2.5 (ICS/OT)</span></div>
                </div>
              </div>
            </div>
          )}

          {/* Top CVEs */}
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <h3 className="text-white font-semibold mb-3 text-sm">Critical CVEs — EoL Amplified</h3>
            <div className="space-y-2">
              {TOP_CVES.slice(0, 4).map(cve => (
                <div key={cve.cveId} className="p-2 bg-gray-800 rounded border border-gray-700 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-blue-400">{cve.cveId}</span>
                    <div className="flex items-center gap-2">
                      {cve.exploited && <span className="text-red-400 font-semibold text-xs">KEV</span>}
                      <span className="text-red-400 font-bold">{cve.amplified.toFixed(1)}</span>
                    </div>
                  </div>
                  <p className="text-gray-300">{cve.description.slice(0, 70)}…</p>
                  <div className="flex gap-1 mt-1 flex-wrap">
                    {cve.assets.map(a => <span key={a} className="text-gray-500 bg-gray-700 px-1 rounded">{a}</span>)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="text-center text-xs text-gray-600 pb-2">
        EoL amplification model: NCSP 2023 · CERT-In KEV alignment · CISA Known Exploited Vulnerabilities catalog · NVD
      </div>
    </div>
  );
}
