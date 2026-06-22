'use client';

import { useState, useEffect } from 'react';

interface CERTInReport {
  report_id: string;
  category: string;
  hours_remaining: number;
  status: 'pending' | 'filed' | 'overdue';
}

interface APTAttribution {
  actor: string;
  alias: string;
  sector: string;
  confidence: number;
  incidents: number;
  last_seen: string;
  origin: string;
}

interface EOLRisk {
  product: string;
  base_cvss: number;
  amplified_cvss: number;
  amplifier: number;
  systems_affected: number;
}

interface OTIncident {
  protocol: string;
  technique: string;
  asset_type: string;
  impact: string;
  timestamp: string;
}

// Static demo data representing the CNI threat landscape
const CERTIN_REPORTS: CERTInReport[] = [
  { report_id: 'CERTIN-CNI001-A1B2', category: 'CAT-4 Ransomware', hours_remaining: 4.2, status: 'pending' },
  { report_id: 'CERTIN-CNI002-C3D4', category: 'CAT-9 Data Breach', hours_remaining: -0.5, status: 'overdue' },
  { report_id: 'CERTIN-CNI003-E5F6', category: 'CAT-10 Critical Infra', hours_remaining: 2.8, status: 'pending' },
  { report_id: 'CERTIN-CNI004-G7H8', category: 'CAT-3 Unauth Access', hours_remaining: 5.1, status: 'filed' },
];

const APT_ATTRIBUTIONS: APTAttribution[] = [
  { actor: 'APT36', alias: 'Transparent Tribe', sector: 'Education (CBSE)', confidence: 87, incidents: 3, last_seen: '2h ago', origin: 'Pakistan-linked' },
  { actor: 'SideCopy', alias: 'APT-C-24', sector: 'Defence / Govt IT', confidence: 79, incidents: 2, last_seen: '6h ago', origin: 'Pakistan-linked' },
  { actor: 'Volt Typhoon', alias: 'Bronze Silhouette', sector: 'Power Grid (PGCIL)', confidence: 92, incidents: 1, last_seen: '1h ago', origin: 'China-linked' },
  { actor: 'Lazarus India', alias: 'Hidden Cobra', sector: 'Healthcare (AIIMS)', confidence: 68, incidents: 1, last_seen: '12h ago', origin: 'DPRK-linked' },
];

const EOL_RISKS: EOLRisk[] = [
  { product: 'Windows 7 (Ministry IT)', base_cvss: 7.5, amplified_cvss: 16.5, amplifier: 2.2, systems_affected: 214 },
  { product: 'Windows Server 2008 (AIIMS)', base_cvss: 7.5, amplified_cvss: 16.5, amplifier: 2.2, systems_affected: 43 },
  { product: 'Apache HTTP 2.2 (Govt Portal)', base_cvss: 9.8, amplified_cvss: 13.7, amplifier: 1.4, systems_affected: 12 },
  { product: 'Siemens S7-300 PLC (Power Grid)', base_cvss: 8.1, amplified_cvss: 20.25, amplifier: 2.5, systems_affected: 8 },
];

const OT_INCIDENTS: OTIncident[] = [
  { protocol: 'Modbus', technique: 'T0855 Unauthorized Command', asset_type: 'PLC', impact: 'SAFETY_CRITICAL', timestamp: '01:23 IST' },
  { protocol: 'DNP3', technique: 'T0815 Denial of Control', asset_type: 'RTU', impact: 'HIGH', timestamp: '03:47 IST' },
  { protocol: 'SCADA', technique: 'T0826 Loss of Availability', asset_type: 'HMI', impact: 'MEDIUM', timestamp: '05:12 IST' },
];

const SECTOR_STATS = [
  { sector: 'Healthcare', label: 'AIIMS Pattern', incidents: 4, critical: 2, color: 'bg-red-500' },
  { sector: 'Education', label: 'CBSE/Exams', incidents: 3, critical: 2, color: 'bg-orange-500' },
  { sector: 'Power Grid', label: 'NTPC/PGCIL', incidents: 2, critical: 2, color: 'bg-yellow-500' },
  { sector: 'Government IT', label: 'Ministry/NIC', incidents: 5, critical: 1, color: 'bg-blue-500' },
];

function MetricCard({ label, value, sub, color = 'text-white' }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
      <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-gray-500 text-xs mt-1">{sub}</p>}
    </div>
  );
}

function CertinRow({ report }: { report: CERTInReport }) {
  const statusColor = report.status === 'filed' ? 'text-green-400 bg-green-400/10' :
    report.status === 'overdue' ? 'text-red-400 bg-red-400/10' : 'text-yellow-400 bg-yellow-400/10';
  const statusLabel = report.status === 'filed' ? 'Filed' : report.status === 'overdue' ? 'OVERDUE' : 'Pending';
  return (
    <div className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0">
      <div>
        <p className="text-sm text-white font-mono">{report.report_id}</p>
        <p className="text-xs text-gray-400">{report.category}</p>
      </div>
      <div className="flex items-center gap-3">
        <span className="text-xs text-gray-400">
          {report.status === 'filed' ? 'Submitted' :
           report.hours_remaining < 0 ? `${Math.abs(report.hours_remaining).toFixed(1)}h late` :
           `${report.hours_remaining.toFixed(1)}h left`}
        </span>
        <span className={`text-xs px-2 py-0.5 rounded font-semibold ${statusColor}`}>{statusLabel}</span>
      </div>
    </div>
  );
}

function APTRow({ apt }: { apt: APTAttribution }) {
  const originColor = apt.origin.includes('Pakistan') ? 'text-orange-400' :
    apt.origin.includes('China') ? 'text-red-400' : 'text-purple-400';
  return (
    <div className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0">
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-white">{apt.actor} <span className="text-gray-500 font-normal text-xs">({apt.alias})</span></p>
        <p className="text-xs text-gray-400">{apt.sector}</p>
      </div>
      <div className="flex items-center gap-4 shrink-0">
        <span className={`text-xs ${originColor}`}>{apt.origin}</span>
        <div className="text-right">
          <p className="text-sm text-white font-semibold">{apt.confidence}%</p>
          <p className="text-xs text-gray-500">{apt.incidents} incidents</p>
        </div>
      </div>
    </div>
  );
}

function EOLRow({ eol }: { eol: EOLRisk }) {
  const amplifierColor = eol.amplifier >= 2.0 ? 'text-red-400' : eol.amplifier >= 1.8 ? 'text-orange-400' : 'text-yellow-400';
  return (
    <div className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0">
      <div className="flex-1 min-w-0">
        <p className="text-sm text-white truncate">{eol.product}</p>
        <p className="text-xs text-gray-400">{eol.systems_affected} systems at risk · No patches available</p>
      </div>
      <div className="text-right shrink-0 ml-4">
        <p className={`text-sm font-bold ${amplifierColor}`}>{eol.amplified_cvss.toFixed(1)}</p>
        <p className="text-xs text-gray-500">×{eol.amplifier} (base {eol.base_cvss})</p>
      </div>
    </div>
  );
}

export function CNIDashboard() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const overdueCount = CERTIN_REPORTS.filter(r => r.status === 'overdue').length;
  const pendingCount = CERTIN_REPORTS.filter(r => r.status === 'pending').length;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span className="text-2xl">🇮🇳</span>
            India CNI Threat Dashboard
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            AI-Driven Cyber Resilience for Critical National Infrastructure · CERT-In Directions 2022 · NCIIPC
          </p>
        </div>
        <div className="text-right">
          <p className="text-gray-400 text-xs">Live · IST</p>
          <p className="text-white font-mono text-sm">{now.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata' })}</p>
        </div>
      </div>

      {/* Top KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Active CNI Incidents" value={14} sub="4 critical" color="text-red-400" />
        <MetricCard label="CERT-In Reports Overdue" value={overdueCount} sub="6-hr deadline breached" color={overdueCount > 0 ? 'text-red-400' : 'text-green-400'} />
        <MetricCard label="EoL Systems At Risk" value={277} sub="67% of govt inventory" color="text-orange-400" />
        <MetricCard label="APT Groups Active" value={4} sub="SideCopy · APT36 · VT · Lazarus" color="text-yellow-400" />
      </div>

      {/* CNI Sector Summary */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h2 className="text-white font-semibold mb-3">CNI Sector Incident Summary</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {SECTOR_STATS.map(s => (
            <div key={s.sector} className="bg-gray-800 rounded-lg p-3 border border-gray-700">
              <div className={`w-2 h-2 rounded-full ${s.color} mb-2`} />
              <p className="text-white text-sm font-semibold">{s.sector}</p>
              <p className="text-gray-400 text-xs">{s.label}</p>
              <div className="flex items-center gap-2 mt-2">
                <span className="text-white text-lg font-bold">{s.incidents}</span>
                <span className="text-red-400 text-xs">{s.critical} crit</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* CERT-In Compliance */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-white font-semibold">CERT-In 6-Hour Reporting</h2>
            <div className="flex gap-2">
              {overdueCount > 0 && <span className="text-xs bg-red-400/10 text-red-400 px-2 py-0.5 rounded font-semibold">{overdueCount} OVERDUE</span>}
              {pendingCount > 0 && <span className="text-xs bg-yellow-400/10 text-yellow-400 px-2 py-0.5 rounded">{pendingCount} pending</span>}
            </div>
          </div>
          <p className="text-gray-500 text-xs mb-3">Under CERT-In Directions 2022 (IT Act 2000 § 70B) — mandatory report within 6 hours of detection</p>
          <div>
            {CERTIN_REPORTS.map(r => <CertinRow key={r.report_id} report={r} />)}
          </div>
        </div>

        {/* APT Attribution */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <h2 className="text-white font-semibold mb-1">India APT Attribution</h2>
          <p className="text-gray-500 text-xs mb-3">AI attribution using TTP overlap scoring against known India CNI threat actors</p>
          <div>
            {APT_ATTRIBUTIONS.map(a => <APTRow key={a.actor} apt={a} />)}
          </div>
        </div>

        {/* EoL Amplified Risk */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <h2 className="text-white font-semibold mb-1">EoL Asset Risk Amplification</h2>
          <p className="text-gray-500 text-xs mb-3">
            CVSS base score × EoL multiplier (1.4–2.5×). India govt networks: &gt;70% EoL rate (NCSP 2023).
            EoL assets receive <span className="text-red-400 font-semibold">zero patches permanently</span>.
          </p>
          <div>
            {EOL_RISKS.map(e => <EOLRow key={e.product} eol={e} />)}
          </div>
        </div>

        {/* OT/ICS Incidents */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <h2 className="text-white font-semibold mb-1">OT/ICS Incident Feed</h2>
          <p className="text-gray-500 text-xs mb-3">
            OT-SAFE response enforced: network segmentation only, never host isolation (prevents physical process disruption).
            NCIIPC notified on SAFETY_CRITICAL events.
          </p>
          <div className="space-y-2">
            {OT_INCIDENTS.map((ot, i) => (
              <div key={i} className="flex items-center justify-between p-2 bg-gray-800 rounded border border-gray-700">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-blue-400 bg-blue-400/10 px-1.5 py-0.5 rounded">{ot.protocol}</span>
                    <span className="text-xs text-gray-300">{ot.technique}</span>
                  </div>
                  <p className="text-xs text-gray-400 mt-0.5">{ot.asset_type} · {ot.timestamp}</p>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded font-semibold ${
                  ot.impact === 'SAFETY_CRITICAL' ? 'bg-red-600 text-white' :
                  ot.impact === 'HIGH' ? 'text-orange-400 bg-orange-400/10' : 'text-yellow-400 bg-yellow-400/10'
                }`}>{ot.impact}</span>
              </div>
            ))}
          </div>
          <div className="mt-3 p-2 bg-blue-900/20 border border-blue-800/30 rounded text-xs text-blue-300">
            OT-SAFE constraint: SAFETY_CRITICAL events → network DMZ segmentation only. Process control preserved.
            NCIIPC notified per IT Act 2000 §70.
          </div>
        </div>
      </div>

      {/* APT Kill-Chain Prediction */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h2 className="text-white font-semibold mb-3">APT Kill-Chain Stage Prediction</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <p className="text-xs text-gray-400 mb-2">Volt Typhoon (Power Grid) — Current Stage</p>
            <div className="flex items-center gap-1 flex-wrap">
              {['Recon', 'Resource Dev', 'Initial Access', 'Execution', 'Persistence', 'Priv Esc', 'Defense Evasion', 'Discovery'].map((stage, i) => (
                <span key={stage} className={`text-xs px-2 py-0.5 rounded ${i < 8 ? 'bg-red-600 text-white' : 'bg-gray-700 text-gray-400'}`}>{stage}</span>
              ))}
            </div>
            <p className="text-xs text-yellow-400 mt-2">Predicted next: Lateral Movement → C&C → Collection → Impact (T0826 Loss of Availability)</p>
          </div>
          <div>
            <p className="text-xs text-gray-400 mb-2">APT36 (CBSE) — Current Stage</p>
            <div className="flex items-center gap-1 flex-wrap">
              {['Recon', 'Resource Dev', 'Initial Access', 'Execution', 'Persistence', 'Priv Esc', 'Defense Evasion', 'Discovery', 'Lateral Mvmt', 'Collection', 'Exfiltration'].map((stage, i) => (
                <span key={stage} className={`text-xs px-2 py-0.5 rounded ${i < 11 ? 'bg-orange-600 text-white' : 'bg-gray-700 text-gray-400'}`}>{stage}</span>
              ))}
            </div>
            <p className="text-xs text-yellow-400 mt-2">Predicted next: Ransomware deployment (T1486) within 24–72 hours based on historical APT36 pattern</p>
          </div>
        </div>
      </div>

      {/* Footer note */}
      <div className="text-center text-xs text-gray-600 pb-2">
        AiSOC India CNI · ET Hackathon 2026 · CERT-In Directions 2022 · NCIIPC · IT Act 2000 §70
      </div>
    </div>
  );
}
