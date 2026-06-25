'use client';

import { useState } from 'react';

interface ComplianceReport {
  id: string;
  category: string;
  categoryCode: string;
  incident: string;
  sector: string;
  detectedAt: string;
  reportDeadline: string;
  hoursRemaining: number;
  status: 'filed' | 'pending' | 'overdue';
  filedAt?: string;
  nciipcNotified: boolean;
}

interface ComplianceRule {
  ref: string;
  description: string;
  deadline: string;
  applies_to: string;
}

const CERTIN_CATEGORIES: ComplianceRule[] = [
  { ref: 'CAT-1', description: 'Targeted scanning/probing of critical networks', deadline: '6 hours', applies_to: 'All CNI sectors' },
  { ref: 'CAT-3', description: 'Unauthorised access to IT systems/data', deadline: '6 hours', applies_to: 'Government, Finance' },
  { ref: 'CAT-4', description: 'Defacement of websites or unauthorised changes', deadline: '6 hours', applies_to: 'All CNI sectors' },
  { ref: 'CAT-4', description: 'Ransomware attacks', deadline: '6 hours', applies_to: 'Healthcare, Education, Power' },
  { ref: 'CAT-9', description: 'Data breach or theft of sensitive personal data', deadline: '6 hours', applies_to: 'Healthcare, Finance' },
  { ref: 'CAT-10', description: 'Attacks on critical infrastructure systems', deadline: '6 hours', applies_to: 'Power, Telecom, Govt IT' },
];

const REPORTS: ComplianceReport[] = [
  {
    id: 'CERTIN-CNI001-A1B2',
    category: 'CAT-4 Ransomware',
    categoryCode: 'CAT-4',
    incident: 'LockBit 3.0 — AIIMS EHR System',
    sector: 'Healthcare',
    detectedAt: '2026-06-24T01:23:00+05:30',
    reportDeadline: '2026-06-24T07:23:00+05:30',
    hoursRemaining: 4.2,
    status: 'pending',
    nciipcNotified: false,
  },
  {
    id: 'CERTIN-CNI002-C3D4',
    category: 'CAT-9 Data Breach',
    categoryCode: 'CAT-9',
    incident: 'APT36 — CBSE Student PII Exfiltration (2.3M records)',
    sector: 'Education',
    detectedAt: '2026-06-23T21:00:00+05:30',
    reportDeadline: '2026-06-24T03:00:00+05:30',
    hoursRemaining: -0.5,
    status: 'overdue',
    nciipcNotified: true,
  },
  {
    id: 'CERTIN-CNI003-E5F6',
    category: 'CAT-10 Critical Infra',
    categoryCode: 'CAT-10',
    incident: 'Volt Typhoon — PGCIL Substation OT Pre-Positioning',
    sector: 'Power Grid',
    detectedAt: '2026-06-24T03:47:00+05:30',
    reportDeadline: '2026-06-24T09:47:00+05:30',
    hoursRemaining: 2.8,
    status: 'pending',
    nciipcNotified: true,
  },
  {
    id: 'CERTIN-CNI004-G7H8',
    category: 'CAT-3 Unauth Access',
    categoryCode: 'CAT-3',
    incident: 'Ministry of Finance — Credential Stuffing Attack',
    sector: 'Govt IT',
    detectedAt: '2026-06-23T16:00:00+05:30',
    reportDeadline: '2026-06-23T22:00:00+05:30',
    hoursRemaining: 5.1,
    status: 'filed',
    filedAt: '2026-06-23T20:30:00+05:30',
    nciipcNotified: false,
  },
  {
    id: 'CERTIN-CNI005-H9I0',
    category: 'CAT-4 Ransomware',
    categoryCode: 'CAT-4',
    incident: 'SideCopy — Defence Research Network Defacement',
    sector: 'Defence',
    detectedAt: '2026-06-24T05:12:00+05:30',
    reportDeadline: '2026-06-24T11:12:00+05:30',
    hoursRemaining: 1.2,
    status: 'pending',
    nciipcNotified: false,
  },
];

const SECTOR_COMPLIANCE = [
  { sector: 'Healthcare', total: 2, filed: 0, pending: 1, overdue: 1, rate: 0 },
  { sector: 'Education', total: 1, filed: 0, pending: 0, overdue: 1, rate: 0 },
  { sector: 'Power Grid', total: 1, filed: 0, pending: 1, overdue: 0, rate: 0 },
  { sector: 'Govt IT', total: 1, filed: 1, pending: 0, overdue: 0, rate: 100 },
  { sector: 'Defence', total: 1, filed: 0, pending: 1, overdue: 0, rate: 0 },
];

function StatusBadge({ status }: { status: ComplianceReport['status'] }) {
  const cfg = {
    filed: 'bg-green-400/10 text-green-400 border border-green-400/20',
    pending: 'bg-yellow-400/10 text-yellow-400 border border-yellow-400/20',
    overdue: 'bg-red-500/10 text-red-400 border border-red-400/20',
  }[status];
  const label = { filed: 'Filed', pending: 'Pending', overdue: 'OVERDUE' }[status];
  return <span className={`text-xs px-2 py-0.5 rounded font-semibold ${cfg}`}>{label}</span>;
}

function SlaTimer({ hours, status }: { hours: number; status: ComplianceReport['status'] }) {
  if (status === 'filed') return <span className="text-xs text-green-400">Submitted on time</span>;
  if (hours < 0) {
    return <span className="text-xs text-red-400 font-semibold">{Math.abs(hours).toFixed(1)}h overdue</span>;
  }
  const color = hours < 2 ? 'text-red-400' : hours < 4 ? 'text-yellow-400' : 'text-gray-400';
  return <span className={`text-xs ${color}`}>{hours.toFixed(1)}h remaining</span>;
}

export function CERTInComplianceView() {
  const [selectedReport, setSelectedReport] = useState<ComplianceReport | null>(null);

  const overdueCount = REPORTS.filter(r => r.status === 'overdue').length;
  const pendingCount = REPORTS.filter(r => r.status === 'pending').length;
  const filedCount = REPORTS.filter(r => r.status === 'filed').length;
  const complianceRate = Math.round((filedCount / REPORTS.length) * 100);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          CERT-In 6-Hour Compliance
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          Mandatory incident reporting under CERT-In Directions 2022 (IT Act 2000 §70B).
          All CNI-sector incidents must be reported to CERT-In within <span className="text-yellow-400 font-semibold">6 hours of detection</span>.
        </p>
      </div>

      {/* KPI Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Compliance Rate</p>
          <p className={`text-2xl font-bold ${complianceRate < 50 ? 'text-red-400' : 'text-yellow-400'}`}>{complianceRate}%</p>
          <p className="text-gray-500 text-xs mt-1">{filedCount}/{REPORTS.length} reports filed</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Overdue Reports</p>
          <p className="text-2xl font-bold text-red-400">{overdueCount}</p>
          <p className="text-gray-500 text-xs mt-1">IT Act §70B violation risk</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Pending Deadline</p>
          <p className="text-2xl font-bold text-yellow-400">{pendingCount}</p>
          <p className="text-gray-500 text-xs mt-1">Action required now</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Filed On Time</p>
          <p className="text-2xl font-bold text-green-400">{filedCount}</p>
          <p className="text-gray-500 text-xs mt-1">Full compliance</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Reports Table */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-white font-semibold">Active Incident Reports</h2>
            {overdueCount > 0 && (
              <span className="text-xs bg-red-500/10 text-red-400 border border-red-400/20 px-2 py-0.5 rounded font-semibold">
                {overdueCount} OVERDUE — IT Act penalty risk
              </span>
            )}
          </div>
          <div className="space-y-3">
            {REPORTS.map(report => (
              <button
                key={report.id}
                onClick={() => setSelectedReport(selectedReport?.id === report.id ? null : report)}
                className={`w-full text-left p-3 rounded border transition-all ${
                  selectedReport?.id === report.id
                    ? 'border-blue-500 bg-blue-500/5'
                    : 'border-gray-700 bg-gray-800 hover:border-gray-500'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono text-blue-400 bg-blue-400/10 px-1.5 py-0.5 rounded">{report.id}</span>
                      <span className="text-xs text-gray-400 bg-gray-700 px-1.5 py-0.5 rounded">{report.categoryCode}</span>
                    </div>
                    <p className="text-sm text-white mt-1 truncate">{report.incident}</p>
                    <p className="text-xs text-gray-400 mt-0.5">{report.sector} · {report.category}</p>
                  </div>
                  <div className="flex flex-col items-end gap-1 shrink-0">
                    <StatusBadge status={report.status} />
                    <SlaTimer hours={report.hoursRemaining} status={report.status} />
                    {report.nciipcNotified && (
                      <span className="text-xs text-blue-400">NCIIPC notified</span>
                    )}
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Detail Panel / Sector Compliance */}
        <div className="space-y-4">
          {selectedReport ? (
            <div className="bg-gray-900 border border-blue-500/30 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-white font-semibold text-sm">Report Detail</h3>
                <button onClick={() => setSelectedReport(null)} className="text-gray-500 hover:text-gray-300 text-xs">✕ close</button>
              </div>
              <div className="space-y-2 text-xs">
                <div>
                  <p className="text-gray-400">Report ID</p>
                  <p className="text-white font-mono">{selectedReport.id}</p>
                </div>
                <div>
                  <p className="text-gray-400">Incident</p>
                  <p className="text-white">{selectedReport.incident}</p>
                </div>
                <div>
                  <p className="text-gray-400">Category</p>
                  <p className="text-white">{selectedReport.category}</p>
                </div>
                <div>
                  <p className="text-gray-400">Sector</p>
                  <p className="text-white">{selectedReport.sector}</p>
                </div>
                <div>
                  <p className="text-gray-400">Detected At (IST)</p>
                  <p className="text-white font-mono">{new Date(selectedReport.detectedAt).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}</p>
                </div>
                <div>
                  <p className="text-gray-400">Report Deadline (IST)</p>
                  <p className={`font-mono font-semibold ${selectedReport.hoursRemaining < 0 ? 'text-red-400' : 'text-yellow-400'}`}>
                    {new Date(selectedReport.reportDeadline).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}
                  </p>
                </div>
                {selectedReport.filedAt && (
                  <div>
                    <p className="text-gray-400">Filed At (IST)</p>
                    <p className="text-green-400 font-mono">{new Date(selectedReport.filedAt).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}</p>
                  </div>
                )}
                <div>
                  <p className="text-gray-400">NCIIPC Notified</p>
                  <p className={selectedReport.nciipcNotified ? 'text-green-400' : 'text-gray-500'}>
                    {selectedReport.nciipcNotified ? 'Yes (IT Act §70)' : 'No — action required'}
                  </p>
                </div>
              </div>
              {selectedReport.status !== 'filed' && (
                <div className="mt-3 p-2 bg-yellow-900/20 border border-yellow-700/30 rounded text-xs text-yellow-300">
                  File report at <span className="font-mono">incident.cert-in.org.in</span> before deadline to avoid §70B penalties.
                </div>
              )}
            </div>
          ) : (
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
              <h3 className="text-white font-semibold mb-3 text-sm">Sector Compliance</h3>
              <div className="space-y-3">
                {SECTOR_COMPLIANCE.map(s => (
                  <div key={s.sector}>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="text-gray-300">{s.sector}</span>
                      <div className="flex items-center gap-2">
                        {s.overdue > 0 && <span className="text-red-400">{s.overdue} overdue</span>}
                        {s.pending > 0 && <span className="text-yellow-400">{s.pending} pending</span>}
                        {s.filed > 0 && <span className="text-green-400">{s.filed} filed</span>}
                      </div>
                    </div>
                    <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden flex">
                      <div className="h-full bg-green-500" style={{ width: `${(s.filed / s.total) * 100}%` }} />
                      <div className="h-full bg-yellow-500" style={{ width: `${(s.pending / s.total) * 100}%` }} />
                      <div className="h-full bg-red-500" style={{ width: `${(s.overdue / s.total) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* CERT-In Category Reference */}
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <h3 className="text-white font-semibold mb-3 text-sm">Reportable Categories (CERT-In 2022)</h3>
            <div className="space-y-2">
              {CERTIN_CATEGORIES.map((rule, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <span className="text-blue-400 font-mono shrink-0 w-12">{rule.ref}</span>
                  <div>
                    <p className="text-gray-300">{rule.description}</p>
                    <p className="text-gray-500">{rule.applies_to}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-3 pt-3 border-t border-gray-700 text-xs text-gray-500">
              All 20 categories require reporting within 6 hours. Non-compliance: up to ₹1 lakh fine + imprisonment under IT Act 2000 §70B.
            </div>
          </div>
        </div>
      </div>

      <div className="text-center text-xs text-gray-600 pb-2">
        CERT-In Directions 2022 · IT Act 2000 §70B · NCIIPC Act · India CNI Compliance Framework
      </div>
    </div>
  );
}
