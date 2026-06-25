'use client';

import { useState } from 'react';

type EntityType = 'user' | 'device' | 'service' | 'ot-asset';
type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

interface Anomaly {
  id: string;
  entityType: EntityType;
  entityId: string;
  sector: string;
  eventType: string;
  anomalyScore: number;
  riskLevel: RiskLevel;
  peerDeviation: number;
  baselineSummary: string;
  observed: string;
  detectedAt: string;
  acknowledged: boolean;
  mitre?: string;
}

interface Baseline {
  entityId: string;
  entityType: EntityType;
  feature: string;
  baselineMean: string;
  currentValue: string;
  deviationSigma: number;
}

interface PeerGroup {
  id: string;
  label: string;
  entityType: EntityType;
  members: number;
  anomalousMembers: number;
}

// Behavioural anomalies derived from baseline deviations — NO signatures.
const ANOMALIES: Anomaly[] = [
  {
    id: 'UEBA-0001',
    entityType: 'user',
    entityId: 'exam.coordinator@cbse.gov.in',
    sector: 'Education (CBSE)',
    eventType: 'Database read volume',
    anomalyScore: 0.97,
    riskLevel: 'critical',
    peerDeviation: 8.4,
    baselineSummary: 'Normally reads ~120 records/hr during 09:00–18:00 IST',
    observed: 'Read 540,000 records at 02:14 IST (4,500× baseline, off-hours)',
    detectedAt: '02:14 IST',
    acknowledged: false,
    mitre: 'T1530 Data from Cloud Storage',
  },
  {
    id: 'UEBA-0002',
    entityType: 'ot-asset',
    entityId: 'PGCIL-SUBSTATION-HMI01',
    sector: 'Power Grid (PGCIL)',
    eventType: 'Modbus write frequency',
    anomalyScore: 0.94,
    riskLevel: 'critical',
    peerDeviation: 6.1,
    baselineSummary: 'HMI issues read-only polls; never writes to PLC register 4096',
    observed: 'First-ever FC-16 write to holding register 4096 at 01:23 IST',
    detectedAt: '01:23 IST',
    acknowledged: false,
    mitre: 'T0855 Unauthorized Command Message',
  },
  {
    id: 'UEBA-0003',
    entityType: 'device',
    entityId: 'AIIMS-EHR-SRV01',
    sector: 'Healthcare (AIIMS)',
    eventType: 'SMB lateral connections',
    anomalyScore: 0.89,
    riskLevel: 'high',
    peerDeviation: 5.2,
    baselineSummary: 'Talks to 3–4 fixed application hosts',
    observed: 'Initiated SMB to 34 distinct hosts in 6 min (fan-out lateral pattern)',
    detectedAt: '01:31 IST',
    acknowledged: false,
    mitre: 'T1021.002 SMB/Windows Admin Shares',
  },
  {
    id: 'UEBA-0004',
    entityType: 'user',
    entityId: 'svc_backup@ministry.gov.in',
    sector: 'Govt IT (Ministry)',
    eventType: 'Auth geo-velocity',
    anomalyScore: 0.81,
    riskLevel: 'high',
    peerDeviation: 4.7,
    baselineSummary: 'Service account: scripted logins from 10.20.x only',
    observed: 'Interactive RDP login from 103.76.228.95 (foreign ASN)',
    detectedAt: '23:48 IST',
    acknowledged: false,
    mitre: 'T1078 Valid Accounts',
  },
  {
    id: 'UEBA-0005',
    entityType: 'device',
    entityId: 'MINISTRY-WS-047',
    sector: 'Govt IT (Ministry)',
    eventType: 'Process spawn entropy',
    anomalyScore: 0.74,
    riskLevel: 'medium',
    peerDeviation: 3.9,
    baselineSummary: 'Office workstation: Word, Outlook, browser only',
    observed: 'powershell.exe -enc spawned by winword.exe (macro execution)',
    detectedAt: '23:50 IST',
    acknowledged: true,
    mitre: 'T1059.001 PowerShell',
  },
  {
    id: 'UEBA-0006',
    entityType: 'service',
    entityId: 'cbse-result-api',
    sector: 'Education (CBSE)',
    eventType: 'Egress data volume',
    anomalyScore: 0.86,
    riskLevel: 'high',
    peerDeviation: 5.5,
    baselineSummary: 'Outbound ~50 MB/day to known CDN endpoints',
    observed: '4.7 GB outbound to 103.76.228.95 over 40 min',
    detectedAt: '02:55 IST',
    acknowledged: false,
    mitre: 'T1041 Exfiltration Over C2 Channel',
  },
];

const BASELINES: Baseline[] = [
  { entityId: 'exam.coordinator@cbse.gov.in', entityType: 'user', feature: 'records_read_per_hour', baselineMean: '118 ± 22', currentValue: '540,000', deviationSigma: 8.4 },
  { entityId: 'PGCIL-SUBSTATION-HMI01', entityType: 'ot-asset', feature: 'modbus_write_ops', baselineMean: '0 ± 0', currentValue: '1 (FC-16)', deviationSigma: 6.1 },
  { entityId: 'AIIMS-EHR-SRV01', entityType: 'device', feature: 'distinct_smb_peers', baselineMean: '3.5 ± 0.9', currentValue: '34', deviationSigma: 5.2 },
  { entityId: 'svc_backup@ministry.gov.in', entityType: 'user', feature: 'login_geo_distance_km', baselineMean: '12 ± 8', currentValue: '3,100', deviationSigma: 4.7 },
];

const PEER_GROUPS: PeerGroup[] = [
  { id: 'pg-exam-staff', label: 'CBSE Exam Coordinators', entityType: 'user', members: 47, anomalousMembers: 1 },
  { id: 'pg-ehr-servers', label: 'AIIMS EHR Servers', entityType: 'device', members: 12, anomalousMembers: 2 },
  { id: 'pg-substation-hmi', label: 'PGCIL Substation HMIs', entityType: 'ot-asset', members: 8, anomalousMembers: 1 },
  { id: 'pg-ministry-svc', label: 'Ministry Service Accounts', entityType: 'user', members: 134, anomalousMembers: 1 },
];

const RISK_CFG: Record<RiskLevel, { dot: string; text: string; bg: string }> = {
  critical: { dot: 'bg-red-500', text: 'text-red-400', bg: 'bg-red-500/10 border-red-400/20' },
  high: { dot: 'bg-orange-500', text: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-400/20' },
  medium: { dot: 'bg-yellow-500', text: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-400/20' },
  low: { dot: 'bg-blue-500', text: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-400/20' },
};

const ENTITY_ICON: Record<EntityType, string> = {
  user: '👤', device: '💻', service: '⚙️', 'ot-asset': '🏭',
};

function ScoreGauge({ score, level }: { score: number; level: RiskLevel }) {
  const pct = Math.round(score * 100);
  return (
    <div className="flex items-center gap-2">
      <div className="relative w-12 h-12">
        <svg className="w-12 h-12 -rotate-90" viewBox="0 0 36 36">
          <circle cx="18" cy="18" r="15.5" fill="none" stroke="#374151" strokeWidth="3" />
          <circle
            cx="18" cy="18" r="15.5" fill="none"
            stroke={level === 'critical' ? '#ef4444' : level === 'high' ? '#f97316' : level === 'medium' ? '#eab308' : '#3b82f6'}
            strokeWidth="3" strokeDasharray={`${pct} 100`} strokeLinecap="round"
          />
        </svg>
        <span className="absolute inset-0 flex items-center justify-center text-xs font-bold text-white">{pct}</span>
      </div>
    </div>
  );
}

export function UEBAView() {
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all');
  const [acked, setAcked] = useState<Set<string>>(new Set(ANOMALIES.filter(a => a.acknowledged).map(a => a.id)));
  const [selected, setSelected] = useState<Anomaly | null>(null);

  const toggleAck = (id: string) => {
    setAcked(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const visible = ANOMALIES.filter(a => riskFilter === 'all' || a.riskLevel === riskFilter);
  const openCount = ANOMALIES.filter(a => !acked.has(a.id)).length;
  const criticalCount = ANOMALIES.filter(a => a.riskLevel === 'critical').length;
  const avgScore = (ANOMALIES.reduce((s, a) => s + a.anomalyScore, 0) / ANOMALIES.length).toFixed(2);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Behavioural Anomaly Detection (UEBA)</h1>
        <p className="text-gray-400 text-sm mt-1">
          Multi-agent behavioural intelligence layer. Builds baseline profiles for users, devices, services and OT assets,
          then scores deviations across logs, network flows and endpoint telemetry — <span className="text-green-400">signature-free</span>.
          Catches low-and-slow APTs that evade signature detection.
        </p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Open Anomalies</p>
          <p className="text-2xl font-bold text-orange-400">{openCount}</p>
          <p className="text-gray-500 text-xs mt-1">Awaiting triage</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Critical Deviations</p>
          <p className="text-2xl font-bold text-red-400">{criticalCount}</p>
          <p className="text-gray-500 text-xs mt-1">&gt;6σ from baseline</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Avg Anomaly Score</p>
          <p className="text-2xl font-bold text-yellow-400">{avgScore}</p>
          <p className="text-gray-500 text-xs mt-1">0=normal · 1=anomalous</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Entities Profiled</p>
          <p className="text-2xl font-bold text-white">201</p>
          <p className="text-gray-500 text-xs mt-1">4 peer groups baselined</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Anomaly Feed */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-white font-semibold">Live Anomaly Feed</h2>
            <div className="flex items-center gap-1 text-xs">
              {(['all', 'critical', 'high', 'medium'] as const).map(r => (
                <button
                  key={r}
                  onClick={() => setRiskFilter(r)}
                  className={`px-2 py-1 rounded capitalize ${riskFilter === r ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>
          <div className="space-y-3">
            {visible.map(a => {
              const cfg = RISK_CFG[a.riskLevel];
              const isAck = acked.has(a.id);
              return (
                <div
                  key={a.id}
                  className={`p-3 rounded border transition-all cursor-pointer ${cfg.bg} ${isAck ? 'opacity-50' : ''} ${selected?.id === a.id ? 'ring-1 ring-blue-500' : ''}`}
                  onClick={() => setSelected(selected?.id === a.id ? null : a)}
                >
                  <div className="flex items-start gap-3">
                    <ScoreGauge score={a.anomalyScore} level={a.riskLevel} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-base">{ENTITY_ICON[a.entityType]}</span>
                        <span className="text-sm font-mono text-white truncate">{a.entityId}</span>
                        <span className={`text-xs px-1.5 py-0.5 rounded font-semibold ${cfg.text} ${cfg.bg}`}>{a.riskLevel.toUpperCase()}</span>
                      </div>
                      <p className="text-xs text-gray-300 mt-1">{a.eventType} · {a.sector}</p>
                      <p className="text-xs text-orange-300 mt-0.5">{a.observed}</p>
                      <div className="flex items-center gap-3 mt-1">
                        <span className="text-xs text-gray-500">{a.detectedAt}</span>
                        <span className="text-xs text-purple-400">{a.peerDeviation}σ peer deviation</span>
                        {a.mitre && <span className="text-xs font-mono text-blue-400">{a.mitre.split(' ')[0]}</span>}
                      </div>
                    </div>
                    <button
                      onClick={(e) => { e.stopPropagation(); toggleAck(a.id); }}
                      className={`text-xs px-2 py-1 rounded shrink-0 ${isAck ? 'bg-gray-700 text-gray-400' : 'bg-green-600/20 text-green-400 hover:bg-green-600/30'}`}
                    >
                      {isAck ? 'Acked' : 'Ack'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right rail */}
        <div className="space-y-4">
          {selected ? (
            <div className="bg-gray-900 border border-blue-500/30 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-white font-semibold text-sm">Anomaly Detail</h3>
                <button onClick={() => setSelected(null)} className="text-gray-500 hover:text-gray-300 text-xs">✕</button>
              </div>
              <div className="space-y-2 text-xs">
                <div><p className="text-gray-400">Entity</p><p className="text-white font-mono">{selected.entityId}</p></div>
                <div><p className="text-gray-400">Anomaly Score</p><p className={`font-bold ${RISK_CFG[selected.riskLevel].text}`}>{selected.anomalyScore} ({selected.riskLevel})</p></div>
                <div><p className="text-gray-400">Baseline</p><p className="text-gray-200">{selected.baselineSummary}</p></div>
                <div><p className="text-gray-400">Observed</p><p className="text-orange-300">{selected.observed}</p></div>
                <div><p className="text-gray-400">Peer Deviation</p><p className="text-purple-400">{selected.peerDeviation}σ above peer group</p></div>
                {selected.mitre && <div><p className="text-gray-400">MITRE Mapping</p><p className="text-blue-400 font-mono">{selected.mitre}</p></div>}
              </div>
              <div className="mt-3 p-2 bg-blue-900/20 border border-blue-700/30 rounded text-xs text-blue-300">
                Recommended: correlate with APT attribution + raise to Investigation Queue. Score &gt;0.9 → auto-create case.
              </div>
            </div>
          ) : (
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
              <h3 className="text-white font-semibold mb-3 text-sm">Top Baseline Deviations</h3>
              <div className="space-y-2">
                {BASELINES.map((b, i) => (
                  <div key={i} className="text-xs border-b border-gray-800 pb-2 last:border-0">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300 font-mono truncate">{b.entityId}</span>
                      <span className="text-red-400 font-semibold shrink-0 ml-2">{b.deviationSigma}σ</span>
                    </div>
                    <p className="text-gray-500">{b.feature}</p>
                    <p className="text-gray-400">baseline <span className="text-gray-300">{b.baselineMean}</span> → now <span className="text-orange-400">{b.currentValue}</span></p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Peer Groups */}
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <h3 className="text-white font-semibold mb-3 text-sm">Peer Groups</h3>
            <div className="space-y-2">
              {PEER_GROUPS.map(pg => (
                <div key={pg.id} className="flex items-center justify-between text-xs">
                  <div>
                    <p className="text-gray-200">{pg.label}</p>
                    <p className="text-gray-500">{pg.members} members · {ENTITY_ICON[pg.entityType]} {pg.entityType}</p>
                  </div>
                  {pg.anomalousMembers > 0 ? (
                    <span className="text-red-400 font-semibold">{pg.anomalousMembers} anomalous</span>
                  ) : (
                    <span className="text-green-400">normal</span>
                  )}
                </div>
              ))}
            </div>
            <p className="text-xs text-gray-600 mt-3 pt-3 border-t border-gray-700">
              Peer-group analytics flag an entity whose behaviour diverges from statistically similar entities — even when its own history looks normal.
            </p>
          </div>
        </div>
      </div>

      <div className="text-center text-xs text-gray-600 pb-2">
        UEBA Engine · unsupervised anomaly detection · per-entity baselines + peer-group deviation · signature-free · wired to services/ueba
      </div>
    </div>
  );
}
