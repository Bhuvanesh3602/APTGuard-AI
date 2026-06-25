'use client';

import { useState } from 'react';

interface OTAsset {
  id: string;
  name: string;
  type: 'plc' | 'hmi' | 'rtu' | 'historian' | 'workstation' | 'firewall' | 'switch';
  protocol: string[];
  zone: 'it' | 'dmz' | 'ot-level3' | 'ot-level2' | 'ot-level1' | 'field';
  status: 'normal' | 'alert' | 'critical' | 'offline';
  vendor?: string;
  firmware?: string;
  isEol?: boolean;
  lastSeen: string;
}

interface OTConnection {
  from: string;
  to: string;
  protocol: string;
  anomalous: boolean;
}

interface OTProtocolEvent {
  ts: string;
  protocol: string;
  src: string;
  dst: string;
  function_code: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'normal';
}

const OT_ASSETS: OTAsset[] = [
  { id: 'fw-ot', name: 'Palo Alto PA-3260 (IT-OT Firewall)', type: 'firewall', protocol: ['TCP/IP'], zone: 'dmz', status: 'normal', lastSeen: '0s ago' },
  { id: 'hist-1', name: 'OSIsoft PI Historian', type: 'historian', protocol: ['OPC-DA', 'PI-API'], zone: 'ot-level3', status: 'normal', vendor: 'OSIsoft', lastSeen: '5s ago' },
  { id: 'hmi-pgcil1', name: 'PGCIL-SUBSTATION-HMI01', type: 'hmi', protocol: ['Modbus/TCP', 'DNP3'], zone: 'ot-level2', status: 'critical', vendor: 'GE iFIX', lastSeen: '1m ago' },
  { id: 'hmi-pgcil2', name: 'PGCIL-CONTROL-HMI02', type: 'hmi', protocol: ['IEC 61850'], zone: 'ot-level2', status: 'alert', vendor: 'Siemens WinCC', lastSeen: '2m ago' },
  { id: 'rtu-1', name: 'SEL-3530 RTU (Bay Controller)', type: 'rtu', protocol: ['DNP3', 'IEC 61850'], zone: 'ot-level1', status: 'alert', vendor: 'SEL', lastSeen: '30s ago' },
  { id: 'plc-pgcil', name: 'PGCIL-PLC-GRID01 (Siemens S7-300)', type: 'plc', protocol: ['Modbus', 'S7comm'], zone: 'ot-level1', status: 'critical', vendor: 'Siemens', firmware: 'V3.3.17', lastSeen: '45s ago' },
  { id: 'plc-backup', name: 'PGCIL-PLC-GRID02 (Backup)', type: 'plc', protocol: ['Modbus'], zone: 'ot-level1', status: 'normal', vendor: 'Siemens', lastSeen: '1m ago' },
  { id: 'eng-ws', name: 'Engineering Workstation EWS-01', type: 'workstation', protocol: ['S7comm', 'RDP'], zone: 'ot-level2', status: 'alert', isEol: true, lastSeen: '5m ago' },
  { id: 'sw-ot', name: 'Cisco IE-4000 (OT Switch)', type: 'switch', protocol: ['Ethernet', 'PROFINET'], zone: 'ot-level2', status: 'normal', lastSeen: '0s ago' },
];

const CONNECTIONS: OTConnection[] = [
  { from: 'fw-ot', to: 'hist-1', protocol: 'TCP/IP', anomalous: false },
  { from: 'hist-1', to: 'hmi-pgcil1', protocol: 'OPC-DA', anomalous: false },
  { from: 'hmi-pgcil1', to: 'plc-pgcil', protocol: 'Modbus/TCP', anomalous: true },
  { from: 'hmi-pgcil2', to: 'rtu-1', protocol: 'IEC 61850', anomalous: false },
  { from: 'rtu-1', to: 'plc-pgcil', protocol: 'DNP3', anomalous: false },
  { from: 'eng-ws', to: 'hmi-pgcil1', protocol: 'RDP', anomalous: true },
  { from: 'sw-ot', to: 'plc-pgcil', protocol: 'Ethernet', anomalous: false },
  { from: 'sw-ot', to: 'plc-backup', protocol: 'Ethernet', anomalous: false },
];

const PROTOCOL_EVENTS: OTProtocolEvent[] = [
  { ts: '01:23:44 IST', protocol: 'Modbus', src: 'PGCIL-SUBSTATION-HMI01', dst: 'PGCIL-PLC-GRID01', function_code: 'FC-16 (Write Mult Regs)', description: 'Unauthorized write to holding register 4096 — relay trip threshold modified', severity: 'critical' },
  { ts: '01:23:11 IST', protocol: 'RDP', src: 'IT-WS-047', dst: 'Engineering WS EWS-01', function_code: 'Session Initiated', description: 'RDP lateral move from IT zone to OT DMZ engineering workstation', severity: 'high' },
  { ts: '03:47:22 IST', protocol: 'DNP3', src: 'SEL-3530 RTU', dst: 'PGCIL-PLC-GRID01', function_code: 'DIRECT_OPERATE (FC-3)', description: 'DNP3 direct operate on binary output — potential relay control', severity: 'high' },
  { ts: '05:12:55 IST', protocol: 'S7comm', src: 'EWS-01', dst: 'PGCIL-PLC-GRID01', function_code: 'Read SZL (0x0131)', description: 'S7comm SZL read — CPU hardware/software inventory enumeration', severity: 'medium' },
  { ts: '06:01:33 IST', protocol: 'Modbus', src: 'PGCIL-PLC-GRID01', dst: 'PGCIL-PLC-GRID02', function_code: 'FC-1 (Read Coils)', description: 'Normal inter-PLC coil sync — within expected operational range', severity: 'normal' },
];

const ZONE_COLORS: Record<OTAsset['zone'], string> = {
  it: 'border-blue-600 bg-blue-900/20',
  dmz: 'border-yellow-600 bg-yellow-900/10',
  'ot-level3': 'border-purple-600 bg-purple-900/10',
  'ot-level2': 'border-orange-600 bg-orange-900/10',
  'ot-level1': 'border-red-600 bg-red-900/10',
  field: 'border-gray-600 bg-gray-800/20',
};

const ZONE_LABELS: Record<OTAsset['zone'], string> = {
  it: 'IT Network',
  dmz: 'IT-OT DMZ',
  'ot-level3': 'OT Level 3 (Supervisory)',
  'ot-level2': 'OT Level 2 (Control)',
  'ot-level1': 'OT Level 1 (Field Control)',
  field: 'Field Devices',
};

const STATUS_DOT: Record<OTAsset['status'], string> = {
  normal: 'bg-green-400',
  alert: 'bg-yellow-400',
  critical: 'bg-red-500 animate-pulse',
  offline: 'bg-gray-500',
};

const TYPE_ICON: Record<OTAsset['type'], string> = {
  plc: '⚙️', hmi: '🖥️', rtu: '📡', historian: '🗄️', workstation: '💻', firewall: '🔥', switch: '🔀',
};

function AssetCard({ asset, selected, onClick }: { asset: OTAsset; selected: boolean; onClick: () => void }) {
  const anomalousConn = CONNECTIONS.filter(c => (c.from === asset.id || c.to === asset.id) && c.anomalous).length;
  return (
    <button
      onClick={onClick}
      className={`w-full text-left p-2 rounded border transition-all ${
        selected ? 'border-blue-500 bg-blue-500/10' : 'border-gray-600 bg-gray-800 hover:border-gray-400'
      }`}
    >
      <div className="flex items-start gap-2">
        <span className="text-base">{TYPE_ICON[asset.type]}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full shrink-0 ${STATUS_DOT[asset.status]}`} />
            <p className="text-xs text-white truncate font-medium">{asset.name}</p>
          </div>
          <div className="flex items-center gap-1 mt-0.5 flex-wrap">
            {asset.protocol.map(p => (
              <span key={p} className="text-xs text-blue-300 bg-blue-900/30 px-1 rounded">{p}</span>
            ))}
            {asset.isEol && <span className="text-xs text-red-400 bg-red-900/20 px-1 rounded">EoL</span>}
            {anomalousConn > 0 && <span className="text-xs text-orange-400 bg-orange-900/20 px-1 rounded">{anomalousConn} anomaly</span>}
          </div>
          <p className="text-xs text-gray-500 mt-0.5">{asset.lastSeen}</p>
        </div>
      </div>
    </button>
  );
}

export function OTTopologyView() {
  const [selectedAsset, setSelectedAsset] = useState<OTAsset | null>(null);
  const criticalCount = OT_ASSETS.filter(a => a.status === 'critical').length;
  const alertCount = OT_ASSETS.filter(a => a.status === 'alert').length;
  const anomalousConns = CONNECTIONS.filter(c => c.anomalous).length;

  const zones: OTAsset['zone'][] = ['dmz', 'ot-level3', 'ot-level2', 'ot-level1'];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">OT/ICS Network Topology</h1>
        <p className="text-gray-400 text-sm mt-1">
          Purdue Model segmentation view for India power grid CNI. OT-SAFE: network DMZ segmentation only — never host isolation
          (preserves physical process control). NCIIPC notified on SAFETY_CRITICAL events.
        </p>
      </div>

      {/* KPI Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Critical Assets</p>
          <p className="text-2xl font-bold text-red-400">{criticalCount}</p>
          <p className="text-gray-500 text-xs mt-1">SAFETY_CRITICAL status</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Alert State</p>
          <p className="text-2xl font-bold text-orange-400">{alertCount}</p>
          <p className="text-gray-500 text-xs mt-1">Elevated risk</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Anomalous Flows</p>
          <p className="text-2xl font-bold text-yellow-400">{anomalousConns}</p>
          <p className="text-gray-500 text-xs mt-1">Unauthorized protocol use</p>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">Total OT Assets</p>
          <p className="text-2xl font-bold text-white">{OT_ASSETS.length}</p>
          <p className="text-gray-500 text-xs mt-1">Monitored via DPI</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Topology by Purdue Zone */}
        <div className="lg:col-span-2 space-y-3">
          {zones.map(zone => {
            const assets = OT_ASSETS.filter(a => a.zone === zone);
            if (!assets.length) return null;
            return (
              <div key={zone} className={`border rounded-lg p-3 ${ZONE_COLORS[zone]}`}>
                <p className="text-xs font-semibold text-gray-300 mb-2 uppercase tracking-wider">
                  {ZONE_LABELS[zone]}
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {assets.map(asset => (
                    <AssetCard
                      key={asset.id}
                      asset={asset}
                      selected={selectedAsset?.id === asset.id}
                      onClick={() => setSelectedAsset(selectedAsset?.id === asset.id ? null : asset)}
                    />
                  ))}
                </div>
              </div>
            );
          })}

          {/* OT-SAFE Policy */}
          <div className="bg-blue-900/10 border border-blue-700/30 rounded-lg p-3 text-xs text-blue-300">
            <p className="font-semibold mb-1">OT-SAFE Response Constraint</p>
            <p>SAFETY_CRITICAL events → apply <strong>IT-OT DMZ firewall rules only</strong>. Host isolation is forbidden on OT assets
            — it would disrupt physical process control and risk grid blackout. NCIIPC notified per IT Act §70.</p>
          </div>
        </div>

        {/* Right Panel: Asset Detail + Protocol Events */}
        <div className="space-y-4">
          {selectedAsset ? (
            <div className="bg-gray-900 border border-blue-500/30 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-white font-semibold text-sm flex items-center gap-2">
                  <span>{TYPE_ICON[selectedAsset.type]}</span>
                  Asset Detail
                </h3>
                <button onClick={() => setSelectedAsset(null)} className="text-gray-500 hover:text-gray-300 text-xs">✕</button>
              </div>
              <div className="space-y-2 text-xs">
                <div><p className="text-gray-400">Name</p><p className="text-white">{selectedAsset.name}</p></div>
                <div><p className="text-gray-400">Zone</p><p className="text-white">{ZONE_LABELS[selectedAsset.zone]}</p></div>
                <div>
                  <p className="text-gray-400">Status</p>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <div className={`w-2 h-2 rounded-full ${STATUS_DOT[selectedAsset.status]}`} />
                    <p className={`capitalize font-semibold ${
                      selectedAsset.status === 'critical' ? 'text-red-400' :
                      selectedAsset.status === 'alert' ? 'text-orange-400' :
                      'text-green-400'
                    }`}>{selectedAsset.status}</p>
                  </div>
                </div>
                <div>
                  <p className="text-gray-400">Protocols</p>
                  <div className="flex flex-wrap gap-1 mt-0.5">
                    {selectedAsset.protocol.map(p => <span key={p} className="bg-blue-900/30 text-blue-300 px-1.5 py-0.5 rounded">{p}</span>)}
                  </div>
                </div>
                {selectedAsset.vendor && <div><p className="text-gray-400">Vendor</p><p className="text-white">{selectedAsset.vendor}</p></div>}
                {selectedAsset.firmware && <div><p className="text-gray-400">Firmware</p><p className="text-white font-mono">{selectedAsset.firmware}</p></div>}
                {selectedAsset.isEol && (
                  <div className="p-2 bg-red-900/20 border border-red-700/30 rounded">
                    <p className="text-red-400 font-semibold">End-of-Life Asset</p>
                    <p className="text-red-300 mt-0.5">No security patches. CVSS amplifier ×1.4–2.5×. Replace immediately.</p>
                  </div>
                )}
                <div>
                  <p className="text-gray-400">Connections</p>
                  {CONNECTIONS.filter(c => c.from === selectedAsset.id || c.to === selectedAsset.id).map((c, i) => (
                    <div key={i} className={`flex items-center gap-1 mt-0.5 text-xs ${c.anomalous ? 'text-orange-400' : 'text-gray-300'}`}>
                      <span>{c.from === selectedAsset.id ? '→' : '←'}</span>
                      <span>{c.from === selectedAsset.id ? c.to : c.from}</span>
                      <span className="text-gray-500">({c.protocol})</span>
                      {c.anomalous && <span className="text-orange-400 font-semibold">ANOMALOUS</span>}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
              <h3 className="text-white font-semibold mb-2 text-sm">Legend</h3>
              <div className="space-y-1.5 text-xs">
                {Object.entries(STATUS_DOT).map(([status, cls]) => (
                  <div key={status} className="flex items-center gap-2">
                    <div className={`w-2.5 h-2.5 rounded-full ${cls.replace(' animate-pulse', '')}`} />
                    <span className="text-gray-300 capitalize">{status}</span>
                  </div>
                ))}
                <div className="border-t border-gray-700 pt-2 mt-2 space-y-1">
                  <p className="text-gray-400 font-medium">Zone Colors</p>
                  {zones.map(z => (
                    <div key={z} className="flex items-center gap-2">
                      <div className={`w-3 h-3 rounded border-2 ${ZONE_COLORS[z].split(' ')[0]}`} />
                      <span className="text-gray-400">{ZONE_LABELS[z]}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Protocol events */}
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <h3 className="text-white font-semibold mb-3 text-sm">Live Protocol Events</h3>
            <div className="space-y-2">
              {PROTOCOL_EVENTS.map((evt, i) => (
                <div key={i} className={`p-2 rounded border text-xs ${
                  evt.severity === 'critical' ? 'border-red-700/40 bg-red-900/10' :
                  evt.severity === 'high' ? 'border-orange-700/40 bg-orange-900/10' :
                  evt.severity === 'medium' ? 'border-yellow-700/40 bg-yellow-900/5' :
                  'border-gray-700 bg-gray-800'
                }`}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-blue-400 text-xs bg-blue-900/20 px-1 rounded">{evt.protocol}</span>
                    <span className="text-gray-500">{evt.ts}</span>
                    <span className={`ml-auto font-semibold ${
                      evt.severity === 'critical' ? 'text-red-400' :
                      evt.severity === 'high' ? 'text-orange-400' :
                      evt.severity === 'medium' ? 'text-yellow-400' : 'text-gray-400'
                    }`}>{evt.severity.toUpperCase()}</span>
                  </div>
                  <p className="text-gray-200">{evt.description}</p>
                  <p className="text-gray-500 mt-0.5 font-mono">{evt.src} → {evt.dst} · {evt.function_code}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="text-center text-xs text-gray-600 pb-2">
        Purdue ICS Reference Model · IEC 62443 · NCIIPC OT Security Guidelines · India Power Grid CNI
      </div>
    </div>
  );
}
