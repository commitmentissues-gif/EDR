import React, { useState, useEffect, useCallback } from 'react';
import { 
  Network as NetworkIcon, 
  Activity, 
  ShieldAlert, 
  Globe, 
  ArrowUpRight, 
  ArrowDownLeft, 
  Search, 
  RefreshCw, 
  Filter, 
  Cpu, 
  CheckCircle2, 
  AlertTriangle, 
  PlayCircle, 
  ExternalLink, 
  Terminal, 
  Layers, 
  Sliders, 
  Clock, 
  ShieldCheck,
  Radio
} from 'lucide-react';
import { 
  NetworkEvent, 
  NetworkAggregatedStats, 
  NetworkDetectorConfig, 
  SafeNetworkSimulationScenario 
} from '../../backend/network/types';
import { safeFetchJson } from '../utils/api';

interface NetworkViewProps {
  onNavigateTab?: (tab: string) => void;
  onSelectProcess?: (pid: number) => void;
}

export const NetworkView: React.FC<NetworkViewProps> = ({ onNavigateTab, onSelectProcess }) => {
  const [activeSubTab, setActiveSubTab] = useState<'stream' | 'processes' | 'destinations' | 'rules' | 'simulator'>('stream');
  
  // Data state
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [stats, setStats] = useState<NetworkAggregatedStats | null>(null);
  const [config, setConfig] = useState<NetworkDetectorConfig | null>(null);
  const [simulations, setSimulations] = useState<SafeNetworkSimulationScenario[]>([]);
  
  // Filtering state
  const [search, setSearch] = useState<string>('');
  const [protocolFilter, setProtocolFilter] = useState<'all' | 'TCP' | 'UDP'>('all');
  const [suspiciousOnly, setSuspiciousOnly] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  
  // Selected inspection modal
  const [selectedEvent, setSelectedEvent] = useState<NetworkEvent | null>(null);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [pidConnections, setPidConnections] = useState<{ processInfo: any; connections: NetworkEvent[] } | null>(null);

  // Simulation running state
  const [runningSimId, setRunningSimId] = useState<string | null>(null);
  const [simResult, setSimResult] = useState<any | null>(null);

  // Fetch telemetry events
  const fetchEvents = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (search) params.set('search', search);
      if (protocolFilter !== 'all') params.set('protocol', protocolFilter);
      if (suspiciousOnly) params.set('is_suspicious', 'true');
      params.set('limit', '100');

      const data = await safeFetchJson<{ events: NetworkEvent[]; total: number }>(
        `/api/network/events?${params.toString()}`,
        { events: [], total: 0 }
      );
      setEvents(data.events || []);
      setTotalEvents(data.total || 0);
    } catch (err) {
      console.warn('[NetworkView] Failed to fetch events:', err);
    } finally {
      setLoading(false);
    }
  }, [search, protocolFilter, suspiciousOnly]);

  // Fetch stats & config
  const fetchStatsAndConfig = useCallback(async () => {
    try {
      const [statsData, cfgData, simsData] = await Promise.all([
        safeFetchJson<NetworkAggregatedStats | null>('/api/network/stats', null),
        safeFetchJson<NetworkDetectorConfig | null>('/api/network/config', null),
        safeFetchJson<SafeNetworkSimulationScenario[]>('/api/network/simulations', [])
      ]);
      if (statsData) setStats(statsData);
      if (cfgData) setConfig(cfgData);
      if (simsData) setSimulations(simsData);
    } catch (err) {
      console.warn('[NetworkView] Failed to fetch stats/config:', err);
    }
  }, []);

  // Drilldown by PID
  const loadProcessConnections = async (pid: number) => {
    setSelectedPid(pid);
    try {
      const data = await safeFetchJson<{ processInfo: any; connections: NetworkEvent[] }>(
        `/api/network/process/${pid}`,
        { processInfo: null, connections: [] }
      );
      setPidConnections(data);
    } catch (err) {
      console.warn(`[NetworkView] Failed to load connections for PID ${pid}:`, err);
    }
  };

  useEffect(() => {
    fetchEvents();
    fetchStatsAndConfig();
    const interval = setInterval(() => {
      fetchEvents();
      fetchStatsAndConfig();
    }, 8000);
    return () => clearInterval(interval);
  }, [fetchEvents, fetchStatsAndConfig]);

  // Run simulation
  const handleRunSimulation = async (scenarioId: string) => {
    try {
      setRunningSimId(scenarioId);
      const res = await fetch('/api/network/simulations/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioId })
      });
      if (res.ok) {
        const data = await res.json();
        setSimResult(data);
        await fetchEvents();
        await fetchStatsAndConfig();
        if (data.event) {
          setSelectedEvent(data.event);
        }
      }
    } catch (err) {
      console.warn('Simulation execution failed:', err);
    } finally {
      setRunningSimId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <NetworkIcon className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-white tracking-tight">Lightweight Network Telemetry & Sockets</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                Connection Metadata
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                No Packet Payload
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Low-overhead socket tracking, process attribution, C2 beaconing detection, and MITRE ATT&CK correlation
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              fetchEvents();
              fetchStatsAndConfig();
            }}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab('alerts')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-xs font-mono rounded border border-rose-500/40 transition"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>View EDR Alerts</span>
            </button>
          )}
        </div>
      </div>

      {/* Metric KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>TOTAL EVENTS</span>
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white font-mono">{stats?.totalEvents ?? totalEvents}</div>
          <div className="text-[11px] text-slate-500 mt-1">Stored in SQLite WAL</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>ACTIVE SOCKETS</span>
            <Radio className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-emerald-400 font-mono">{stats?.activeConnectionsCount ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">ESTABLISHED / LISTENING</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>SUSPICIOUS</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold text-rose-400 font-mono">{stats?.suspiciousCount ?? 0}</div>
          <div className="text-[11px] text-rose-500/80 mt-1">Flagged for SOC review</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>DIRECTION</span>
            <ArrowUpRight className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <div className="text-base font-bold text-slate-200 font-mono">
            {stats?.outboundCount ?? 0} <span className="text-xs text-slate-400 font-normal">out</span> / {stats?.inboundCount ?? 0} <span className="text-xs text-slate-400 font-normal">in</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Outbound vs Inbound</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>PROCESSES</span>
            <Cpu className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold text-amber-400 font-mono">{stats?.uniqueProcessesCount ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Unique binaries</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>DESTINATIONS</span>
            <Globe className="w-3.5 h-3.5 text-teal-400" />
          </div>
          <div className="text-xl font-bold text-teal-400 font-mono">{stats?.uniqueDestinationsCount ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Unique remote IPs</div>
        </div>
      </div>

      {/* Sub Navigation Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-1.5 overflow-x-auto">
          {[
            { id: 'stream', label: 'Connection Stream', icon: Activity, count: totalEvents },
            { id: 'processes', label: 'Process Attribution', icon: Cpu, count: stats?.uniqueProcessesCount },
            { id: 'destinations', label: 'Destinations & Ports', icon: Globe },
            { id: 'rules', label: 'Detection Rules & Config', icon: Sliders },
            { id: 'simulator', label: 'Safe Simulator', icon: PlayCircle, badge: 'Tests' }
          ].map(tab => {
            const Icon = tab.icon;
            const active = activeSubTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveSubTab(tab.id as any)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono transition ${
                  active
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span className={`text-[10px] px-1.5 py-0.2 rounded ${active ? 'bg-cyan-900/60 text-cyan-200' : 'bg-slate-800 text-slate-400'}`}>
                    {tab.count}
                  </span>
                )}
                {tab.badge && (
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Stream Search & Filters */}
        {activeSubTab === 'stream' && (
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search IP, domain, process..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="pl-8 pr-3 py-1 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 w-48 sm:w-60"
              />
            </div>

            <select
              value={protocolFilter}
              onChange={e => setProtocolFilter(e.target.value as any)}
              className="px-2 py-1 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">Protocol: All</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
            </select>

            <button
              onClick={() => setSuspiciousOnly(!suspiciousOnly)}
              className={`flex items-center gap-1 px-2.5 py-1 text-xs font-mono rounded border transition ${
                suspiciousOnly
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              <AlertTriangle className="w-3 h-3" />
              <span>Suspicious Only</span>
            </button>
          </div>
        )}
      </div>

      {/* SUBTAB 1: Live Connection Stream */}
      {activeSubTab === 'stream' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-4 py-3 bg-slate-950/60 border-b border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="font-semibold text-slate-200">Network Sockets & Connection Metadata Stream</span>
              <span>({events.length} shown)</span>
            </div>
            <span className="text-[11px] text-slate-500">Click any row to inspect connection & process lineage</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">TIMESTAMP</th>
                  <th className="py-2.5 px-3">PROCESS / PID</th>
                  <th className="py-2.5 px-3">DIRECTION</th>
                  <th className="py-2.5 px-3">SOURCE</th>
                  <th className="py-2.5 px-3">DESTINATION</th>
                  <th className="py-2.5 px-3">PROTO / STATE</th>
                  <th className="py-2.5 px-3">DOMAIN</th>
                  <th className="py-2.5 px-3">STATUS & TAGS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-slate-500">
                      No network events match the current filter.
                    </td>
                  </tr>
                ) : (
                  events.map(ev => {
                    const isSusp = ev.is_suspicious;
                    return (
                      <tr
                        key={ev.event_uuid || ev.id}
                        onClick={() => setSelectedEvent(ev)}
                        className={`hover:bg-slate-800/50 cursor-pointer transition ${
                          isSusp ? 'bg-rose-950/20 border-l-2 border-rose-500' : ''
                        }`}
                      >
                        <td className="py-2 px-3 text-slate-400 whitespace-nowrap">
                          {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A'}
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <span className="font-semibold text-white">{ev.process_name}</span>
                            <span className="text-slate-400 text-[10px]">[{ev.pid}]</span>
                          </div>
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <span
                            className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] ${
                              ev.direction === 'outbound'
                                ? 'bg-indigo-950/60 text-indigo-400 border border-indigo-800/40'
                                : 'bg-teal-950/60 text-teal-400 border border-teal-800/40'
                            }`}
                          >
                            {ev.direction === 'outbound' ? <ArrowUpRight className="w-2.5 h-2.5" /> : <ArrowDownLeft className="w-2.5 h-2.5" />}
                            {ev.direction}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-slate-300 whitespace-nowrap">
                          {ev.source_ip}:{ev.source_port}
                        </td>
                        <td className="py-2 px-3 text-slate-200 whitespace-nowrap">
                          <span className={isSusp ? 'text-rose-300 font-bold' : 'text-slate-200'}>
                            {ev.destination_ip}:{ev.destination_port}
                          </span>
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <div className="flex items-center gap-1">
                            <span className="text-cyan-400 font-semibold">{ev.protocol}</span>
                            <span className="text-[10px] text-slate-400">({ev.connection_state})</span>
                          </div>
                        </td>
                        <td className="py-2 px-3 text-slate-300 max-w-[180px] truncate" title={ev.domain}>
                          {ev.domain || <span className="text-slate-600">—</span>}
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          {isSusp ? (
                            <div className="flex items-center gap-1 flex-wrap">
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold flex items-center gap-1">
                                <AlertTriangle className="w-2.5 h-2.5" />
                                {ev.risk_score}/100
                              </span>
                              {ev.detection_tags && ev.detection_tags.slice(0, 1).map(tag => (
                                <span key={tag} className="text-[9px] px-1 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-800">
                                  {tag}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3" /> Clean
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUBTAB 2: Process Attribution & Associations */}
      {activeSubTab === 'processes' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Process List */}
          <div className="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-4">
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2 mb-3">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Processes with Network Sockets</span>
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Select a process to inspect all active/historical network connections associated with its PID.
            </p>

            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
              {stats?.topProcesses && stats.topProcesses.length > 0 ? (
                stats.topProcesses.map(p => {
                  const isSelected = selectedPid === p.pid;
                  return (
                    <button
                      key={`${p.process_name}-${p.pid}`}
                      onClick={() => loadProcessConnections(p.pid)}
                      className={`w-full text-left p-2.5 rounded-lg border font-mono text-xs transition flex items-center justify-between ${
                        isSelected
                          ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-200'
                          : 'bg-slate-950/80 border-slate-800 text-slate-300 hover:bg-slate-800/60'
                      }`}
                    >
                      <div>
                        <div className="font-semibold text-white flex items-center gap-1.5">
                          <span>{p.process_name}</span>
                          <span className="text-[10px] text-slate-400">PID {p.pid}</span>
                        </div>
                        <div className="text-[10px] text-slate-500 mt-0.5">
                          {p.connectionCount} connection{p.connectionCount > 1 ? 's' : ''} recorded
                        </div>
                      </div>
                      {p.isSuspicious ? (
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/40">
                          Suspicious
                        </span>
                      ) : (
                        <span className="text-[10px] text-emerald-400 flex items-center gap-0.5">
                          <CheckCircle2 className="w-3 h-3" /> Clean
                        </span>
                      )}
                    </button>
                  );
                })
              ) : (
                <div className="text-xs text-slate-500 text-center py-6">No process network associations recorded.</div>
              )}
            </div>
          </div>

          {/* Process Connection Drilldown */}
          <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-4">
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2 mb-3">
              <NetworkIcon className="w-4 h-4 text-emerald-400" />
              <span>Process Network Correlation Drilldown</span>
            </h3>

            {selectedPid && pidConnections ? (
              <div className="space-y-4 font-mono">
                {/* Process Details Card */}
                <div className="bg-slate-950 border border-slate-800 p-3.5 rounded-lg text-xs">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2 mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white text-sm">
                        {pidConnections.processInfo?.process_name || 'Selected PID'}
                      </span>
                      <span className="text-slate-400">PID: {selectedPid}</span>
                      {pidConnections.processInfo?.parent_pid > 0 && (
                        <span className="text-slate-500">Parent PID: {pidConnections.processInfo.parent_pid}</span>
                      )}
                    </div>
                    {onSelectProcess && pidConnections.processInfo && (
                      <button
                        onClick={() => onSelectProcess(selectedPid)}
                        className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1"
                      >
                        <span>View in Process Monitor</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-400 text-[11px]">
                    <div>Executable: <span className="text-slate-300 break-all">{pidConnections.processInfo?.executable_path || 'N/A'}</span></div>
                    <div>User Context: <span className="text-slate-300">{pidConnections.processInfo?.username || 'SYSTEM'}</span></div>
                    <div>Signature: <span className="text-slate-300">{pidConnections.processInfo?.signature_status || 'Unknown'}</span></div>
                    <div>Total Sockets: <span className="text-cyan-400 font-bold">{pidConnections.connections.length}</span></div>
                  </div>
                </div>

                {/* Connection History Table */}
                <div className="overflow-x-auto border border-slate-800 rounded-lg">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950 text-slate-400">
                      <tr>
                        <th className="p-2">TIMESTAMP</th>
                        <th className="p-2">DESTINATION</th>
                        <th className="p-2">DOMAIN</th>
                        <th className="p-2">PROTO/STATE</th>
                        <th className="p-2">RISK</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {pidConnections.connections.map(c => (
                        <tr
                          key={c.event_uuid || c.id}
                          onClick={() => setSelectedEvent(c)}
                          className="hover:bg-slate-800/50 cursor-pointer"
                        >
                          <td className="p-2 text-slate-400 whitespace-nowrap">{new Date(c.timestamp).toLocaleTimeString()}</td>
                          <td className="p-2 text-slate-200 whitespace-nowrap">{c.destination_ip}:{c.destination_port}</td>
                          <td className="p-2 text-slate-300 max-w-[150px] truncate">{c.domain || '—'}</td>
                          <td className="p-2 text-cyan-400 whitespace-nowrap">{c.protocol} ({c.connection_state})</td>
                          <td className="p-2 whitespace-nowrap">
                            {c.is_suspicious ? (
                              <span className="text-rose-400 font-bold text-[10px] bg-rose-500/20 px-1.5 py-0.5 rounded border border-rose-500/30">
                                {c.risk_score} / 100
                              </span>
                            ) : (
                              <span className="text-emerald-400 text-[10px]">Clean</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="py-16 text-center text-slate-500 font-mono text-xs">
                Select a process from the list on the left to inspect its connection metadata and lineage.
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUBTAB 3: Top Destinations & Port Analysis */}
      {activeSubTab === 'destinations' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Top Destinations */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2 mb-3">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span>Top Destination Remote IPs & Domains</span>
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Remote endpoints accessed by host processes, with threat intelligence correlation flags.
            </p>

            <div className="space-y-2">
              {stats?.topDestinations && stats.topDestinations.length > 0 ? (
                stats.topDestinations.map(d => (
                  <div
                    key={d.ip}
                    className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white">{d.ip}</span>
                        {d.isSuspicious && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                            Threat Alert
                          </span>
                        )}
                      </div>
                      {d.domain && <div className="text-[11px] text-slate-400 mt-0.5">{d.domain}</div>}
                    </div>
                    <div className="text-right">
                      <span className="text-cyan-400 font-bold">{d.count}</span>
                      <span className="text-slate-500 text-[10px] block">connections</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 text-center py-6">No external destinations recorded.</div>
              )}
            </div>
          </div>

          {/* Port Distribution & Common vs Uncommon */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2 mb-3">
              <Activity className="w-4 h-4 text-indigo-400" />
              <span>Destination Ports & Service Classification</span>
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Analysis of destination ports. Flags uncommon or dangerous ports (e.g. 4444, 1337, 6667) vs standard TLS/DNS.
            </p>

            <div className="space-y-2">
              {stats?.topPorts && stats.topPorts.length > 0 ? (
                stats.topPorts.map(p => (
                  <div
                    key={p.port}
                    className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white">Port {p.port}</span>
                        <span className="text-slate-400">({p.serviceName})</span>
                        {!p.isCommon && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            Uncommon Port
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="text-right">
                      <span className="text-indigo-400 font-bold">{p.count}</span>
                      <span className="text-slate-500 text-[10px] block">occurrences</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 text-center py-6">No port telemetry recorded.</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 4: Detection Rules & Config */}
      {activeSubTab === 'rules' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-6 font-mono text-xs">
          <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <span>Contextual Network Detection Rules & Mitigations</span>
              </h3>
              <p className="text-slate-400 mt-1">
                Lightweight behavioral heuristics mapped to MITRE ATT&CK for detecting suspicious socket activity.
              </p>
            </div>
            <span className="px-2 py-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px]">
              Detector Active
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white">1. Known Malicious IP / C2</span>
                <span className="text-rose-400 text-[10px] font-bold">CRITICAL (95)</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Checks destination IP against SQLite threat intelligence IoCs and embedded high-confidence C2 lists.
              </p>
              <div className="text-[10px] text-cyan-400">MITRE: [T1071 Application Layer Protocol]</div>
            </div>

            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white">2. Suspicious Destination & TLD</span>
                <span className="text-amber-400 text-[10px] font-bold">HIGH (80)</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Flags high-abuse TLDs (.xyz, .top, .ru, .onion) and dynamic DNS/tunneling domains (duckdns, ngrok).
              </p>
              <div className="text-[10px] text-cyan-400">MITRE: [T1071.001 Web Protocols]</div>
            </div>

            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white">3. Unusual Outbound Connection</span>
                <span className="text-rose-400 text-[10px] font-bold">CRITICAL (90)</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Detects core Windows processes (notepad.exe, calc.exe, lsass.exe, spoolsv.exe) opening sockets to internet hosts.
              </p>
              <div className="text-[10px] text-cyan-400">MITRE: [T1071 Application Layer Protocol]</div>
            </div>

            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white">4. Suspicious Process Network</span>
                <span className="text-rose-400 text-[10px] font-bold">HIGH (85)</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Flags Microsoft Office binaries (winword.exe, excel.exe) and LOLBins (cmd, powershell, certutil) connecting outbound.
              </p>
              <div className="text-[10px] text-cyan-400">MITRE: [T1204.002 Malicious File / T1105 Ingress]</div>
            </div>

            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white">5. Repeated Connection Patterns</span>
                <span className="text-amber-400 text-[10px] font-bold">HIGH (85)</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Detects periodic C2 beaconing with low jitter variance (&lt; 20%) over rolling time windows.
              </p>
              <div className="text-[10px] text-cyan-400">MITRE: [T1071 Application Layer Protocol]</div>
            </div>

            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white">6. Uncommon / Suspicious Ports</span>
                <span className="text-amber-400 text-[10px] font-bold">HIGH (75)</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Flags connections destined for non-standard ports: 4444 (Metasploit), 1337, 6667 (IRC), 31337, 9001 (Tor).
              </p>
              <div className="text-[10px] text-cyan-400">MITRE: [T1571 Non-Standard Port]</div>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 5: Safe Network Simulator */}
      {activeSubTab === 'simulator' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                <PlayCircle className="w-4 h-4 text-emerald-400" />
                <span>Safe Network Telemetry Simulator & Verifier</span>
              </h3>
              <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950 border border-emerald-800 px-2 py-0.5 rounded">
                Benign & Detection Tests
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Execute pre-configured network traffic scenarios to verify detection accuracy, false positive immunity, and EDR alerting.
            </p>
          </div>

          {/* Last Simulation Result Callout */}
          {simResult && (
            <div
              className={`p-4 rounded-xl border font-mono text-xs ${
                simResult.success
                  ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200'
                  : 'bg-rose-950/30 border-rose-500/40 text-rose-200'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2 font-bold">
                  {simResult.success ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-rose-400" />}
                  <span>{simResult.scenario.name}</span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 border border-slate-700">
                  {simResult.message}
                </span>
              </div>
              <div className="text-slate-300 text-[11px] space-y-1">
                <div>Connection: {simResult.event.process_name} (PID: {simResult.event.pid}) -&gt; {simResult.event.destination_ip}:{simResult.event.destination_port}</div>
                <div>Alert Generated: <span className={simResult.detectedAlert ? 'text-rose-400 font-bold' : 'text-emerald-400'}>{String(simResult.detectedAlert)}</span> (Expected: {String(simResult.scenario.expectedAlert)})</div>
                {simResult.event.detection_tags && simResult.event.detection_tags.length > 0 && (
                  <div>Tags: [{simResult.event.detection_tags.join(', ')}] • Risk Score: {simResult.event.risk_score}/100</div>
                )}
              </div>
            </div>
          )}

          {/* Scenario Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {simulations.map(sim => {
              const isMalicious = sim.category === 'malicious_detection';
              const isRunning = runningSimId === sim.id;

              return (
                <div
                  key={sim.id}
                  className={`bg-slate-900 border rounded-xl p-4 flex flex-col justify-between transition ${
                    isMalicious ? 'border-slate-800 hover:border-rose-500/40' : 'border-slate-800 hover:border-emerald-500/40'
                  }`}
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-bold text-white text-xs font-mono">{sim.name}</span>
                      <span
                        className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase ${
                          isMalicious
                            ? 'bg-rose-950 text-rose-300 border-rose-800'
                            : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                        }`}
                      >
                        {isMalicious ? 'Expects Alert' : 'Clean / Benign'}
                      </span>
                    </div>

                    <p className="text-slate-400 text-xs">{sim.description}</p>

                    <div className="bg-slate-950 p-2.5 rounded border border-slate-850 font-mono text-[11px] text-slate-300 space-y-0.5">
                      <div>Process: <span className="text-cyan-400">{sim.process_name}</span> [PID: {sim.pid}]</div>
                      <div>Target: <span className="text-white">{sim.destination_ip}:{sim.destination_port}</span> ({sim.protocol})</div>
                      {sim.domain && <div>Domain: <span className="text-amber-400">{sim.domain}</span></div>}
                    </div>

                    <p className="text-[11px] text-slate-500 italic">{sim.explanation}</p>
                  </div>

                  <div className="pt-4 mt-2 border-t border-slate-800/80 flex items-center justify-between">
                    <span className="text-[10px] text-slate-500 font-mono">ID: {sim.id}</span>
                    <button
                      onClick={() => handleRunSimulation(sim.id)}
                      disabled={isRunning}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono transition ${
                        isMalicious
                          ? 'bg-rose-600 hover:bg-rose-500 text-white'
                          : 'bg-emerald-600 hover:bg-emerald-500 text-white'
                      }`}
                    >
                      <PlayCircle className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin' : ''}`} />
                      <span>{isRunning ? 'Executing...' : 'Run Simulation'}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Selected Event Details Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-5 font-mono text-xs space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <NetworkIcon className="w-5 h-5 text-cyan-400" />
                <div>
                  <h3 className="font-bold text-white text-sm">Connection Metadata Details</h3>
                  <span className="text-[11px] text-slate-500">{selectedEvent.event_uuid}</span>
                </div>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white px-2 py-1 bg-slate-800 rounded"
              >
                Close
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800">
              <div><span className="text-slate-500">Process Name:</span> <span className="text-white font-bold">{selectedEvent.process_name}</span></div>
              <div><span className="text-slate-500">Process ID:</span> <span className="text-white">{selectedEvent.pid}</span></div>
              <div><span className="text-slate-500">Parent Process:</span> <span className="text-slate-300">{selectedEvent.parent_process_name || 'N/A'}</span></div>
              <div><span className="text-slate-500">Direction:</span> <span className="text-slate-300">{selectedEvent.direction}</span></div>
              <div><span className="text-slate-500">Source:</span> <span className="text-slate-300">{selectedEvent.source_ip}:{selectedEvent.source_port}</span></div>
              <div><span className="text-slate-500">Destination:</span> <span className="text-cyan-400 font-bold">{selectedEvent.destination_ip}:{selectedEvent.destination_port}</span></div>
              <div><span className="text-slate-500">Protocol:</span> <span className="text-slate-300">{selectedEvent.protocol}</span></div>
              <div><span className="text-slate-500">Connection State:</span> <span className="text-slate-300">{selectedEvent.connection_state}</span></div>
              <div><span className="text-slate-500">Domain:</span> <span className="text-amber-400">{selectedEvent.domain || 'N/A'}</span></div>
              <div><span className="text-slate-500">Bytes Transferred:</span> <span className="text-slate-300">↑ {selectedEvent.bytes_sent} B / ↓ {selectedEvent.bytes_received} B</span></div>
            </div>

            {selectedEvent.is_suspicious ? (
              <div className="bg-rose-950/40 border border-rose-500/40 p-3 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-rose-300 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    Suspicious Network Detection
                  </span>
                  <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold">
                    Risk Score: {selectedEvent.risk_score} / 100
                  </span>
                </div>
                {selectedEvent.detection_tags && (
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-slate-400">Detection Tags:</span>
                    {selectedEvent.detection_tags.map(t => (
                      <span key={t} className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-200 border border-rose-800 text-[10px]">
                        {t}
                      </span>
                    ))}
                  </div>
                )}
                {selectedEvent.detection_reasons && selectedEvent.detection_reasons.length > 0 && (
                  <div className="space-y-1 pt-1 border-t border-rose-900/50">
                    <span className="text-slate-400 block">Analysis Reasons:</span>
                    {selectedEvent.detection_reasons.map((r, i) => (
                      <div key={i} className="text-slate-300 text-[11px]">• {r}</div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="bg-emerald-950/40 border border-emerald-500/40 p-3 rounded-lg flex items-center gap-2 text-emerald-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>Clean baseline traffic. No known malicious indicators or suspicious behavioral patterns detected.</span>
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-2">
              {onNavigateTab && selectedEvent.is_suspicious && (
                <button
                  onClick={() => {
                    setSelectedEvent(null);
                    onNavigateTab('alerts');
                  }}
                  className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded transition"
                >
                  View in Alerts Investigation
                </button>
              )}
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
