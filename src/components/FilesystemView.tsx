import React, { useState, useEffect, useCallback } from 'react';
import { 
  FolderSync, 
  Activity, 
  ShieldAlert, 
  Search, 
  RefreshCw, 
  Filter, 
  Cpu, 
  CheckCircle2, 
  AlertTriangle, 
  PlayCircle, 
  ExternalLink, 
  Terminal, 
  Sliders, 
  Clock, 
  FileText, 
  FileCode, 
  FileCheck, 
  Binary, 
  Hash, 
  Eye, 
  Layers, 
  Folder, 
  FolderLock,
  ArrowRight
} from 'lucide-react';
import { 
  FileEvent, 
  FileAggregatedStats, 
  SecurityLocationDef, 
  SafeFileSimulationScenario, 
  IncidentTimelineItem 
} from '../../backend/filesystem/types';
import { safeFetchJson } from '../utils/api';

interface FilesystemViewProps {
  onNavigateTab?: (tab: string) => void;
  onSelectProcess?: (pid: number) => void;
}

export const FilesystemView: React.FC<FilesystemViewProps> = ({ onNavigateTab, onSelectProcess }) => {
  const [activeSubTab, setActiveSubTab] = useState<'stream' | 'locations' | 'timeline' | 'scanner' | 'simulator'>('stream');
  
  // Data state
  const [events, setEvents] = useState<FileEvent[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [stats, setStats] = useState<FileAggregatedStats | null>(null);
  const [locations, setLocations] = useState<SecurityLocationDef[]>([]);
  const [simulations, setSimulations] = useState<SafeFileSimulationScenario[]>([]);
  const [timeline, setTimeline] = useState<IncidentTimelineItem[]>([]);
  
  // Filtering state
  const [search, setSearch] = useState<string>('');
  const [actionFilter, setActionFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [locationFilter, setLocationFilter] = useState<string>('all');
  const [suspiciousOnly, setSuspiciousOnly] = useState<boolean>(false);
  const [hasHashOnly, setHasHashOnly] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);

  // Manual Hash Scanner State
  const [scanPath, setScanPath] = useState<string>('C:\\Windows\\System32\\calc.exe');
  const [scanLoading, setScanLoading] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<any | null>(null);

  // Inspection modal
  const [selectedEvent, setSelectedEvent] = useState<FileEvent | null>(null);

  // Simulation execution state
  const [runningSimId, setRunningSimId] = useState<string | null>(null);
  const [simResult, setSimResult] = useState<any | null>(null);

  const fetchEvents = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (search) params.set('search', search);
      if (actionFilter !== 'all') params.set('action', actionFilter);
      if (categoryFilter !== 'all') params.set('category', categoryFilter);
      if (locationFilter !== 'all') params.set('location', locationFilter);
      if (suspiciousOnly) params.set('is_suspicious', 'true');
      if (hasHashOnly) params.set('has_hash', 'true');
      params.set('limit', '100');

      const data = await safeFetchJson<{ events: FileEvent[]; total: number }>(
        `/api/filesystem/events?${params.toString()}`,
        { events: [], total: 0 }
      );
      setEvents(data.events || []);
      setTotalEvents(data.total || 0);
    } catch (err) {
      console.warn('[FilesystemView] Failed to fetch events:', err);
    } finally {
      setLoading(false);
    }
  }, [search, actionFilter, categoryFilter, locationFilter, suspiciousOnly, hasHashOnly]);

  const fetchMetadata = useCallback(async () => {
    try {
      const [statsData, locData, simData, timeData] = await Promise.all([
        safeFetchJson<FileAggregatedStats | null>('/api/filesystem/stats', null),
        safeFetchJson<SecurityLocationDef[]>('/api/filesystem/locations', []),
        safeFetchJson<SafeFileSimulationScenario[]>('/api/filesystem/simulations', []),
        safeFetchJson<IncidentTimelineItem[]>('/api/filesystem/timeline', [])
      ]);
      if (statsData) setStats(statsData);
      if (locData) setLocations(locData);
      if (simData) setSimulations(simData);
      if (timeData) setTimeline(timeData);
    } catch (err) {
      console.warn('[FilesystemView] Failed to fetch metadata:', err);
    }
  }, []);

  useEffect(() => {
    fetchEvents();
    fetchMetadata();
    const interval = setInterval(() => {
      fetchEvents();
      fetchMetadata();
    }, 8000);
    return () => clearInterval(interval);
  }, [fetchEvents, fetchMetadata]);

  // Request selective file hash
  const handleRequestHash = async () => {
    if (!scanPath.trim()) return;
    try {
      setScanLoading(true);
      const res = await fetch('/api/filesystem/hash-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filePath: scanPath.trim() })
      });
      if (res.ok) {
        const data = await res.json();
        setScanResult(data);
        await fetchEvents();
        await fetchMetadata();
      }
    } catch (err) {
      console.warn('Manual hash scan failed:', err);
    } finally {
      setScanLoading(false);
    }
  };

  // Run simulation
  const handleRunSimulation = async (scenarioId: string) => {
    try {
      setRunningSimId(scenarioId);
      const res = await fetch('/api/filesystem/simulations/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioId })
      });
      if (res.ok) {
        const data = await res.json();
        setSimResult(data);
        await fetchEvents();
        await fetchMetadata();
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
      {/* Top Banner & Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <FolderSync className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-white tracking-tight">Event-Driven Filesystem Monitoring</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                Targeted Security Locations
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                Selective Hashing Only
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Zero continuous full-disk scans. Real-time telemetry for Startup, Temp, Downloads, System32, and Persistence locations.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              fetchEvents();
              fetchMetadata();
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
              <span>View Alerts</span>
            </button>
          )}
        </div>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>FILE EVENTS</span>
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white font-mono">{stats?.totalEvents ?? totalEvents}</div>
          <div className="text-[11px] text-slate-500 mt-1">SQLite Indexed</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>EXECUTABLES</span>
            <Binary className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-emerald-400 font-mono">{stats?.executablesCreatedCount ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">.exe / .scr created</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>DLLs DROPPED</span>
            <FileCode className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <div className="text-xl font-bold text-indigo-400 font-mono">{stats?.dllsCreatedCount ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Dynamic libraries</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>SCRIPTS</span>
            <Terminal className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold text-amber-400 font-mono">{stats?.scriptsCreatedCount ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">.ps1, .vbs, .bat</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>SELECTIVE HASHES</span>
            <Hash className="w-3.5 h-3.5 text-teal-400" />
          </div>
          <div className="text-xl font-bold text-teal-400 font-mono">{stats?.hashesCalculatedCount ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Targeted SHA-256 only</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>SUSPICIOUS</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold text-rose-400 font-mono">{stats?.suspiciousCount ?? 0}</div>
          <div className="text-[11px] text-rose-500/80 mt-1">MITRE ATT&CK flags</div>
        </div>
      </div>

      {/* Sub Navigation Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-1.5 overflow-x-auto">
          {[
            { id: 'stream', label: 'File Activity Stream', icon: Activity, count: totalEvents },
            { id: 'locations', label: 'Monitored Security Locations', icon: FolderLock },
            { id: 'timeline', label: 'Incident Timeline', icon: Clock, count: timeline.length },
            { id: 'scanner', label: 'Selective Hash Scanner', icon: Hash },
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
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span className={`text-[10px] px-1.5 py-0.2 rounded ${active ? 'bg-emerald-900/60 text-emerald-200' : 'bg-slate-800 text-slate-400'}`}>
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
                placeholder="Search file path, process, hash..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="pl-8 pr-3 py-1 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500 w-44 sm:w-56"
              />
            </div>

            <select
              value={actionFilter}
              onChange={e => setActionFilter(e.target.value)}
              className="px-2 py-1 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-300 focus:outline-none focus:border-emerald-500"
            >
              <option value="all">Action: All</option>
              <option value="create">create</option>
              <option value="modify">modify</option>
              <option value="delete">delete</option>
              <option value="rename">rename</option>
            </select>

            <select
              value={categoryFilter}
              onChange={e => setCategoryFilter(e.target.value)}
              className="px-2 py-1 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-300 focus:outline-none focus:border-emerald-500"
            >
              <option value="all">Category: All</option>
              <option value="executable">executable (.exe)</option>
              <option value="dll">dll (.dll)</option>
              <option value="script">script (.ps1/.bat)</option>
              <option value="document">document</option>
            </select>

            <select
              value={locationFilter}
              onChange={e => setLocationFilter(e.target.value)}
              className="px-2 py-1 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-300 focus:outline-none focus:border-emerald-500"
            >
              <option value="all">Location: All</option>
              <option value="startup">Startup</option>
              <option value="temp">Temp</option>
              <option value="downloads">Downloads</option>
              <option value="system32">System32</option>
              <option value="persistence">Persistence</option>
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
              <span>Suspicious</span>
            </button>
          </div>
        )}
      </div>

      {/* SUBTAB 1: Live File Activity Stream */}
      {activeSubTab === 'stream' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden font-mono">
          <div className="px-4 py-3 bg-slate-950/60 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span className="font-semibold text-slate-200">Event-Driven Filesystem Activity Log</span>
              <span>({events.length} shown)</span>
            </div>
            <span className="text-[11px] text-slate-500">Selective hash calculation active for executed/suspicious files</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">TIMESTAMP</th>
                  <th className="py-2.5 px-3">ACTION</th>
                  <th className="py-2.5 px-3">LOCATION</th>
                  <th className="py-2.5 px-3">FILE NAME &amp; PATH</th>
                  <th className="py-2.5 px-3">CATEGORY</th>
                  <th className="py-2.5 px-3">PROCESS / PID</th>
                  <th className="py-2.5 px-3">HASH (SHA-256)</th>
                  <th className="py-2.5 px-3">DETECTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-slate-500">
                      No filesystem events match current filter.
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
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-bold ${
                              ev.action === 'create'
                                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                : ev.action === 'modify'
                                ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                                : ev.action === 'delete'
                                ? 'bg-rose-950 text-rose-400 border border-rose-800'
                                : 'bg-indigo-950 text-indigo-400 border border-indigo-800'
                            }`}
                          >
                            {ev.action}
                          </span>
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                            {ev.security_location}
                          </span>
                        </td>
                        <td className="py-2 px-3 max-w-[220px] truncate" title={ev.file_path}>
                          <span className="font-semibold text-white block">{ev.file_name}</span>
                          <span className="text-[10px] text-slate-500 truncate block">{ev.file_path}</span>
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <span className="text-slate-300">{ev.file_category}</span>
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <div className="flex items-center gap-1">
                            <span className="text-white">{ev.process_name || 'system'}</span>
                            <span className="text-slate-500 text-[10px]">[{ev.pid || 0}]</span>
                          </div>
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap max-w-[120px] truncate">
                          {ev.hash_calculated && ev.file_hash ? (
                            <span className="text-teal-400 text-[10px] flex items-center gap-1 font-mono" title={ev.file_hash}>
                              <Hash className="w-2.5 h-2.5 shrink-0" />
                              {ev.file_hash.substring(0, 10)}...
                            </span>
                          ) : (
                            <span className="text-slate-600 text-[10px]">Selective (skipped)</span>
                          )}
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          {isSusp ? (
                            <div className="flex items-center gap-1">
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold flex items-center gap-1">
                                <AlertTriangle className="w-2.5 h-2.5" />
                                {ev.risk_score}
                              </span>
                              {ev.detection_tags && ev.detection_tags[0] && (
                                <span className="text-[9px] px-1 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-800">
                                  {ev.detection_tags[0]}
                                </span>
                              )}
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

      {/* SUBTAB 2: Monitored Security Locations */}
      {activeSubTab === 'locations' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 font-mono text-xs">
            <h3 className="font-bold text-white text-sm flex items-center gap-2 mb-2">
              <FolderLock className="w-4 h-4 text-emerald-400" />
              <span>Targeted Security-Relevant Monitored Locations</span>
            </h3>
            <p className="text-slate-400 text-xs">
              Strictly focused on high-risk persistence, staging, and system integrity directories to avoid unnecessary disk I/O and excessive resource utilization.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
            {locations.map(loc => {
              const locationStat = stats?.topSecurityLocations.find(s => s.location === loc.type);
              return (
                <div key={loc.id} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3 flex flex-col justify-between">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white text-sm">{loc.name}</span>
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-950 text-emerald-400 border border-emerald-800">
                        Weight: {loc.riskWeight}
                      </span>
                    </div>

                    <p className="text-slate-400 text-xs">{loc.description}</p>

                    <div className="bg-slate-950 p-2.5 rounded border border-slate-850 space-y-1">
                      <span className="text-[10px] text-slate-500 block uppercase">Watched Path Patterns:</span>
                      {loc.patterns.map((p, i) => (
                        <div key={i} className="text-slate-300 text-[11px] truncate">• {p}</div>
                      ))}
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-[11px]">
                    <span className="text-slate-400">Total Events: <b className="text-white">{locationStat?.count ?? 0}</b></span>
                    <span className="text-slate-400">Suspicious: <b className="text-rose-400">{locationStat?.suspiciousCount ?? 0}</b></span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SUBTAB 3: Incident Timeline with File Activity */}
      {activeSubTab === 'timeline' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 font-mono text-xs space-y-4">
          <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
            <div>
              <h3 className="font-bold text-white text-sm flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                <span>Unified Incident Timeline (File, Alert, Process &amp; Network Events)</span>
              </h3>
              <p className="text-slate-400 mt-1">
                Correlates file drops, process creations, and network callbacks sequentially around detection triggers.
              </p>
            </div>
            <span className="text-[10px] px-2 py-1 rounded bg-slate-950 text-cyan-300 border border-slate-800">
              {timeline.length} timeline milestones
            </span>
          </div>

          <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
            {timeline.length === 0 ? (
              <div className="py-8 text-center text-slate-500">No incident timeline activity recorded yet.</div>
            ) : (
              timeline.map(item => {
                const isAlert = item.type === 'ALERT';
                const isFile = item.type === 'FILE';
                const isNet = item.type === 'NETWORK';

                return (
                  <div key={item.id} className="relative group">
                    {/* Timeline Node Dot */}
                    <div
                      className={`absolute -left-[27px] top-1.5 w-3.5 h-3.5 rounded-full border-2 ${
                        isAlert
                          ? 'bg-rose-500 border-slate-950 ring-2 ring-rose-500/40'
                          : isFile
                          ? 'bg-emerald-400 border-slate-950 ring-2 ring-emerald-400/40'
                          : 'bg-cyan-400 border-slate-950 ring-2 ring-cyan-400/40'
                      }`}
                    />

                    <div className="bg-slate-950 border border-slate-800 hover:border-slate-700 p-3 rounded-lg transition space-y-1.5">
                      <div className="flex items-center justify-between text-[11px]">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-1.5 py-0.2 rounded text-[9px] uppercase font-bold ${
                              isAlert
                                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                : isFile
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                            }`}
                          >
                            {item.type}
                          </span>
                          <span className="font-bold text-white text-xs">{item.title}</span>
                          {item.mitre_technique_id && (
                            <span className="text-[10px] text-cyan-400">[{item.mitre_technique_id}]</span>
                          )}
                        </div>
                        <span className="text-slate-500 text-[10px]">{new Date(item.timestamp).toLocaleTimeString()}</span>
                      </div>

                      <p className="text-slate-300 text-xs leading-relaxed">{item.description}</p>

                      {item.file_hash && (
                        <div className="text-[10px] text-teal-400 font-mono truncate">
                          SHA256: {item.file_hash}
                        </div>
                      )}

                      {item.tags && item.tags.length > 0 && (
                        <div className="flex items-center gap-1 pt-1 flex-wrap">
                          {item.tags.map((t, idx) => (
                            <span key={idx} className="text-[9px] px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 border border-slate-800">
                              {t}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* SUBTAB 4: Selective Hash Scanner */}
      {activeSubTab === 'scanner' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 font-mono text-xs space-y-5">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <Hash className="w-4 h-4 text-teal-400" />
              <span>Selective On-Demand Cryptographic Hash Calculator</span>
            </h3>
            <p className="text-slate-400 text-xs mt-1">
              "Calculate hashes selectively for: executed files, suspicious files, files involved in alerts, manually requested scans."
            </p>
          </div>

          <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3">
            <label className="text-slate-300 font-bold block">Target File Path for Manual Verification:</label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={scanPath}
                onChange={e => setScanPath(e.target.value)}
                placeholder="e.g. C:\Users\User\Downloads\payload.exe or C:\Windows\System32\notepad.exe"
                className="flex-1 px-3 py-2 bg-slate-900 border border-slate-700 rounded text-xs text-white focus:outline-none focus:border-teal-500"
              />
              <button
                onClick={handleRequestHash}
                disabled={scanLoading}
                className="px-4 py-2 bg-teal-600 hover:bg-teal-500 text-white rounded font-bold transition flex items-center gap-1.5"
              >
                <Hash className={`w-3.5 h-3.5 ${scanLoading ? 'animate-spin' : ''}`} />
                <span>{scanLoading ? 'Hashing...' : 'Calculate Hash'}</span>
              </button>
            </div>
            <span className="text-[11px] text-slate-500">
              Only computes streaming SHA-256 for requested file. Streams and caches result without taxing CPU or memory.
            </span>
          </div>

          {/* Scan Output */}
          {scanResult && (
            <div className="bg-slate-950 p-4 rounded-lg border border-teal-500/40 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-teal-300 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-teal-400" />
                  Hash Computed Successfully
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-slate-400">
                  {scanResult.fromCache ? 'Loaded from Memory Cache' : 'Streamed from Disk'}
                </span>
              </div>
              <div className="space-y-1 text-slate-300 text-[11px]">
                <div>File Path: <span className="text-white">{scanResult.filePath}</span></div>
                <div>Algorithm: <span className="text-cyan-400">SHA-256</span></div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800 text-teal-300 font-bold select-all break-all">
                  {scanResult.hash}
                </div>
                <div>Trigger Reason: <span className="text-amber-400">{scanResult.reason}</span></div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 5: Safe Simulator */}
      {activeSubTab === 'simulator' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 font-mono text-xs">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <PlayCircle className="w-4 h-4 text-emerald-400" />
                <span>Safe Filesystem Simulation Suite</span>
              </h3>
              <span className="text-[11px] text-emerald-400 bg-emerald-950 border border-emerald-800 px-2 py-0.5 rounded">
                Benign &amp; Dropper Scenarios
              </span>
            </div>
            <p className="text-slate-400">
              Trigger pre-configured benign file creations and simulated malicious dropper patterns to test rules and timeline integration.
            </p>
          </div>

          {/* Last Simulation Callout */}
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
                <div>File Path: {simResult.event.file_path} ({simResult.event.file_category})</div>
                <div>Selective Hash: {simResult.event.file_hash || 'Skipped'} (Reason: {simResult.event.hash_calculation_reason || 'N/A'})</div>
                {simResult.event.detection_tags && simResult.event.detection_tags.length > 0 && (
                  <div>Tags: [{simResult.event.detection_tags.join(', ')}] • Risk Score: {simResult.event.risk_score}/100</div>
                )}
              </div>
            </div>
          )}

          {/* Simulation Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {simulations.map(sim => {
              const isMalicious = sim.category === 'malicious_file_detection';
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
                      <div>Action: <span className="text-cyan-400 uppercase font-bold">{sim.action}</span></div>
                      <div>Path: <span className="text-white break-all">{sim.file_path}</span></div>
                      <div>Process: <span className="text-amber-400">{sim.process_name}</span> [PID: {sim.pid}]</div>
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
                      <span>{isRunning ? 'Running...' : 'Run Simulation'}</span>
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
                <FolderSync className="w-5 h-5 text-emerald-400" />
                <div>
                  <h3 className="font-bold text-white text-sm">Filesystem Event Details</h3>
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
              <div><span className="text-slate-500">File Name:</span> <span className="text-white font-bold">{selectedEvent.file_name}</span></div>
              <div><span className="text-slate-500">Action:</span> <span className="text-white uppercase font-bold">{selectedEvent.action}</span></div>
              <div className="col-span-2"><span className="text-slate-500">File Path:</span> <span className="text-slate-200 break-all">{selectedEvent.file_path}</span></div>
              <div><span className="text-slate-500">Location Type:</span> <span className="text-cyan-400 font-bold">{selectedEvent.security_location}</span></div>
              <div><span className="text-slate-500">Category:</span> <span className="text-slate-300">{selectedEvent.file_category}</span></div>
              <div><span className="text-slate-500">Process Name:</span> <span className="text-slate-300">{selectedEvent.process_name || 'N/A'}</span></div>
              <div><span className="text-slate-500">Process PID:</span> <span className="text-slate-300">{selectedEvent.pid || 0}</span></div>
              <div className="col-span-2">
                <span className="text-slate-500">Selective Hash:</span>{' '}
                {selectedEvent.hash_calculated && selectedEvent.file_hash ? (
                  <span className="text-teal-300 font-bold select-all break-all">{selectedEvent.file_hash} (Reason: {selectedEvent.hash_calculation_reason})</span>
                ) : (
                  <span className="text-slate-500 italic">Not calculated (Preserving disk/CPU resources)</span>
                )}
              </div>
            </div>

            {selectedEvent.is_suspicious ? (
              <div className="bg-rose-950/40 border border-rose-500/40 p-3 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-rose-300 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    Suspicious Filesystem Detection
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
                <span>Clean file activity in standard endpoint operation.</span>
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
