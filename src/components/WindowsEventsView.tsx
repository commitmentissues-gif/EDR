import React, { useEffect, useState, useMemo } from 'react';
import { 
  ScrollText, 
  ShieldCheck, 
  ShieldAlert, 
  Sliders, 
  Search, 
  Filter, 
  RefreshCw, 
  PlayCircle, 
  CheckCircle2, 
  AlertTriangle, 
  X, 
  Eye, 
  Cpu, 
  Layers, 
  Database, 
  Lock, 
  UserCheck, 
  UserX, 
  FileCode, 
  Clock, 
  Sparkles,
  ExternalLink,
  ChevronRight,
  Copy,
  Check
} from 'lucide-react';
import { 
  NormalizedEvent, 
  ChannelConfig, 
  CollectorMetrics, 
  EventCategory, 
  WindowsEventChannel 
} from '../types';
import { safeFetchJson } from '../utils/api';

interface WindowsEventsViewProps {
  onNavigateTab: (tab: string) => void;
  onSelectAlertId?: (alertId: string) => void;
}

export const WindowsEventsView: React.FC<WindowsEventsViewProps> = ({ 
  onNavigateTab, 
  onSelectAlertId 
}) => {
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [channels, setChannels] = useState<Record<string, ChannelConfig>>({});
  const [metrics, setMetrics] = useState<CollectorMetrics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  // Filters
  const [selectedCategory, setSelectedCategory] = useState<EventCategory | 'all'>('all');
  const [selectedChannel, setSelectedChannel] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Channel configuration modal / drawer
  const [selectedChannelForEdit, setSelectedChannelForEdit] = useState<ChannelConfig | null>(null);
  const [savingChannel, setSavingChannel] = useState<boolean>(false);

  // Event detail modal
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEvent | null>(null);
  const [copiedJson, setCopiedJson] = useState<boolean>(false);

  // Simulation execution feedback
  const [simulating, setSimulating] = useState<string | null>(null);
  const [simulationMessage, setSimulationMessage] = useState<string | null>(null);

  // Load channels and normalized events
  const loadData = async (isManualRefresh = false) => {
    if (isManualRefresh) setRefreshing(true);
    try {
      // 1. Fetch channel configs & metrics
      const channelRes = await safeFetchJson<{
        config: { channels: Record<string, ChannelConfig> };
        channels: Record<string, ChannelConfig>;
        metrics: CollectorMetrics;
      }>('/api/events/channels', undefined);

      if (channelRes) {
        setChannels(channelRes.channels || channelRes.config?.channels || {});
        if (channelRes.metrics) setMetrics(channelRes.metrics);
      }

      // 2. Fetch normalized events
      const queryParams = new URLSearchParams();
      if (selectedCategory !== 'all') queryParams.set('category', selectedCategory);
      if (selectedChannel !== 'all') queryParams.set('channel', selectedChannel);
      if (selectedSeverity !== 'all') queryParams.set('severity', selectedSeverity);
      if (searchQuery.trim()) queryParams.set('search', searchQuery.trim());
      queryParams.set('limit', '150');

      const eventsRes = await safeFetchJson<{
        total: number;
        count: number;
        events: NormalizedEvent[];
        metrics?: CollectorMetrics;
      }>(`/api/events/normalized?${queryParams.toString()}`, undefined);

      if (eventsRes) {
        setEvents(eventsRes.events || []);
        setTotalCount(eventsRes.total || 0);
        if (eventsRes.metrics) setMetrics(eventsRes.metrics);
      }
    } catch (err) {
      console.error('Failed to load normalized events data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [selectedCategory, selectedChannel, selectedSeverity]);

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      loadData();
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Toggle channel enabled state directly
  const handleToggleChannel = async (channelName: string, currentEnabled: boolean) => {
    try {
      const res = await safeFetchJson<{ success: boolean; channel: ChannelConfig }>(
        `/api/events/channels/${encodeURIComponent(channelName)}`,
        undefined,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: !currentEnabled })
        }
      );

      if (res && res.success) {
        setChannels(prev => ({
          ...prev,
          [channelName]: res.channel
        }));
      }
    } catch (err) {
      console.error(`Failed to toggle channel ${channelName}:`, err);
    }
  };

  // Toggle noise filter for a channel
  const handleToggleNoiseFilter = async (channelName: string, currentFilter: boolean) => {
    try {
      const res = await safeFetchJson<{ success: boolean; channel: ChannelConfig }>(
        `/api/events/channels/${encodeURIComponent(channelName)}`,
        undefined,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filter_system_noise: !currentFilter })
        }
      );

      if (res && res.success) {
        setChannels(prev => ({
          ...prev,
          [channelName]: res.channel
        }));
      }
    } catch (err) {
      console.error(`Failed to toggle noise filter for ${channelName}:`, err);
    }
  };

  // Execute safe simulation
  const handleRunSimulation = async (scenario: string, label: string) => {
    setSimulating(scenario);
    setSimulationMessage(null);
    try {
      const res = await safeFetchJson<{
        success: boolean;
        scenario: string;
        event: NormalizedEvent;
        eventId: number;
        alertsTriggered: number;
        alerts: any[];
      }>(
        '/api/events/simulate',
        undefined,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario })
        }
      );

      if (res && res.success) {
        setSimulationMessage(`Injected ${label}. Alerts Triggered: ${res.alertsTriggered}`);
        // Reload list to see the event immediately
        await loadData();
      }
    } catch (err) {
      setSimulationMessage(`Simulation failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSimulating(null);
      setTimeout(() => setSimulationMessage(null), 5000);
    }
  };

  const handleCopyJson = (obj: any) => {
    navigator.clipboard.writeText(JSON.stringify(obj, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const prioritizedChannelList = [
    'Security',
    'System',
    'PowerShell',
    'Windows Defender',
    'Task Scheduler',
    'Service Control Manager'
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner with Low Resource Telemetry & Noise Reduction Stats */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <ScrollText className="w-5 h-5 text-indigo-400" />
              <h2 className="text-lg font-bold text-white tracking-tight">
                Windows Event Log Collection & Common Event Schema
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
                Normalized SQLite Store
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              High-efficiency collection pipeline prioritizing Security, System, PowerShell, Defender, Task Scheduler, and SCM event channels.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => loadData(true)}
              disabled={refreshing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button
              onClick={() => onNavigateTab('rules')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-mono transition cursor-pointer"
            >
              <Sliders className="w-3.5 h-3.5" />
              Detection Rules
            </button>
          </div>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 pt-4">
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
            <div className="text-[11px] text-slate-400 font-mono">Total Collected</div>
            <div className="text-xl font-bold text-white font-mono mt-1">
              {metrics?.totalCollected || 0}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5 font-mono">Raw telemetry stream</div>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
            <div className="text-[11px] text-slate-400 font-mono">Noise Filtered</div>
            <div className="text-xl font-bold text-cyan-400 font-mono mt-1">
              {metrics?.totalFilteredNoise || 0}
            </div>
            <div className="text-[10px] text-cyan-500/80 mt-0.5 font-mono">Low-resource policy</div>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
            <div className="text-[11px] text-slate-400 font-mono">Normalized In SQLite</div>
            <div className="text-xl font-bold text-emerald-400 font-mono mt-1">
              {metrics?.totalIngestedToDb || totalCount}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5 font-mono">Common schema records</div>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
            <div className="text-[11px] text-slate-400 font-mono">Active Channels</div>
            <div className="text-xl font-bold text-indigo-400 font-mono mt-1">
              {Object.values(channels).filter(c => c.enabled).length} / {Object.keys(channels).length || 6}
            </div>
            <div className="text-[10px] text-indigo-400/80 mt-0.5 font-mono">Prioritized sources</div>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
            <div className="text-[11px] text-slate-400 font-mono">Deduplication Cache</div>
            <div className="text-xl font-bold text-purple-400 font-mono mt-1">
              Active
            </div>
            <div className="text-[10px] text-purple-400/80 mt-0.5 font-mono">Bounded 5k records</div>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
            <div className="text-[11px] text-slate-400 font-mono">Detection Pipeline</div>
            <div className="text-xl font-bold text-amber-400 font-mono mt-1">
              Unified
            </div>
            <div className="text-[10px] text-amber-400/80 mt-0.5 font-mono">5 Event Categories</div>
          </div>
        </div>
      </div>

      {/* Configurable Windows Event Channels Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-emerald-400" />
              Prioritized Windows Event Channels Configuration
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Selectively collects security-relevant event IDs. Filters high-volume system background noise to conserve CPU and disk resources.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {prioritizedChannelList.map(channelName => {
            const ch = channels[channelName] || {
              channel: channelName as WindowsEventChannel,
              enabled: true,
              priority: 'HIGH',
              description: `Windows Event Log channel: ${channelName}`,
              allowed_event_ids: [],
              excluded_event_ids: [],
              filter_system_noise: true,
              max_batch_size: 100,
              min_severity_level: 'All'
            };

            const countInDb = metrics?.eventsPerChannel[channelName] || 0;

            return (
              <div 
                key={channelName}
                className={`bg-slate-950 rounded-xl border p-4 transition ${
                  ch.enabled ? 'border-slate-800' : 'border-slate-800/40 opacity-60'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span 
                      className={`w-2.5 h-2.5 rounded-full ${ch.enabled ? 'bg-emerald-400' : 'bg-slate-600'}`} 
                    />
                    <h4 className="font-bold text-xs text-white font-mono">{ch.channel}</h4>
                    <span 
                      className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold ${
                        ch.priority === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : ch.priority === 'HIGH'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {ch.priority}
                    </span>
                  </div>

                  {/* Enable/Disable Toggle */}
                  <button
                    onClick={() => handleToggleChannel(channelName, ch.enabled)}
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold transition cursor-pointer ${
                      ch.enabled
                        ? 'bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30'
                        : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                    }`}
                  >
                    {ch.enabled ? 'ENABLED' : 'DISABLED'}
                  </button>
                </div>

                <p className="text-[11px] text-slate-400 mt-2 line-clamp-2 leading-relaxed">
                  {ch.description}
                </p>

                {/* Event IDs configured */}
                <div className="mt-3 pt-3 border-t border-slate-900 flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-[10px] text-slate-500 font-mono">EIDs:</span>
                    {ch.allowed_event_ids.length > 0 ? (
                      ch.allowed_event_ids.map(eid => (
                        <span 
                          key={eid}
                          className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-cyan-400"
                        >
                          {eid}
                        </span>
                      ))
                    ) : (
                      <span className="text-[10px] text-slate-500 font-mono">All Allowed</span>
                    )}
                  </div>

                  <div className="text-[11px] font-mono text-slate-400">
                    <span className="text-white font-semibold">{countInDb}</span> logs
                  </div>
                </div>

                {/* Noise Reduction Toggle */}
                <div className="mt-2.5 flex items-center justify-between text-[11px] text-slate-400 bg-slate-900/60 px-2.5 py-1.5 rounded-lg border border-slate-850">
                  <span className="text-slate-400">Noise Filtering</span>
                  <button
                    onClick={() => handleToggleNoiseFilter(channelName, ch.filter_system_noise)}
                    className={`text-[10px] font-mono cursor-pointer font-semibold ${
                      ch.filter_system_noise ? 'text-cyan-400 hover:text-cyan-300' : 'text-slate-500 hover:text-slate-400'
                    }`}
                  >
                    {ch.filter_system_noise ? 'ACTIVE (Low Noise)' : 'OFF (Raw)'}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Quick Security Events Simulator Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <PlayCircle className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-bold text-white tracking-wide uppercase font-mono">
              Live Security Events Simulator
            </h3>
            <span className="text-[11px] text-slate-400">
              Trigger high-fidelity normalized Windows events to test collection & detections:
            </span>
          </div>

          {simulationMessage && (
            <div className="text-xs font-mono px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 animate-fade-in">
              <CheckCircle2 className="w-3.5 h-3.5" />
              {simulationMessage}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
          {[
            { id: 'successful_logon', label: 'Logon (4624)', desc: 'Interactive session' },
            { id: 'failed_logon', label: 'Failed Logon (4625)', desc: 'Bad password probing' },
            { id: 'account_creation', label: 'Account Created (4720)', desc: 'Backdoor admin' },
            { id: 'privilege_change', label: 'Privilege Assigned (4672)', desc: 'SeDebug privilege' },
            { id: 'service_creation', label: 'Service Created (7045)', desc: 'SCM persistence' },
            { id: 'scheduled_task', label: 'Task Registered (106)', desc: 'Task scheduler' },
            { id: 'powershell_activity', label: 'PowerShell ScriptBlock (4104)', desc: 'Download cradle' },
            { id: 'defender_disabled', label: 'Defender Disabled (5001)', desc: 'Defense tampering' },
            { id: 'audit_cleared', label: 'Audit Cleared (1102)', desc: 'Log wiping' }
          ].map(sim => (
            <button
              key={sim.id}
              onClick={() => handleRunSimulation(sim.id, sim.label)}
              disabled={simulating !== null}
              className={`px-2.5 py-1.5 rounded-lg border text-[11px] transition flex items-center gap-1.5 cursor-pointer ${
                simulating === sim.id
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 animate-pulse'
                  : 'bg-slate-950 hover:bg-slate-800 text-slate-300 border-slate-800'
              }`}
            >
              <span>{sim.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Normalized Common Event Schema Explorer */}
      <div className="space-y-4">
        {/* Filter and Search Bar */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3 flex-wrap">
            {/* Search */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search event, user, process, service, task, command..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 w-80 font-mono"
              />
            </div>

            {/* Category Filter Tabs */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
              {[
                { id: 'all', label: 'All Schemas' },
                { id: 'windows_event', label: 'Windows Event Logs' },
                { id: 'process', label: 'Process Events' },
                { id: 'network', label: 'Network Events' },
                { id: 'file', label: 'File Events' },
                { id: 'registry', label: 'Registry Events' }
              ].map(cat => (
                <button
                  key={cat.id}
                  onClick={() => setSelectedCategory(cat.id as any)}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono transition cursor-pointer ${
                    selectedCategory === cat.id
                      ? 'bg-indigo-600 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>

            {/* Channel Filter (if Windows Event or All) */}
            <select
              value={selectedChannel}
              onChange={(e) => setSelectedChannel(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-indigo-500"
            >
              <option value="all">All Channels</option>
              {prioritizedChannelList.map(ch => (
                <option key={ch} value={ch}>{ch}</option>
              ))}
            </select>

            {/* Severity Filter */}
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-indigo-500"
            >
              <option value="all">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFORMATIONAL">INFORMATIONAL</option>
            </select>
          </div>

          <div className="text-xs font-mono text-slate-400">
            Showing <span className="text-white font-semibold">{events.length}</span> of {totalCount} normalized records
          </div>
        </div>

        {/* Normalized Events Table */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead>
                <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Category</th>
                  <th className="p-3">Channel / Event ID</th>
                  <th className="p-3">Action & Summary</th>
                  <th className="p-3">Subject / User</th>
                  <th className="p-3">Target / Resource</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3 text-right">Detection</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-10 text-center text-slate-500">
                      {loading ? 'Loading normalized events from SQLite...' : 'No normalized events matching the current criteria.'}
                    </td>
                  </tr>
                ) : (
                  events.map(ev => {
                    const isAlerted = !!ev.is_alerted;
                    return (
                      <tr
                        key={ev.id || ev.event_uuid}
                        onClick={() => setSelectedEvent(ev)}
                        className="hover:bg-slate-850/80 transition cursor-pointer group"
                      >
                        <td className="p-3 text-slate-400 whitespace-nowrap">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </td>

                        {/* Category Badge */}
                        <td className="p-3 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                              ev.event_category === 'windows_event'
                                ? 'bg-indigo-950 text-indigo-400 border border-indigo-800'
                                : ev.event_category === 'process'
                                ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                                : ev.event_category === 'network'
                                ? 'bg-blue-950 text-blue-400 border border-blue-800'
                                : ev.event_category === 'file'
                                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                : 'bg-amber-950 text-amber-400 border border-amber-800'
                            }`}
                          >
                            {ev.event_category.replace('_', ' ')}
                          </span>
                        </td>

                        {/* Channel & Event ID */}
                        <td className="p-3 whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-200 font-semibold">{ev.channel || 'Sysmon'}</span>
                            {ev.windows_event_id && (
                              <span className="px-1.5 py-0.2 rounded bg-slate-950 text-cyan-300 border border-slate-800 text-[10px]">
                                EID {ev.windows_event_id}
                              </span>
                            )}
                          </div>
                        </td>

                        {/* Action & Message */}
                        <td className="p-3 text-slate-300 max-w-sm">
                          <div className="font-semibold text-white truncate">{ev.action}</div>
                          <div className="text-[11px] text-slate-400 truncate mt-0.5">{ev.message}</div>
                        </td>

                        {/* Subject / User */}
                        <td className="p-3 text-slate-300 whitespace-nowrap">
                          <div className="flex items-center gap-1">
                            <span className="text-slate-200">
                              {ev.user_domain ? `${ev.user_domain}\\` : ''}{ev.user_name || ev.user || 'SYSTEM'}
                            </span>
                          </div>
                        </td>

                        {/* Target / Resource */}
                        <td className="p-3 text-slate-300 max-w-xs truncate">
                          {ev.target_user ? (
                            <span className="text-rose-300 font-semibold">&rarr; User: {ev.target_user}</span>
                          ) : ev.service_name ? (
                            <span className="text-amber-300 font-semibold">&rarr; Svc: {ev.service_name}</span>
                          ) : ev.task_name ? (
                            <span className="text-purple-300 font-semibold">&rarr; Task: {ev.task_name}</span>
                          ) : ev.process_name ? (
                            <span className="text-cyan-300 font-semibold">&rarr; {ev.process_name}</span>
                          ) : ev.file_path ? (
                            <span className="text-emerald-300">&rarr; {ev.file_path}</span>
                          ) : ev.registry_key ? (
                            <span className="text-amber-300">&rarr; {ev.registry_key}</span>
                          ) : ev.destination_ip ? (
                            <span className="text-blue-300">&rarr; {ev.destination_ip}:{ev.destination_port}</span>
                          ) : (
                            <span className="text-slate-500">-</span>
                          )}
                        </td>

                        {/* Severity */}
                        <td className="p-3 whitespace-nowrap">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              ev.severity === 'CRITICAL'
                                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                : ev.severity === 'HIGH'
                                ? 'bg-amber-950 text-amber-300 border border-amber-800'
                                : ev.severity === 'MEDIUM'
                                ? 'bg-yellow-950 text-yellow-300 border border-yellow-800'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {ev.severity}
                          </span>
                        </td>

                        {/* Detection Alert Status */}
                        <td className="p-3 text-right whitespace-nowrap">
                          {isAlerted ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40">
                              ALERTED
                            </span>
                          ) : (
                            <span className="text-slate-500 text-[10px]">
                              Ingested
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
      </div>

      {/* Normalized Event Record Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full p-5 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ScrollText className="w-5 h-5 text-indigo-400" />
                <h4 className="font-bold text-white text-sm">
                  Normalized Event Record #{selectedEvent.id || 'N/A'} [{selectedEvent.event_category.toUpperCase()}]
                </h4>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleCopyJson(selectedEvent)}
                  className="flex items-center gap-1 text-slate-300 hover:text-white text-xs px-2.5 py-1 rounded bg-slate-800 cursor-pointer"
                >
                  {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedJson ? 'Copied' : 'Copy JSON'}
                </button>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="text-slate-400 hover:text-white text-xs px-2.5 py-1 rounded bg-slate-800 cursor-pointer"
                >
                  Close
                </button>
              </div>
            </div>

            {/* Structured Schema Breakdown */}
            <div className="space-y-4 text-xs font-mono">
              {/* Core Information */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2.5 p-3.5 bg-slate-950 rounded-lg border border-slate-800">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Timestamp</span>
                  <span className="text-white font-semibold">{selectedEvent.timestamp}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Category</span>
                  <span className="text-indigo-400 font-semibold">{selectedEvent.event_category}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Event Type</span>
                  <span className="text-cyan-400 font-semibold">{selectedEvent.event_type}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Channel</span>
                  <span className="text-white">{selectedEvent.channel || 'Sysmon'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Windows Event ID</span>
                  <span className="text-amber-400 font-bold">{selectedEvent.windows_event_id || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Hostname</span>
                  <span className="text-white">{selectedEvent.hostname}</span>
                </div>
              </div>

              {/* Action & Message */}
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
                <span className="text-slate-400 block text-[10px] uppercase">Action / Description</span>
                <div className="text-white font-semibold">{selectedEvent.action}</div>
                <div className="text-slate-300 text-xs leading-relaxed">{selectedEvent.message}</div>
              </div>

              {/* Identity & Process Context */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {/* Identity */}
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                  <span className="text-slate-400 block text-[10px] uppercase border-b border-slate-900 pb-1">
                    Identity Context
                  </span>
                  <div>
                    <span className="text-slate-400">User:</span>{' '}
                    <span className="text-white">{selectedEvent.user_name || selectedEvent.user || 'SYSTEM'}</span>
                  </div>
                  {selectedEvent.user_domain && (
                    <div>
                      <span className="text-slate-400">Domain:</span>{' '}
                      <span className="text-white">{selectedEvent.user_domain}</span>
                    </div>
                  )}
                  {selectedEvent.logon_type !== undefined && (
                    <div>
                      <span className="text-slate-400">Logon Type:</span>{' '}
                      <span className="text-cyan-300">{selectedEvent.logon_type}</span>
                    </div>
                  )}
                  {selectedEvent.privilege_list && selectedEvent.privilege_list.length > 0 && (
                    <div>
                      <span className="text-slate-400">Privileges:</span>{' '}
                      <span className="text-rose-300">{selectedEvent.privilege_list.join(', ')}</span>
                    </div>
                  )}
                  {selectedEvent.target_user && (
                    <div>
                      <span className="text-slate-400">Target User:</span>{' '}
                      <span className="text-amber-400 font-bold">{selectedEvent.target_user}</span>
                    </div>
                  )}
                </div>

                {/* Process & Target */}
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                  <span className="text-slate-400 block text-[10px] uppercase border-b border-slate-900 pb-1">
                    Process & Target Context
                  </span>
                  {selectedEvent.process_name && (
                    <div>
                      <span className="text-slate-400">Process:</span>{' '}
                      <span className="text-white">{selectedEvent.process_name} (PID: {selectedEvent.process_id})</span>
                    </div>
                  )}
                  {selectedEvent.service_name && (
                    <div>
                      <span className="text-slate-400">Service:</span>{' '}
                      <span className="text-amber-400 font-bold">{selectedEvent.service_name}</span>
                    </div>
                  )}
                  {selectedEvent.task_name && (
                    <div>
                      <span className="text-slate-400">Task Name:</span>{' '}
                      <span className="text-purple-400 font-bold">{selectedEvent.task_name}</span>
                    </div>
                  )}
                  {selectedEvent.file_path && (
                    <div>
                      <span className="text-slate-400">File Path:</span>{' '}
                      <span className="text-emerald-300 break-all">{selectedEvent.file_path}</span>
                    </div>
                  )}
                  {selectedEvent.registry_key && (
                    <div>
                      <span className="text-slate-400">Registry Key:</span>{' '}
                      <span className="text-amber-300 break-all">{selectedEvent.registry_key}</span>
                    </div>
                  )}
                  {selectedEvent.destination_ip && (
                    <div>
                      <span className="text-slate-400">Destination IP:</span>{' '}
                      <span className="text-blue-300">{selectedEvent.destination_ip}:{selectedEvent.destination_port}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Command Line or Script Text */}
              {(selectedEvent.command_line || selectedEvent.script_text) && (
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                  <span className="text-slate-400 block text-[10px] uppercase">
                    {selectedEvent.script_text ? 'ScriptBlock Payload' : 'Command Line Arguments'}
                  </span>
                  <pre className="text-slate-200 text-xs break-all whitespace-pre-wrap max-h-32 overflow-y-auto">
                    {selectedEvent.script_text || selectedEvent.command_line}
                  </pre>
                </div>
              )}

              {/* Raw JSON */}
              <div>
                <span className="text-slate-400 text-xs block mb-1">Normalized Common Event Schema (JSON):</span>
                <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] text-slate-300 overflow-x-auto max-h-48">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
