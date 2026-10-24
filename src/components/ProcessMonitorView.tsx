import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  Search, 
  GitBranch, 
  List, 
  ShieldCheck, 
  ShieldAlert, 
  Copy, 
  Check, 
  ChevronRight, 
  ChevronDown, 
  X, 
  User, 
  Terminal, 
  FileCode, 
  RefreshCw,
  Clock,
  AlertTriangle
} from 'lucide-react';
import { ProcessEvent, ProcessTreeNode } from '../types';
import { ProcessTreeComponent } from './ProcessTreeComponent';
import { safeFetchJson } from '../utils/api';

interface ProcessMonitorViewProps {
  onRefresh?: () => void;
}

export const ProcessMonitorView: React.FC<ProcessMonitorViewProps> = () => {
  const [viewMode, setViewMode] = useState<'tree' | 'list'>('tree');
  const [processes, setProcesses] = useState<ProcessEvent[]>([]);
  const [processTree, setProcessTree] = useState<ProcessTreeNode[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [integrityFilter, setIntegrityFilter] = useState<string>('all');
  const [signatureFilter, setSignatureFilter] = useState<string>('all');
  const [riskFilter, setRiskFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<'all' | 'live' | 'baseline' | 'simulated'>('all');
  const [selectedProcess, setSelectedProcess] = useState<ProcessEvent | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const fetchProcesses = async () => {
    setLoading(true);
    try {
      const [listRes, treeRes] = await Promise.all([
        safeFetchJson<{ processes: ProcessEvent[] }>('/api/processes?limit=300', { processes: [] }),
        safeFetchJson<{ tree: ProcessTreeNode[] }>('/api/process-tree', { tree: [] })
      ]);

      if (listRes?.processes) {
        setProcesses(listRes.processes);
      }
      if (treeRes?.tree) {
        setProcessTree(treeRes.tree);
      }
    } catch (err) {
      console.warn('[LocalEDR] Non-fatal process telemetry fetch warning:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProcesses();
    const interval = setInterval(fetchProcesses, 8000);
    return () => clearInterval(interval);
  }, []);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const isLiveSource = (source?: string) => source === 'sysmon_live' || source === 'live_monitor' || source === 'sysmon_agent';
  const isSimulatedSource = (source?: string) => source === 'safe_simulator';
  const isBaselineSource = (source?: string) => source === 'baseline_seed' || (!isLiveSource(source) && !isSimulatedSource(source));

  const liveProcessesCount = processes.filter(p => isLiveSource(p.source)).length;
  const baselineCount = processes.filter(p => isBaselineSource(p.source)).length;
  const simulatedCount = processes.filter(p => isSimulatedSource(p.source)).length;

  // Filtered process list
  const filteredProcesses = processes.filter((proc) => {
    if (sourceFilter === 'live' && !isLiveSource(proc.source)) {
      return false;
    }
    if (sourceFilter === 'baseline' && !isBaselineSource(proc.source)) {
      return false;
    }
    if (sourceFilter === 'simulated' && !isSimulatedSource(proc.source)) {
      return false;
    }
    if (integrityFilter !== 'all' && proc.integrity_level.toLowerCase() !== integrityFilter.toLowerCase()) {
      return false;
    }
    if (signatureFilter !== 'all' && proc.signature_status.toLowerCase() !== signatureFilter.toLowerCase()) {
      return false;
    }
    if (riskFilter === 'high_critical' && (proc.risk_score || 0) < 50) {
      return false;
    }
    if (riskFilter === 'medium' && ((proc.risk_score || 0) < 25 || (proc.risk_score || 0) >= 50)) {
      return false;
    }
    if (riskFilter === 'low' && (proc.risk_score || 0) >= 25) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        proc.process_name.toLowerCase().includes(q) ||
        proc.pid.toString().includes(q) ||
        proc.parent_pid.toString().includes(q) ||
        proc.executable_path.toLowerCase().includes(q) ||
        proc.command_line.toLowerCase().includes(q) ||
        proc.username.toLowerCase().includes(q) ||
        (proc.sha256 && proc.sha256.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const systemCount = processes.filter(p => p.integrity_level === 'System').length;
  const highCount = processes.filter(p => p.integrity_level === 'High').length;
  const mediumCount = processes.filter(p => p.integrity_level === 'Medium').length;
  const highRiskCount = processes.filter(p => (p.risk_score || 0) >= 50).length;

  return (
    <div className="space-y-4">
      {/* Top Banner & Mode Switcher */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <h2 className="font-bold text-white text-base">Windows Process Monitoring &amp; Lineage Engine</h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              Event-Driven • Tree Reconstructed
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Hierarchical process execution tree reconstructing parent-child relationships (e.g. explorer.exe ➔ chrome.exe, powershell.exe, cmd.exe). Preserves terminated parents.
          </p>
        </div>

        {/* View Switcher & Refresh */}
        <div className="flex items-center gap-2">
          <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            <button
              onClick={() => setViewMode('tree')}
              className={`px-3 py-1 rounded flex items-center gap-1.5 transition font-medium cursor-pointer ${
                viewMode === 'tree'
                  ? 'bg-slate-800 text-cyan-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              <span>Process Tree</span>
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`px-3 py-1 rounded flex items-center gap-1.5 transition font-medium cursor-pointer ${
                viewMode === 'list'
                  ? 'bg-slate-800 text-cyan-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <List className="w-3.5 h-3.5" />
              <span>Process List</span>
            </button>
          </div>

          <button
            onClick={fetchProcesses}
            disabled={loading}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer disabled:opacity-50"
            title="Refresh processes"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Telemetry Provenance Banner */}
      <div className={`p-4 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 text-xs font-mono transition ${
        liveProcessesCount > 0
          ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
          : 'bg-slate-900/90 border-slate-800 text-slate-300'
      }`}>
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 shrink-0">
            {liveProcessesCount > 0 ? (
              <span className="flex h-3 w-3 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
              </span>
            ) : (
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-bold text-white text-sm">
                {liveProcessesCount > 0
                  ? `Genuine Endpoint Telemetry Connected (${liveProcessesCount} live events)`
                  : 'Telemetry Mode: Baseline Fixtures Active (No Live Windows Telemetry Yet)'}
              </span>
              <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                liveProcessesCount > 0 ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-slate-800 text-slate-400 border border-slate-700'
              }`}>
                {liveProcessesCount > 0 ? 'Live Ingestion Verified' : 'Awaiting Windows Agent'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5 max-w-2xl font-sans leading-normal">
              {liveProcessesCount > 0
                ? 'Genuine Sysmon process creation events forwarded from Windows host are actively updating this execution tree in real-time.'
                : 'Seeded baseline processes are displayed for architecture and lineage verification. To forward genuine live events from Windows, run the LocalEDR Agent or scripts/LocalEDR-Sysmon-Collector.ps1.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-[11px] self-end md:self-auto shrink-0">
          <span className="px-2.5 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            {liveProcessesCount} Live
          </span>
          <span className="px-2.5 py-1 rounded bg-slate-950 text-slate-300 border border-slate-800">
            {baselineCount} Baseline
          </span>
          {simulatedCount > 0 && (
            <span className="px-2.5 py-1 rounded bg-purple-950 text-purple-300 border border-purple-800">
              {simulatedCount} Simulated
            </span>
          )}
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
        <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
          <span className="text-slate-500 block text-[10px] uppercase">Recorded Processes</span>
          <span className="text-xl font-bold text-white mt-1 block">{processes.length}</span>
        </div>
        <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
          <span className="text-slate-500 block text-[10px] uppercase">Live Endpoint (Sysmon)</span>
          <span className={`text-xl font-bold mt-1 block ${liveProcessesCount > 0 ? 'text-emerald-400' : 'text-slate-400'}`}>
            {liveProcessesCount}
          </span>
        </div>
        <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
          <span className="text-slate-500 block text-[10px] uppercase">Seeded Baseline</span>
          <span className="text-xl font-bold text-slate-300 mt-1 block">{baselineCount}</span>
        </div>
        <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
          <span className="text-slate-500 block text-[10px] uppercase">High / Critical Risk</span>
          <span className="text-xl font-bold text-rose-400 mt-1 block">{highRiskCount}</span>
        </div>
      </div>

      {/* Main View: Process Tree vs Process List */}
      {viewMode === 'tree' ? (
        <ProcessTreeComponent
          tree={processTree}
          loading={loading}
          onRefresh={fetchProcesses}
        />
      ) : (
        <div className="space-y-4">
          {/* Filter and Search Bar for List Mode */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
            <div className="flex items-center gap-3 flex-wrap">
              {/* Search Box */}
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search PID, name, cmdline, SHA-256..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-72"
                />
              </div>

              {/* Risk Filter */}
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-500 px-1.5">Risk:</span>
                {[
                  { id: 'all', label: 'All' },
                  { id: 'high_critical', label: 'High+' },
                  { id: 'medium', label: 'Medium' },
                  { id: 'low', label: 'Low' }
                ].map((r) => (
                  <button
                    key={r.id}
                    onClick={() => setRiskFilter(r.id)}
                    className={`px-2 py-0.5 rounded text-[11px] transition cursor-pointer ${
                      riskFilter === r.id
                        ? 'bg-slate-800 text-white font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {r.label}
                  </button>
                ))}
              </div>

              {/* Integrity Level Filter */}
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-500 px-1.5">Integrity:</span>
                {['all', 'System', 'High', 'Medium'].map((lvl) => (
                  <button
                    key={lvl}
                    onClick={() => setIntegrityFilter(lvl)}
                    className={`px-2 py-0.5 rounded text-[11px] transition cursor-pointer ${
                      integrityFilter === lvl
                        ? 'bg-slate-800 text-white font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {lvl}
                  </button>
                ))}
              </div>

              {/* Signature Filter */}
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-500 px-1.5">Signature:</span>
                {['all', 'Valid', 'Unsigned', 'Invalid'].map((sig) => (
                  <button
                    key={sig}
                    onClick={() => setSignatureFilter(sig)}
                    className={`px-2 py-0.5 rounded text-[11px] transition cursor-pointer ${
                      signatureFilter === sig
                        ? 'bg-slate-800 text-white font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {sig}
                  </button>
                ))}
              </div>

              {/* Telemetry Source Filter */}
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-500 px-1.5">Source:</span>
                {[
                  { id: 'all', label: 'All' },
                  { id: 'live', label: '🟢 Live' },
                  { id: 'baseline', label: '⚪ Baseline' },
                  { id: 'simulated', label: '🟣 Simulated' }
                ].map((s) => (
                  <button
                    key={s.id}
                    onClick={() => setSourceFilter(s.id as any)}
                    className={`px-2 py-0.5 rounded text-[11px] transition cursor-pointer ${
                      sourceFilter === s.id
                        ? 'bg-slate-800 text-white font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="text-[11px] text-slate-400">
              Showing <span className="text-white font-semibold">{filteredProcesses.length}</span> processes
            </div>
          </div>

          {/* Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
                    <th className="p-3">PID</th>
                    <th className="p-3">PPID</th>
                    <th className="p-3">Source</th>
                    <th className="p-3">Process Name</th>
                    <th className="p-3">Risk Score</th>
                    <th className="p-3">User</th>
                    <th className="p-3">Integrity</th>
                    <th className="p-3">Signature / Publisher</th>
                    <th className="p-3">Command Line / Path</th>
                    <th className="p-3">Started</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredProcesses.length === 0 ? (
                    <tr>
                      <td colSpan={10} className="p-8 text-center text-slate-500">
                        No processes match the current search criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredProcesses.map((proc) => {
                      const isSystem = proc.integrity_level === 'System';
                      const isHigh = proc.integrity_level === 'High';
                      const isSelected = selectedProcess?.id === proc.id;
                      const riskScore = proc.risk_score ?? 0;

                      return (
                        <tr
                          key={proc.id}
                          onClick={() => setSelectedProcess(proc)}
                          className={`hover:bg-slate-850/80 transition cursor-pointer ${
                            isSelected ? 'bg-slate-850 border-l-2 border-cyan-500' : ''
                          }`}
                        >
                          <td className="p-3 font-bold text-cyan-300">{proc.pid}</td>
                          <td className="p-3 text-slate-400">{proc.parent_pid}</td>
                          <td className="p-3 whitespace-nowrap">
                            {isLiveSource(proc.source) ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/70 flex items-center gap-1 w-fit shadow-xs">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                                <span>Live</span>
                              </span>
                            ) : isSimulatedSource(proc.source) ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950/80 text-purple-300 border border-purple-800 w-fit block">
                                Simulated
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700 w-fit block">
                                Baseline
                              </span>
                            )}
                          </td>
                          <td className="p-3 font-semibold text-slate-100 whitespace-nowrap">
                            <div className="flex items-center gap-1.5">
                              <span>{proc.process_name}</span>
                              {proc.is_terminated && (
                                <span className="text-[9px] text-slate-400 px-1 py-0.2 rounded bg-slate-800">
                                  Terminated
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="p-3 whitespace-nowrap">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                riskScore >= 75
                                  ? 'bg-rose-950 text-rose-300 border-rose-800'
                                  : riskScore >= 50
                                  ? 'bg-orange-950 text-orange-300 border-orange-800'
                                  : riskScore >= 25
                                  ? 'bg-amber-950 text-amber-300 border-amber-800'
                                  : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                              }`}
                            >
                              {riskScore} ({proc.risk_level || 'LOW'})
                            </span>
                          </td>
                          <td className="p-3 text-slate-400 whitespace-nowrap">{proc.username}</td>
                          <td className="p-3 whitespace-nowrap">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                                isSystem
                                  ? 'bg-indigo-950 text-indigo-300 border border-indigo-800'
                                  : isHigh
                                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                  : 'bg-slate-800 text-slate-300 border border-slate-700'
                              }`}
                            >
                              {proc.integrity_level}
                            </span>
                          </td>
                          <td className="p-3 whitespace-nowrap">
                            <div className="flex items-center gap-1.5">
                              <span
                                className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                                  proc.signature_status === 'Valid'
                                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                                }`}
                              >
                                {proc.signature_status}
                              </span>
                              <span className="text-[10px] text-slate-400 truncate max-w-[120px]">
                                {proc.publisher || 'Unknown'}
                              </span>
                            </div>
                          </td>
                          <td className="p-3 text-slate-300 max-w-sm truncate">
                            {proc.command_line || proc.executable_path}
                          </td>
                          <td className="p-3 text-slate-400 whitespace-nowrap text-[11px]">
                            {new Date(proc.creation_timestamp).toLocaleTimeString()}
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
      )}

      {/* Process Detail Inspector Drawer for List Mode */}
      {selectedProcess && viewMode === 'list' && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-cyan-400 font-bold text-sm">
                    PID {selectedProcess.pid}
                  </span>
                  <span className="text-xs text-slate-400">•</span>
                  <span className="text-xs font-mono text-slate-300 font-semibold">
                    {selectedProcess.process_name}
                  </span>
                  <span
                    className={`px-1.5 py-0.2 rounded text-[10px] font-mono uppercase font-bold ${
                      selectedProcess.integrity_level === 'System'
                        ? 'bg-indigo-950 text-indigo-400 border border-indigo-800'
                        : selectedProcess.integrity_level === 'High'
                        ? 'bg-rose-950 text-rose-400 border border-rose-800'
                        : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    {selectedProcess.integrity_level}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-300 border border-slate-700">
                    Risk: {selectedProcess.risk_score || 0}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                      isLiveSource(selectedProcess.source)
                        ? 'bg-emerald-950 text-emerald-300 border-emerald-500/70'
                        : isSimulatedSource(selectedProcess.source)
                        ? 'bg-purple-950 text-purple-300 border-purple-800'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    {isLiveSource(selectedProcess.source)
                      ? '🟢 Live Endpoint'
                      : isSimulatedSource(selectedProcess.source)
                      ? '🟣 Simulation'
                      : '⚪ Baseline Seed'}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1 font-mono">
                  Started at {new Date(selectedProcess.creation_timestamp).toLocaleString()}
                </p>
              </div>

              <button
                onClick={() => setSelectedProcess(null)}
                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Metadata Grid */}
            <div className="space-y-3 text-xs font-mono">
              <div className="grid grid-cols-2 gap-2 p-3 bg-slate-950 rounded-lg border border-slate-800">
                <div>
                  <span className="text-slate-500 block text-[10px]">PROCESS ID (PID)</span>
                  <span className="text-white font-bold">{selectedProcess.pid}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">PARENT PROCESS ID (PPID)</span>
                  <span className="text-white font-bold">{selectedProcess.parent_pid}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">USERNAME</span>
                  <span className="text-slate-200">{selectedProcess.username}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">HOSTNAME / ENDPOINT</span>
                  <span className="text-slate-200 font-semibold">{selectedProcess.hostname || 'WIN-ENDPOINT'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">AUTHENTICODE SIGNATURE</span>
                  <span className={`font-semibold ${selectedProcess.signature_status === 'Valid' ? 'text-emerald-400' : 'text-slate-400'}`}>
                    {selectedProcess.signature_status}
                  </span>
                </div>
              </div>

              {/* Executable Path */}
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                <div className="flex items-center justify-between text-[10px] text-slate-500">
                  <span>EXECUTABLE PATH</span>
                  <button
                    onClick={() => copyToClipboard(selectedProcess.executable_path, 'path')}
                    className="flex items-center gap-1 text-cyan-400 hover:underline cursor-pointer"
                  >
                    {copiedText === 'path' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedText === 'path' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <div className="text-slate-200 break-all">{selectedProcess.executable_path}</div>
              </div>

              {/* Command Line */}
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                <div className="flex items-center justify-between text-[10px] text-slate-500">
                  <span>COMMAND LINE ARGUMENTS</span>
                  <button
                    onClick={() => copyToClipboard(selectedProcess.command_line, 'cmd')}
                    className="flex items-center gap-1 text-cyan-400 hover:underline cursor-pointer"
                  >
                    {copiedText === 'cmd' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedText === 'cmd' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <div className="text-slate-200 break-all leading-relaxed bg-slate-900 p-2 rounded border border-slate-800">
                  {selectedProcess.command_line || selectedProcess.executable_path}
                </div>
              </div>

              {/* SHA-256 Hash */}
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                <div className="flex items-center justify-between text-[10px] text-slate-500">
                  <span>SHA-256 HASH</span>
                  {selectedProcess.sha256 && (
                    <button
                      onClick={() => copyToClipboard(selectedProcess.sha256, 'hash')}
                      className="flex items-center gap-1 text-cyan-400 hover:underline cursor-pointer"
                    >
                      {copiedText === 'hash' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedText === 'hash' ? 'Copied' : 'Copy'}</span>
                    </button>
                  )}
                </div>
                <div className="text-cyan-300 break-all font-mono text-[11px]">
                  {selectedProcess.sha256 || 'Hash not available.'}
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedProcess(null)}
                className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold cursor-pointer"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
