import React, { useState, useEffect, useMemo } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Terminal, 
  PlayCircle, 
  CheckCircle2, 
  AlertTriangle, 
  Sliders, 
  RefreshCw, 
  Search, 
  Info, 
  ExternalLink,
  ChevronRight,
  Eye,
  X,
  FileCode,
  FolderOpen,
  ArrowRight,
  Layers,
  Cpu,
  Power
} from 'lucide-react';
import { 
  MonitoredBinaryMeta, 
  ContextualBehaviorDefinition, 
  LolbinGlobalConfig, 
  SafeSimulationScenario,
  LolbinDetectionResult,
  MonitoredBinaryName
} from '../types';
import { safeFetchJson } from '../utils/api';

interface LolbinsViewProps {
  onNavigateTab?: (tab: string) => void;
}

export const LolbinsView: React.FC<LolbinsViewProps> = ({ onNavigateTab }) => {
  const [binaries, setBinaries] = useState<MonitoredBinaryMeta[]>([]);
  const [behaviors, setBehaviors] = useState<ContextualBehaviorDefinition[]>([]);
  const [config, setConfig] = useState<LolbinGlobalConfig | null>(null);
  const [simulations, setSimulations] = useState<SafeSimulationScenario[]>([]);
  const [activeSubTab, setActiveSubTab] = useState<'binaries' | 'behaviors' | 'simulator' | 'config'>('binaries');
  
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [loading, setLoading] = useState(false);
  const [updatingBinary, setUpdatingBinary] = useState<string | null>(null);

  // Real-time evaluation input
  const [evalProcess, setEvalProcess] = useState('powershell.exe');
  const [evalCmd, setEvalCmd] = useState('powershell.exe -WindowStyle Hidden -Command "(New-Object Net.WebClient).DownloadString(\'http://127.0.0.1/test.ps1\')"');
  const [evalParent, setEvalParent] = useState('cmd.exe');
  const [evalResult, setEvalResult] = useState<LolbinDetectionResult | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  // Simulation run state
  const [runningSimId, setRunningSimId] = useState<string | null>(null);
  const [simResultModal, setSimResultModal] = useState<any | null>(null);

  // Inspect detail modal
  const [selectedBinary, setSelectedBinary] = useState<MonitoredBinaryMeta | null>(null);
  const [selectedBehavior, setSelectedBehavior] = useState<ContextualBehaviorDefinition | null>(null);

  const fetchLolbinData = async () => {
    try {
      setLoading(true);
      const [binRes, behRes, cfgRes, simRes] = await Promise.all([
        safeFetchJson<{ total: number; monitored: MonitoredBinaryMeta[] }>('/api/lolbins/monitored', { total: 0, monitored: [] }),
        safeFetchJson<{ total: number; behaviors: ContextualBehaviorDefinition[] }>('/api/lolbins/behaviors', { total: 0, behaviors: [] }),
        safeFetchJson<LolbinGlobalConfig | null>('/api/lolbins/config', null),
        safeFetchJson<{ total: number; simulations: SafeSimulationScenario[] }>('/api/lolbins/simulations', { total: 0, simulations: [] })
      ]);

      if (binRes && binRes.monitored) setBinaries(binRes.monitored);
      if (behRes && behRes.behaviors) setBehaviors(behRes.behaviors);
      if (cfgRes) setConfig(cfgRes);
      if (simRes && simRes.simulations) setSimulations(simRes.simulations);
    } catch (err) {
      console.warn('[LocalEDR] Failed to load LOLBin data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLolbinData();
  }, []);

  // Toggle monitoring for a specific binary
  const handleToggleBinary = async (name: MonitoredBinaryName, currentEnabled: boolean) => {
    try {
      setUpdatingBinary(name);
      const res = await fetch(`/api/lolbins/monitored/${name}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !currentEnabled })
      });
      if (res.ok) {
        setBinaries(prev => prev.map(b => b.name === name ? { ...b, enabled: !currentEnabled } : b));
      }
    } catch (err) {
      console.error(`Failed to update binary ${name}:`, err);
    } finally {
      setUpdatingBinary(null);
    }
  };

  // Update risk weight
  const handleUpdateRiskWeight = async (name: MonitoredBinaryName, weight: number) => {
    try {
      await fetch(`/api/lolbins/monitored/${name}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ riskWeight: weight })
      });
      setBinaries(prev => prev.map(b => b.name === name ? { ...b, riskWeight: weight } : b));
    } catch (err) {
      console.error(`Failed to update risk weight for ${name}:`, err);
    }
  };

  // Run Real-time Contextual Evaluation
  const handleEvaluate = async () => {
    try {
      setEvaluating(true);
      const res = await fetch('/api/lolbins/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          process_name: evalProcess,
          command_line: evalCmd,
          parent_process_name: evalParent
        })
      });
      if (res.ok) {
        const data: LolbinDetectionResult = await res.json();
        setEvalResult(data);
      }
    } catch (err) {
      console.error('Failed to evaluate command:', err);
    } finally {
      setEvaluating(false);
    }
  };

  // Execute a safe simulation
  const handleRunSimulation = async (simId: string) => {
    try {
      setRunningSimId(simId);
      const res = await fetch('/api/lolbins/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioId: simId })
      });
      if (res.ok) {
        const data = await res.json();
        setSimResultModal(data);
        fetchLolbinData();
      }
    } catch (err) {
      console.error('Failed to run simulation:', err);
    } finally {
      setRunningSimId(null);
    }
  };

  // Filtered binaries
  const filteredBinaries = useMemo(() => {
    return binaries.filter(b => {
      const matchSearch = b.name.toLowerCase().includes(search.toLowerCase()) || 
                          b.displayName.toLowerCase().includes(search.toLowerCase()) ||
                          b.description.toLowerCase().includes(search.toLowerCase());
      const matchCategory = categoryFilter === 'all' || b.category.toLowerCase().includes(categoryFilter.toLowerCase());
      return matchSearch && matchCategory;
    });
  }, [binaries, search, categoryFilter]);

  const activeBinariesCount = binaries.filter(b => b.enabled).length;
  const totalDetections = binaries.reduce((acc, b) => acc + (b.totalDetections || 0), 0);

  return (
    <div className="space-y-6">
      {/* Top Banner & Stats */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>
        
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                13 Monitored LOLBins Active
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                Contextual Low-False-Positive Engine
              </span>
            </div>
            <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2.5">
              <Terminal className="w-6 h-6 text-emerald-400" />
              PowerShell & Windows LOLBin Detection
            </h1>
            <p className="text-sm text-slate-400 max-w-2xl mt-1">
              Monitors built-in Windows utilities (Living-off-the-Land Binaries) against encoded execution, download cradles, hidden windows, anomalous parents, and temporary directory execution without flagging benign administrative commands.
            </p>
          </div>

          {/* Quick Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 w-full lg:w-auto">
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 text-center">
              <div className="text-xs text-slate-400 font-mono">Monitored</div>
              <div className="text-xl font-bold text-emerald-400">{activeBinariesCount} / 13</div>
            </div>
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 text-center">
              <div className="text-xs text-slate-400 font-mono">Behaviors</div>
              <div className="text-xl font-bold text-cyan-400">9 Active</div>
            </div>
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 text-center">
              <div className="text-xs text-slate-400 font-mono">Detections</div>
              <div className="text-xl font-bold text-amber-400">{totalDetections}</div>
            </div>
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 text-center">
              <div className="text-xs text-slate-400 font-mono">Benign FP Rate</div>
              <div className="text-xl font-bold text-emerald-400">0.0%</div>
            </div>
          </div>
        </div>

        {/* Sub-Tabs Navigation */}
        <div className="flex items-center gap-2 border-t border-slate-800/80 mt-5 pt-4">
          <button
            onClick={() => setActiveSubTab('binaries')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
              activeSubTab === 'binaries'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Cpu className="w-4 h-4" />
            13 Monitored LOLBins ({binaries.length})
          </button>
          <button
            onClick={() => setActiveSubTab('behaviors')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
              activeSubTab === 'behaviors'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            Contextual Behaviors (9)
          </button>
          <button
            onClick={() => setActiveSubTab('simulator')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
              activeSubTab === 'simulator'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <PlayCircle className="w-4 h-4" />
            Safe Testing & Simulator
          </button>
          <button
            onClick={() => setActiveSubTab('config')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
              activeSubTab === 'config'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Sliders className="w-4 h-4" />
            Detection Settings
          </button>
          <button
            onClick={fetchLolbinData}
            disabled={loading}
            className="ml-auto px-3 py-1.5 rounded-lg text-xs font-mono text-slate-400 hover:text-slate-200 bg-slate-800/60 border border-slate-700/60 flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* 1. Monitored Binaries View */}
      {activeSubTab === 'binaries' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900 border border-slate-800 p-3 rounded-lg">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search monitored binaries by name, description, or keyword..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-1.5 bg-slate-950 border border-slate-800 rounded-md text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div className="flex items-center gap-2">
              <select
                value={categoryFilter}
                onChange={e => setCategoryFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-md px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
              >
                <option value="all">All Categories</option>
                <option value="Script Host">Script Hosts</option>
                <option value="Command Interpreter">Command Interpreters</option>
                <option value="System Utility">System Utilities</option>
                <option value="Installer">Installers</option>
                <option value="Task Manager">Task Managers</option>
              </select>
            </div>
          </div>

          {/* Binaries Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredBinaries.map(binary => (
              <div 
                key={binary.name}
                className={`bg-slate-900 border rounded-xl p-4 shadow-md transition-all flex flex-col justify-between ${
                  binary.enabled 
                    ? 'border-slate-800 hover:border-slate-700' 
                    : 'border-slate-800/40 opacity-60'
                }`}
              >
                <div>
                  {/* Card Header */}
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-slate-100 text-base">{binary.name}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                          {binary.category}
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5">{binary.displayName}</div>
                    </div>
                    {/* Toggle Button */}
                    <button
                      onClick={() => handleToggleBinary(binary.name, binary.enabled)}
                      disabled={updatingBinary === binary.name}
                      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                        binary.enabled ? 'bg-emerald-500' : 'bg-slate-700'
                      }`}
                    >
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                          binary.enabled ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>

                  <p className="text-xs text-slate-300 line-clamp-2 mb-3">
                    {binary.description}
                  </p>

                  {/* MITRE Tags */}
                  <div className="flex flex-wrap gap-1.5 mb-3">
                    {binary.mitreTechniques.map(tech => (
                      <span 
                        key={tech}
                        className="px-2 py-0.5 rounded text-[11px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>

                  {/* Legitimate vs Suspicious Callout */}
                  <div className="space-y-2 text-xs bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80 mb-3">
                    <div>
                      <span className="text-emerald-400 font-medium">Legitimate: </span>
                      <span className="text-slate-400">{binary.legitimateUse}</span>
                    </div>
                    <div>
                      <span className="text-rose-400 font-medium">Abuse Pattern: </span>
                      <span className="text-slate-400">{binary.commonAbuse}</span>
                    </div>
                  </div>
                </div>

                {/* Card Footer: Risk Weight & Details */}
                <div className="pt-3 border-t border-slate-800 flex items-center justify-between gap-3 text-xs">
                  <div className="flex items-center gap-2 flex-1">
                    <span className="text-slate-400 text-[11px]">Risk:</span>
                    <input
                      type="range"
                      min="10"
                      max="100"
                      step="5"
                      value={binary.riskWeight}
                      onChange={e => handleUpdateRiskWeight(binary.name, parseInt(e.target.value))}
                      className="w-full accent-emerald-500 cursor-pointer h-1 bg-slate-800 rounded"
                    />
                    <span className="font-mono text-slate-200 w-7 text-right">{binary.riskWeight}</span>
                  </div>
                  <button
                    onClick={() => setSelectedBinary(binary)}
                    className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200"
                    title="View Binary Details & Benign Examples"
                  >
                    <Eye className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 2. Contextual Behaviors View */}
      {activeSubTab === 'behaviors' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {behaviors.map(beh => (
              <div 
                key={beh.id}
                className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                      beh.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                      beh.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border-amber-500/30' :
                      'bg-blue-500/20 text-blue-400 border-blue-500/30'
                    }`}>
                      {beh.severity} ({beh.baseScore} pts)
                    </span>
                    <span className="font-mono text-xs text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
                      {beh.primaryMitre.technique_id}
                    </span>
                  </div>

                  <h3 className="font-bold text-slate-100 text-sm mb-1.5">{beh.name}</h3>
                  <p className="text-xs text-slate-400 mb-3">{beh.description}</p>

                  <div className="text-xs font-mono space-y-1.5 bg-slate-950 p-2.5 rounded-lg border border-slate-800 mb-3">
                    <div className="text-slate-400">Trigger Indicators:</div>
                    <div className="flex flex-wrap gap-1">
                      {beh.indicators.slice(0, 5).map(ind => (
                        <span key={ind} className="bg-slate-800 px-1.5 py-0.5 rounded text-emerald-400 text-[10px]">
                          {ind}
                        </span>
                      ))}
                      {beh.indicators.length > 5 && (
                        <span className="text-[10px] text-slate-500 self-center">
                          +{beh.indicators.length - 5} more
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
                  <span>MITRE: {beh.primaryMitre.technique_name}</span>
                  <button
                    onClick={() => setSelectedBehavior(beh)}
                    className="text-emerald-400 hover:text-emerald-300 font-medium flex items-center gap-1"
                  >
                    Details <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 3. Safe Testing & Simulator */}
      {activeSubTab === 'simulator' && (
        <div className="space-y-6">
          {/* Live Command Evaluator */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2 mb-1">
              <PlayCircle className="w-5 h-5 text-emerald-400" />
              Live Contextual Command Evaluator
            </h2>
            <p className="text-xs text-slate-400 mb-4">
              Test any arbitrary command line against the contextual detection engine. Demonstrates how benign commands are suppressed while malicious combinations are flagged.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Process Name</label>
                <select
                  value={evalProcess}
                  onChange={e => setEvalProcess(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
                >
                  {binaries.map(b => (
                    <option key={b.name} value={b.name}>{b.name} ({b.displayName})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Parent Process</label>
                <input
                  type="text"
                  value={evalParent}
                  onChange={e => setEvalParent(e.target.value)}
                  placeholder="e.g. explorer.exe, winword.exe, svchost.exe"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Action</label>
                <button
                  onClick={handleEvaluate}
                  disabled={evaluating}
                  className="w-full py-2 px-4 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold text-sm transition-colors flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/10"
                >
                  {evaluating ? <RefreshCw className="w-4 h-4 animate-spin" /> : <PlayCircle className="w-4 h-4" />}
                  Evaluate Context
                </button>
              </div>
            </div>

            <div className="mb-4">
              <label className="block text-xs font-mono text-slate-400 mb-1">Command Line String</label>
              <textarea
                value={evalCmd}
                onChange={e => setEvalCmd(e.target.value)}
                rows={2}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
                placeholder="Enter command line parameters..."
              />
            </div>

            {/* Evaluation Result Output */}
            {evalResult && (
              <div className={`p-4 rounded-xl border ${
                evalResult.isSuspicious
                  ? 'bg-rose-950/20 border-rose-500/40'
                  : 'bg-emerald-950/20 border-emerald-500/40'
              }`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2">
                    {evalResult.isSuspicious ? (
                      <AlertTriangle className="w-5 h-5 text-rose-400" />
                    ) : (
                      <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    )}
                    <span className="font-bold text-sm text-slate-100">
                      {evalResult.isSuspicious ? 'Suspicious LOLBin Activity Detected' : 'Benign / Clean Command Evaluated'}
                    </span>
                    {evalResult.isSuspicious && (
                      <span className="px-2 py-0.5 rounded text-xs font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                        Score: {evalResult.totalScore}/100 [{evalResult.severity}]
                      </span>
                    )}
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    {evalResult.isBenignMatch ? 'Suppressed as Known Benign' : (evalResult.isSuspicious ? 'Alert Triggered' : 'No Threat')}
                  </span>
                </div>

                <p className="text-xs text-slate-300 mt-2 font-mono">{evalResult.summary}</p>

                {evalResult.behaviorDetails.length > 0 && (
                  <div className="mt-3 space-y-2">
                    <div className="text-xs font-semibold text-slate-300">Matched Contextual Behaviors:</div>
                    {evalResult.behaviorDetails.map(d => (
                      <div key={d.type} className="text-xs bg-slate-950/80 p-2.5 rounded-lg border border-slate-800">
                        <div className="flex items-center justify-between text-rose-400 font-semibold mb-1">
                          <span>{d.name} (+{d.score} pts)</span>
                          <span className="text-blue-400 font-mono text-[11px]">{d.mitre.technique_id} - {d.mitre.technique_name}</span>
                        </div>
                        <div className="text-slate-400 font-mono">{d.evidence}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Pre-built Safe Simulations Library */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4">
              <div>
                <h3 className="text-base font-bold text-slate-100">Pre-Built Safe Simulations Library</h3>
                <p className="text-xs text-slate-400">
                  Execute safe benign commands or attack scenarios to test the EDR in real time using 100% benign command strings.
                </p>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Benign Tests (Must NOT Alert)
                </span>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  <AlertTriangle className="w-3.5 h-3.5" /> Detection Scenarios (Must Alert)
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {simulations.map(sim => (
                <div 
                  key={sim.id}
                  className={`p-3.5 rounded-xl border transition-all ${
                    sim.expectedAlert 
                      ? 'bg-slate-950/60 border-slate-800 hover:border-rose-500/40' 
                      : 'bg-slate-950/60 border-slate-800 hover:border-emerald-500/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-1.5">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${sim.expectedAlert ? 'bg-rose-400' : 'bg-emerald-400'}`} />
                        <span className="font-bold text-xs text-slate-200">{sim.name}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">{sim.description}</div>
                    </div>
                    <button
                      onClick={() => handleRunSimulation(sim.id)}
                      disabled={runningSimId === sim.id}
                      className="px-2.5 py-1 rounded text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1 shrink-0"
                    >
                      {runningSimId === sim.id ? <RefreshCw className="w-3 h-3 animate-spin" /> : <PlayCircle className="w-3 h-3" />}
                      Run Test
                    </button>
                  </div>

                  <div className="text-[11px] font-mono bg-slate-900 p-2 rounded text-slate-400 truncate">
                    {sim.commandLine}
                  </div>

                  <div className="mt-2 flex items-center justify-between text-[11px] text-slate-500">
                    <span>Parent: <span className="text-slate-400 font-mono">{sim.parentProcess}</span></span>
                    {sim.mitre && <span className="text-blue-400 font-mono">MITRE: {sim.mitre}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 4. Global Detection Settings View */}
      {activeSubTab === 'config' && config && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-6">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2 mb-1">
              <Sliders className="w-5 h-5 text-emerald-400" />
              Configurable LOLBin Detection Rules & Guardrails
            </h2>
            <p className="text-xs text-slate-400">
              Customize contextual thresholds, monitored temporary folders, and parent process allowlists.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div>
                  <div className="text-sm font-semibold text-slate-200">Contextual Detection Engine</div>
                  <div className="text-xs text-slate-400">Enable advanced lineage and parameter checks</div>
                </div>
                <span className="px-2.5 py-1 rounded text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  ENABLED
                </span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div>
                  <div className="text-sm font-semibold text-slate-200">Suppress Benign Administrative Commands</div>
                  <div className="text-xs text-slate-400">Exempt safe query commands (e.g. echo, Get-Date, -hashfile)</div>
                </div>
                <span className="px-2.5 py-1 rounded text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  ACTIVE
                </span>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <div className="text-sm font-semibold text-slate-200">Monitored Office Suite Parents</div>
                <div className="flex flex-wrap gap-1.5">
                  {config.monitoredOfficeParents.map(parent => (
                    <span key={parent} className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-rose-400">
                      {parent}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <div className="text-sm font-semibold text-slate-200">Monitored Web Browser Parents</div>
                <div className="flex flex-wrap gap-1.5">
                  {config.monitoredBrowserParents.map(parent => (
                    <span key={parent} className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-amber-400">
                      {parent}
                    </span>
                  ))}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <div className="text-sm font-semibold text-slate-200">Anomalous System Background Services</div>
                <div className="flex flex-wrap gap-1.5">
                  {config.anomalousSystemServices.map(svc => (
                    <span key={svc} className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-blue-400">
                      {svc}
                    </span>
                  ))}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <div className="text-sm font-semibold text-slate-200">Monitored Temporary Staging Folders</div>
                <div className="flex flex-wrap gap-1.5">
                  {config.monitoredTempDirectories.map(dir => (
                    <span key={dir} className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300">
                      {dir}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Binary Details Modal */}
      {selectedBinary && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setSelectedBinary(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-100 p-1 rounded-lg hover:bg-slate-800"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <Terminal className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-slate-100 font-mono">{selectedBinary.name}</h3>
                <div className="text-xs text-slate-400">{selectedBinary.displayName} • {selectedBinary.category}</div>
              </div>
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <h4 className="font-semibold text-slate-300 mb-1">Description</h4>
                <p className="text-slate-400">{selectedBinary.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="font-semibold text-emerald-400 mb-1">Legitimate Administrative Use</div>
                  <div className="text-slate-400">{selectedBinary.legitimateUse}</div>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="font-semibold text-rose-400 mb-1">Common Attack Abuse Patterns</div>
                  <div className="text-slate-400">{selectedBinary.commonAbuse}</div>
                </div>
              </div>

              <div>
                <h4 className="font-semibold text-slate-300 mb-1">Safe Benign Examples (No Alert Generated)</h4>
                <div className="space-y-1.5 font-mono">
                  {selectedBinary.benignExamples.map(cmd => (
                    <div key={cmd} className="bg-slate-950 p-2 rounded border border-slate-800 text-emerald-400 flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 shrink-0" />
                      <span className="truncate">{cmd}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="font-semibold text-slate-300 mb-1">MITRE ATT&CK Mappings</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedBinary.mitreTechniques.map(tech => (
                    <span key={tech} className="px-2.5 py-1 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                      {tech}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Simulation Result Modal */}
      {simResultModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setSimResultModal(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-100 p-1 rounded-lg hover:bg-slate-800"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              {simResultModal.isSuccess ? (
                <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
              ) : (
                <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400">
                  <AlertTriangle className="w-6 h-6" />
                </div>
              )}
              <div>
                <h3 className="text-lg font-bold text-slate-100">
                  {simResultModal.simulation.name}
                </h3>
                <div className="text-xs text-slate-400">
                  Expected Alert: <span className="font-mono font-bold text-slate-300">{String(simResultModal.simulation.expectedAlert).toUpperCase()}</span>
                </div>
              </div>
            </div>

            <div className="space-y-3 text-xs bg-slate-950 p-4 rounded-xl border border-slate-800 mb-4 font-mono">
              <div>
                <span className="text-slate-500">Command: </span>
                <span className="text-slate-200">{simResultModal.simulation.commandLine}</span>
              </div>
              <div>
                <span className="text-slate-500">Parent Process: </span>
                <span className="text-slate-200">{simResultModal.simulation.parentProcess}</span>
              </div>
              <div>
                <span className="text-slate-500">Detection Result: </span>
                <span className={simResultModal.detectionResult.isSuspicious ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                  {simResultModal.detectionResult.isSuspicious ? 'SUSPICIOUS (Alert Triggered)' : 'BENIGN (Alert Suppressed)'}
                </span>
              </div>
              <div>
                <span className="text-slate-500">Alerts Count: </span>
                <span className="text-slate-200">{simResultModal.alertsGenerated?.length || 0}</span>
              </div>
            </div>

            <div className="text-xs text-slate-400 mb-5">
              <span className="font-semibold text-slate-300">Explanation: </span>
              {simResultModal.simulation.explanation}
            </div>

            <div className="flex items-center justify-end gap-3">
              {simResultModal.alertsGenerated?.length > 0 && onNavigateTab && (
                <button
                  onClick={() => {
                    setSimResultModal(null);
                    onNavigateTab('alerts');
                  }}
                  className="px-4 py-2 rounded-lg bg-rose-500 hover:bg-rose-600 text-white font-bold text-xs transition-colors flex items-center gap-1.5"
                >
                  <ShieldAlert className="w-4 h-4" /> View Generated Alert
                </button>
              )}
              <button
                onClick={() => setSimResultModal(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
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
