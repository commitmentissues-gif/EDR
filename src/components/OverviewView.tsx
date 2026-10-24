import React from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Terminal, 
  PlayCircle, 
  ChevronRight, 
  Layers, 
  Server,
  Zap,
  ScrollText
} from 'lucide-react';
import { AgentStatus, Alert, SimulationItem } from '../types';

interface OverviewViewProps {
  status: AgentStatus | null;
  alerts: Alert[];
  simulations: SimulationItem[];
  onSelectAlert: (alert: Alert) => void;
  onRunSimulation: (simId: string) => void;
  runningSimId: string | null;
  onNavigateTab: (tab: string) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  status,
  alerts,
  simulations,
  onSelectAlert,
  onRunSimulation,
  runningSimId,
  onNavigateTab
}) => {
  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severity === 'HIGH').length;
  const mediumCount = alerts.filter(a => a.severity === 'MEDIUM').length;
  const lowCount = alerts.filter(a => a.severity === 'LOW' || a.severity === 'INFO').length;

  const newAlerts = alerts.filter(a => a.status === 'NEW').slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Top Banner: Local & Autonomous Defense Mode */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden">
        <div className="absolute right-0 top-0 bottom-0 w-96 bg-gradient-to-l from-emerald-500/5 to-transparent pointer-events-none" />
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <CheckCircle2 className="w-3.5 h-3.5" />
                ENDPOINT SHIELD ACTIVE
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Host: <span className="text-white font-medium">{status?.agent.hostname || 'WIN-ENDPOINT'}</span>
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              Autonomous Defensive Endpoint Detection & Response
            </h2>
            <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
              Real-time Windows telemetry correlation running locally with zero cloud dependencies. High-fidelity Sysmon ETW stream analysis, MITRE ATT&amp;CK mapping, and local SQLite audit trails.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => onNavigateTab('lolbins')}
              className="px-3.5 py-2 rounded-lg bg-emerald-600/30 hover:bg-emerald-600/40 text-emerald-200 border border-emerald-500/40 font-medium text-xs flex items-center gap-2 transition cursor-pointer"
            >
              <Terminal className="w-4 h-4 text-emerald-400" />
              PowerShell & LOLBins
            </button>
            <button
              onClick={() => onNavigateTab('windows-events')}
              className="px-3.5 py-2 rounded-lg bg-indigo-600/30 hover:bg-indigo-600/40 text-indigo-200 border border-indigo-500/40 font-medium text-xs flex items-center gap-2 transition cursor-pointer"
            >
              <ScrollText className="w-4 h-4 text-indigo-400" />
              Windows Event Logs
            </button>
            <button
              onClick={() => onNavigateTab('simulations')}
              className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs flex items-center gap-2 shadow-lg shadow-emerald-950 transition cursor-pointer"
            >
              <PlayCircle className="w-4 h-4" />
              Run Safe Test Event
            </button>
            <button
              onClick={() => onNavigateTab('service')}
              className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-xs flex items-center gap-2 transition cursor-pointer"
            >
              <Server className="w-4 h-4" />
              Service Commands
            </button>
          </div>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Active Threats */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Active Alerts</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white">
              {status?.metrics.activeAlerts ?? 0}
            </span>
            <span className="text-xs text-slate-400 font-mono">
              of {status?.metrics.totalAlerts ?? 0} total
            </span>
          </div>
          <div className="mt-3 flex items-center gap-2 text-[11px] font-mono">
            <span className="text-rose-400 font-semibold">{criticalCount} Critical</span>
            <span className="text-slate-600">•</span>
            <span className="text-amber-400 font-semibold">{highCount} High</span>
          </div>
        </div>

        {/* Telemetry Throughput */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Telemetry Events</span>
            <Terminal className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-cyan-300">
              {status?.metrics.totalEvents ?? 0}
            </span>
            <span className="text-xs text-slate-400 font-mono">events logged</span>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 font-mono flex items-center justify-between">
            <span>Sysmon + Baseline</span>
            <span className="text-emerald-400">Stream Live</span>
          </div>
        </div>

        {/* Detection Rules */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Detection Rules</span>
            <Layers className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-emerald-300">
              {status?.metrics.activeRules ?? 0}
            </span>
            <span className="text-xs text-slate-400 font-mono">
              / {status?.metrics.totalRules ?? 0} enabled
            </span>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 font-mono flex items-center justify-between">
            <span>MITRE Mapped</span>
            <span className="text-emerald-400 font-semibold">100%</span>
          </div>
        </div>

        {/* System Footprint (Rule 5 & 20) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Laptop Resource Use</span>
            <Zap className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-indigo-300">
              {status?.metrics.rssMemoryMb ?? 42} <span className="text-sm font-normal text-slate-400">MB</span>
            </span>
            <span className="text-xs text-slate-400 font-mono">
              CPU: {status?.metrics.cpuUsagePercent ?? 0.2}%
            </span>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 font-mono flex items-center justify-between">
            <span>Local SQLite:</span>
            <span className="text-slate-300">{status?.metrics.databaseSizeFormatted ?? '48 KB'}</span>
          </div>
        </div>
      </div>

      {/* Main Split: Recent Detections & Quick Safe Simulations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Recent High Priority Detections (2 Columns) */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Recent Detections &amp; Alerts
              </h3>
              <p className="text-xs text-slate-400">
                Click any alert to launch the forensic investigation drawer with process tree lineage.
              </p>
            </div>
            <button
              onClick={() => onNavigateTab('alerts')}
              className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 font-medium cursor-pointer"
            >
              View All ({alerts.length})
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {newAlerts.length === 0 ? (
            <div className="text-center py-10 border border-dashed border-slate-800 rounded-lg">
              <CheckCircle2 className="w-8 h-8 text-emerald-400/80 mx-auto mb-2" />
              <p className="text-sm font-medium text-slate-300">Endpoint Telemetry Clean</p>
              <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
                No active threats detected. Trigger a safe simulated event to test the detection engine.
              </p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {newAlerts.map((alert) => {
                const isCrit = alert.severity === 'CRITICAL';
                const isHigh = alert.severity === 'HIGH';
                const isMed = alert.severity === 'MEDIUM';

                return (
                  <div
                    key={alert.id}
                    onClick={() => onSelectAlert(alert)}
                    className="p-3 bg-slate-950/70 hover:bg-slate-800/60 border border-slate-800/90 hover:border-slate-700 rounded-lg transition cursor-pointer group"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1 flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                              isCrit
                                ? 'bg-rose-950 text-rose-400 border border-rose-800'
                                : isHigh
                                ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                : isMed
                                ? 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                                : 'bg-slate-800 text-slate-300 border border-slate-700'
                            }`}
                          >
                            {alert.severity}
                          </span>
                          <span className="text-xs font-semibold text-slate-200 group-hover:text-emerald-400 transition truncate">
                            {alert.title}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                            {alert.mitre_technique_id}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 line-clamp-1 font-mono">
                          {alert.why_triggered}
                        </p>
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono whitespace-nowrap">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right: Quick Safe Simulation Suite (Rule 13) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div>
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <PlayCircle className="w-4 h-4 text-emerald-400" />
                Safe Test Triggers
              </h3>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                Rule 13 Safe
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Verify detection rules instantly using non-harmful simulated events.
            </p>
          </div>

          <div className="space-y-2">
            {simulations.slice(0, 4).map((sim) => (
              <div
                key={sim.id}
                className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-center justify-between gap-3 text-xs"
              >
                <div className="min-w-0 flex-1">
                  <div className="font-medium text-slate-200 truncate">{sim.name}</div>
                  <div className="text-[10px] font-mono text-slate-400">{sim.technique}</div>
                </div>
                <button
                  onClick={() => onRunSimulation(sim.id)}
                  disabled={runningSimId === sim.id}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-emerald-600 text-slate-200 hover:text-white border border-slate-700 transition font-mono text-[11px] flex items-center gap-1 cursor-pointer disabled:opacity-50"
                >
                  <PlayCircle className={`w-3 h-3 ${runningSimId === sim.id ? 'animate-spin' : ''}`} />
                  Test
                </button>
              </div>
            ))}
          </div>

          <button
            onClick={() => onNavigateTab('simulations')}
            className="w-full py-2 rounded-lg bg-slate-800/60 hover:bg-slate-800 text-slate-300 border border-slate-700/60 text-xs font-medium transition cursor-pointer"
          >
            Open Full Simulation Center &rarr;
          </button>
        </div>
      </div>
    </div>
  );
};
