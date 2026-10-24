import React from 'react';
import { PlayCircle, ShieldCheck, CheckCircle2, AlertTriangle, ArrowRight, Zap } from 'lucide-react';
import { SimulationItem } from '../types';

interface SimulationsViewProps {
  simulations: SimulationItem[];
  onRunSimulation: (simId: string) => void;
  runningSimId: string | null;
  lastSimResult: any;
  onNavigateAlerts: () => void;
}

export const SimulationsView: React.FC<SimulationsViewProps> = ({
  simulations,
  onRunSimulation,
  runningSimId,
  lastSimResult,
  onNavigateAlerts
}) => {
  return (
    <div className="space-y-5">
      {/* Top Banner: Safe Defensive Testing Protocol */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-2">
        <div className="flex items-center gap-2 text-emerald-400">
          <ShieldCheck className="w-5 h-5" />
          <h2 className="font-bold text-white text-base">Safe Endpoint Attack Simulations (Rule 12 &amp; 13)</h2>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">
          To verify detection heuristics and alert pipelines safely, LocalEDR includes an Atomic Red Team style simulation harness. 
          These test events mimic known adversary tradecraft (e.g. LOLBAS syntax, encoded commands, autostart persistence) using completely benign payloads. 
          No malicious binaries or hostile payloads are ever executed on the system.
        </p>
      </div>

      {/* Execution Feedback Banner */}
      {lastSimResult && (
        <div className="p-4 bg-emerald-950/30 border border-emerald-500/50 rounded-xl flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-6 h-6 text-emerald-400 flex-shrink-0" />
            <div className="text-xs font-mono">
              <div className="font-bold text-white">
                Simulation Executed: {lastSimResult.simulationName}
              </div>
              <div className="text-emerald-300 mt-0.5">
                Ingested Event #{lastSimResult.eventId} &bull; Generated {lastSimResult.alertsGenerated.length} Alert(s)
              </div>
            </div>
          </div>
          <button
            onClick={onNavigateAlerts}
            className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-1.5 shadow-lg shadow-emerald-950 cursor-pointer"
          >
            Investigate Alert &rarr;
          </button>
        </div>
      )}

      {/* Simulations Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {simulations.map((sim) => {
          const isRunning = runningSimId === sim.id;
          return (
            <div
              key={sim.id}
              className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-4 flex flex-col justify-between transition space-y-3"
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-emerald-400">
                    {sim.id}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                    Target: {sim.targetRule}
                  </span>
                </div>
                <h3 className="font-semibold text-sm text-white">{sim.name}</h3>
                <div className="text-xs font-mono text-cyan-400">{sim.technique}</div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {sim.description}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-500">Safe • Non-harmful</span>
                <button
                  onClick={() => onRunSimulation(sim.id)}
                  disabled={isRunning}
                  className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-emerald-600 text-slate-200 hover:text-white border border-slate-700 transition font-mono text-xs font-medium flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                >
                  <PlayCircle className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin text-emerald-400' : ''}`} />
                  {isRunning ? 'Injecting...' : 'Trigger Safe Event'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
