import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Cpu, 
  HardDrive, 
  Terminal, 
  Grid3X3, 
  Sliders, 
  Database, 
  PlayCircle, 
  Layers,
  ScrollText,
  Network
} from 'lucide-react';
import { AgentStatus } from '../types';

interface HeaderProps {
  status: AgentStatus | null;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onRefresh: () => void;
  loading: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  status,
  activeTab,
  setActiveTab,
  onRefresh,
  loading
}) => {
  const tabs = [
    { id: 'overview', label: 'SOC Overview', icon: Activity },
    { id: 'processes', label: 'Processes', icon: Cpu },
    { id: 'network', label: 'Network Telemetry', icon: Network },
    { id: 'alerts', label: 'Alerts & Investigation', icon: ShieldAlert, badge: status?.metrics.activeAlerts },
    { id: 'lolbins', label: 'PowerShell & LOLBins', icon: Terminal },
    { id: 'windows-events', label: 'Windows Events & Schema', icon: ScrollText },
    { id: 'telemetry', label: 'Telemetry Stream', icon: Terminal },
    { id: 'mitre', label: 'MITRE ATT&CK Matrix', icon: Grid3X3 },
    { id: 'rules', label: 'Detection Rules', icon: Sliders, badge: status?.metrics.activeRules },
    { id: 'threat-intel', label: 'Threat Intel', icon: Database },
    { id: 'simulations', label: 'Safe Simulations', icon: PlayCircle },
    { id: 'service', label: 'Service & Setup', icon: Layers }
  ];

  return (
    <header className="bg-slate-900 border-b border-slate-800 text-slate-100 sticky top-0 z-40">
      {/* Top Bar with Real-time System Metrics */}
      <div className="max-w-7xl mx-auto px-4 py-2.5 flex flex-wrap items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-base tracking-tight text-white">LocalEDR</h1>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                v1.0.0 Local
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {status?.agent.platform === 'win32' ? 'Windows Service' : 'Autonomous Engine'}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Host: <span className="text-slate-300">{status?.agent.hostname || 'WIN-ENDPOINT'}</span> • Local SQLite WAL
            </p>
          </div>
        </div>

        {/* Real-time System Metrics Badges (Rule 5 & Rule 20) */}
        <div className="flex items-center gap-2 sm:gap-4 text-xs font-mono">
          <div className="bg-slate-950/80 px-2.5 py-1.5 rounded border border-slate-800 flex items-center gap-2">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <div>
              <span className="text-slate-400 text-[10px] block leading-none">AGENT CPU</span>
              <span className="text-cyan-300 font-semibold">{status?.metrics.cpuUsagePercent ?? 0.2}%</span>
            </div>
          </div>

          <div className="bg-slate-950/80 px-2.5 py-1.5 rounded border border-slate-800 flex items-center gap-2">
            <HardDrive className="w-3.5 h-3.5 text-indigo-400" />
            <div>
              <span className="text-slate-400 text-[10px] block leading-none">RAM / DB</span>
              <span className="text-indigo-300 font-semibold">
                {status?.metrics.rssMemoryMb ?? 42} MB / {status?.metrics.databaseSizeFormatted ?? '48 KB'}
              </span>
            </div>
          </div>

          <div className="bg-slate-950/80 px-2.5 py-1.5 rounded border border-slate-800 flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
            <div>
              <span className="text-slate-400 text-[10px] block leading-none">EVENTS INGESTED</span>
              <span className="text-emerald-300 font-semibold">{status?.metrics.totalEvents ?? 0}</span>
            </div>
          </div>

          <button
            onClick={onRefresh}
            disabled={loading}
            className="px-2 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition flex items-center gap-1 text-xs cursor-pointer disabled:opacity-50"
            title="Refresh telemetry"
          >
            <Activity className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            <span className="hidden sm:inline">Sync</span>
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="max-w-7xl mx-auto px-4 flex items-center gap-1 overflow-x-auto border-t border-slate-800/80 scrollbar-none">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3 py-2 text-xs font-medium border-b-2 transition whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'border-emerald-500 text-emerald-400 bg-slate-800/40'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/20'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
              {typeof tab.badge === 'number' && tab.badge > 0 && (
                <span
                  className={`px-1.5 py-0.2 text-[10px] rounded-full font-mono font-bold ${
                    tab.id === 'alerts'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                      : 'bg-slate-700 text-slate-300'
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </header>
  );
};
