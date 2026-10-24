import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Terminal, 
  GitBranch, 
  ExternalLink, 
  Check, 
  X, 
  Play, 
  CheckCircle,
  FileText,
  Sliders,
  Clock,
  FolderSync,
  Network
} from 'lucide-react';
import { Alert, ProcessNode, ScoreFactorContribution, RiskScoreCalculation } from '../types';
import { RiskScoringModal } from './RiskScoringModal';

interface AlertsViewProps {
  alerts: Alert[];
  selectedAlert: Alert | null;
  onSelectAlert: (alert: Alert | null) => void;
  onUpdateAlertStatus: (alertId: string, status: string) => void;
  onRequestResponseAction: (alertId: string, actionType: string, target: string, details: string) => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  selectedAlert,
  onSelectAlert,
  onUpdateAlertStatus,
  onRequestResponseAction
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isScoringModalOpen, setIsScoringModalOpen] = useState<boolean>(false);
  
  // Staged Response Action Modal State (Rule 10)
  const [stagedAction, setStagedAction] = useState<{
    actionType: string;
    target: string;
    details: string;
  } | null>(null);

  // Incident Timeline with Correlated File and Network Activity
  const [incidentTimeline, setIncidentTimeline] = useState<any[]>([]);

  useEffect(() => {
    if (!selectedAlert?.id) {
      setIncidentTimeline([]);
      return;
    }
    fetch(`/api/filesystem/timeline?alertId=${selectedAlert.id}`)
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          setIncidentTimeline(data);
        }
      })
      .catch(() => {});
  }, [selectedAlert?.id]);

  const filteredAlerts = alerts.filter(alert => {
    if (severityFilter !== 'all' && alert.severity !== severityFilter) return false;
    if (statusFilter !== 'all' && alert.status !== statusFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        alert.title.toLowerCase().includes(q) ||
        alert.why_triggered.toLowerCase().includes(q) ||
        alert.mitre_technique_id.toLowerCase().includes(q) ||
        alert.mitre_technique_name.toLowerCase().includes(q)
      );
    }
    return true;
  });

  // Parse process lineage for selected alert
  let lineageNodes: ProcessNode[] = [];
  if (selectedAlert?.process_lineage_json) {
    try {
      lineageNodes = JSON.parse(selectedAlert.process_lineage_json);
    } catch {
      lineageNodes = [];
    }
  }

  // Parse forensic evidence used for selected alert
  let evidenceData: any = null;
  if (selectedAlert?.evidence_json) {
    try {
      evidenceData = JSON.parse(selectedAlert.evidence_json);
    } catch {
      evidenceData = null;
    }
  }

  // Parse transparent score factors and calculation for selected alert
  let scoreFactors: ScoreFactorContribution[] = [];
  if (selectedAlert?.score_factors_json) {
    try {
      scoreFactors = JSON.parse(selectedAlert.score_factors_json);
    } catch {
      scoreFactors = [];
    }
  }

  let scoreCalc: RiskScoreCalculation | null = null;
  if (selectedAlert?.score_calculation_json) {
    try {
      scoreCalc = JSON.parse(selectedAlert.score_calculation_json);
    } catch {
      scoreCalc = null;
    }
  }

  const handleStageAction = (actionType: string, target: string, details: string) => {
    setStagedAction({ actionType, target, details });
  };

  const handleConfirmAction = () => {
    if (stagedAction && selectedAlert) {
      onRequestResponseAction(
        selectedAlert.id,
        stagedAction.actionType,
        stagedAction.target,
        stagedAction.details
      );
      setStagedAction(null);
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Filter Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-wrap">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search alerts, techniques, processes..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-64 font-mono"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-1 rounded text-[11px] font-mono font-medium transition cursor-pointer ${
                  severityFilter === sev
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            {['all', 'NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2 py-1 rounded text-[11px] font-mono font-medium transition cursor-pointer ${
                  statusFilter === st
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsScoringModalOpen(true)}
            className="px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 text-emerald-400 hover:text-emerald-300 border border-slate-800 hover:border-emerald-500/50 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer shadow-sm"
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Risk Scoring Engine</span>
          </button>
          <div className="text-xs font-mono text-slate-400">
            Showing <span className="text-white font-semibold">{filteredAlerts.length}</span> alerts
          </div>
        </div>
      </div>

      {/* Split View: Alert List & Investigation Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Alerts Table */}
        <div className={`space-y-2 ${selectedAlert ? 'lg:col-span-6' : 'lg:col-span-12'}`}>
          {filteredAlerts.length === 0 ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center">
              <ShieldAlert className="w-10 h-10 text-slate-600 mx-auto mb-2" />
              <p className="text-sm font-medium text-slate-300">No alerts match current criteria</p>
              <p className="text-xs text-slate-500 mt-1">Adjust filters or trigger safe simulations to test detection rules.</p>
            </div>
          ) : (
            filteredAlerts.map((alert) => {
              const isSelected = selectedAlert?.id === alert.id;
              const isCrit = alert.severity === 'CRITICAL';
              const isHigh = alert.severity === 'HIGH';
              const isMed = alert.severity === 'MEDIUM';

              return (
                <div
                  key={alert.id}
                  onClick={() => onSelectAlert(alert)}
                  className={`p-4 rounded-xl border transition cursor-pointer ${
                    isSelected
                      ? 'bg-slate-850 border-emerald-500/80 shadow-md ring-1 ring-emerald-500/30'
                      : 'bg-slate-900 hover:bg-slate-850/80 border-slate-800'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1.5 flex-1 min-w-0">
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
                        <span className="font-semibold text-sm text-slate-100 hover:text-emerald-400 transition truncate">
                          {alert.title}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-emerald-400 border border-slate-800">
                          {alert.mitre_technique_id}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                            alert.status === 'NEW'
                              ? 'bg-rose-500/10 text-rose-400'
                              : alert.status === 'RESOLVED'
                              ? 'bg-emerald-500/10 text-emerald-400'
                              : 'bg-amber-500/10 text-amber-400'
                          }`}
                        >
                          {alert.status}
                        </span>
                        {(() => {
                          let isLive = false;
                          try {
                            if (alert.details_json) {
                              const parsed = JSON.parse(alert.details_json);
                              isLive = parsed.event_snapshot?.source === 'sysmon_live' || parsed.event_snapshot?.source === 'sysmon_agent';
                            }
                          } catch {}
                          return isLive ? (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/70 flex items-center gap-1 shadow-xs">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                              <span>Live Endpoint</span>
                            </span>
                          ) : (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded font-medium bg-purple-950/80 text-purple-300 border border-purple-800">
                              Simulated
                            </span>
                          );
                        })()}
                      </div>

                      {/* Forensic Summary Preview (Rule 18) */}
                      <p className="text-xs text-slate-400 font-mono line-clamp-2">
                        {alert.why_triggered}
                      </p>
                    </div>

                    <div className="text-right text-[11px] font-mono text-slate-400 whitespace-nowrap">
                      <div>{new Date(alert.timestamp).toLocaleTimeString()}</div>
                      <div className="text-[10px] text-slate-400">{alert.rule_id}</div>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Forensic Investigation Drawer */}
        {selectedAlert && (
          <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-5 sticky top-20">
            {/* Header & Close */}
            <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-emerald-400 font-semibold">
                    {selectedAlert.id}
                  </span>
                  <span className="text-xs text-slate-400">•</span>
                  <span className="text-xs font-mono text-slate-400">
                    {new Date(selectedAlert.timestamp).toLocaleString()}
                  </span>
                  {(() => {
                    let isLive = false;
                    try {
                      if (selectedAlert.details_json) {
                        const parsed = JSON.parse(selectedAlert.details_json);
                        isLive = parsed.event_snapshot?.source === 'sysmon_live' || parsed.event_snapshot?.source === 'sysmon_agent';
                      }
                    } catch {}
                    return isLive ? (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/70 flex items-center gap-1 shadow-xs ml-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                        <span>Genuine Endpoint Telemetry</span>
                      </span>
                    ) : (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded font-medium bg-purple-950/80 text-purple-300 border border-purple-800 ml-2">
                        Simulated Attack Scenario
                      </span>
                    );
                  })()}
                </div>
                <h3 className="text-base font-bold text-white mt-1">
                  {selectedAlert.title}
                </h3>
              </div>
              <button
                onClick={() => onSelectAlert(null)}
                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Transparent Risk-Scoring Engine Card */}
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-slate-300">Transparent Risk Scoring Breakdown</span>
                  <button
                    onClick={() => setIsScoringModalOpen(true)}
                    className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 font-mono transition cursor-pointer flex items-center gap-1"
                    title="Inspect & Configure Risk Scoring Weights"
                  >
                    <Sliders className="w-3 h-3" />
                    <span>Configure Weights</span>
                  </button>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono ${
                      (selectedAlert.risk_level === 'Critical' || selectedAlert.severity === 'CRITICAL')
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : (selectedAlert.risk_level === 'High' || selectedAlert.severity === 'HIGH')
                        ? 'bg-amber-950 text-amber-300 border border-amber-800'
                        : (selectedAlert.risk_level === 'Medium' || selectedAlert.severity === 'MEDIUM')
                        ? 'bg-yellow-950 text-yellow-300 border border-yellow-800'
                        : (selectedAlert.risk_level === 'Low' || selectedAlert.severity === 'LOW')
                        ? 'bg-blue-950 text-blue-300 border border-blue-800'
                        : 'bg-slate-850 text-slate-300 border border-slate-700'
                    }`}
                  >
                    Risk Level: {selectedAlert.risk_level || 'Medium'}
                  </span>
                  <span className="text-xs font-mono font-bold text-white bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
                    Final Score: {selectedAlert.score ?? 50}/100
                  </span>
                </div>
              </div>

              {/* Score Bar with Max 100 Indicator */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <span>Base Score: {selectedAlert.base_score ?? 0}</span>
                  <span>
                    {scoreCalc?.is_clamped && (
                      <span className="text-rose-400 font-semibold mr-2">Raw {scoreCalc.raw_score} clamped to max 100</span>
                    )}
                    Max Score: 100
                  </span>
                </div>
                <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                  <div
                    className={`h-full transition-all duration-500 rounded-full ${
                      (selectedAlert.score ?? 50) >= 80
                        ? 'bg-rose-500'
                        : (selectedAlert.score ?? 50) >= 60
                        ? 'bg-amber-500'
                        : (selectedAlert.score ?? 50) >= 40
                        ? 'bg-yellow-500'
                        : (selectedAlert.score ?? 50) >= 20
                        ? 'bg-blue-500'
                        : 'bg-slate-400'
                    }`}
                    style={{ width: `${Math.min(100, Math.max(5, selectedAlert.score ?? 50))}%` }}
                  />
                </div>
              </div>

              {/* Individual Score Factors List */}
              <div className="space-y-1.5 pt-1">
                <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Individual Score Factors
                </div>
                {scoreFactors.length > 0 ? (
                  <div className="space-y-1.5">
                    {scoreFactors.map((f, idx) => (
                      <div
                        key={idx}
                        className="flex items-start justify-between gap-2 p-2 rounded bg-slate-900 border border-slate-800/80 text-xs font-mono"
                      >
                        <div className="space-y-0.5">
                          <div className="text-slate-200 font-medium flex items-center gap-1.5">
                            <span className="text-emerald-400 font-bold">+{f.points}</span>
                            <span>{f.name}</span>
                          </div>
                          <div className="text-[11px] text-slate-400 leading-tight">
                            {f.reason}
                          </div>
                        </div>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800 shrink-0">
                          +{f.points} pts
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-2 rounded bg-slate-900 border border-slate-800/80 text-xs text-slate-400 font-mono">
                    No individual factors recorded (Rule baseline applied: {selectedAlert.score ?? 50} pts)
                  </div>
                )}
              </div>

              {/* Transparent Calculation Formula */}
              {scoreCalc?.breakdown && (
                <div className="p-2 rounded bg-slate-900/60 border border-slate-800 text-[11px] font-mono text-slate-300">
                  <span className="text-slate-500">Formula:</span> {scoreCalc.breakdown}
                </div>
              )}
            </div>

            {/* Forensic Risk & Rule Banner */}
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400">Triggered Detection Rule</span>
                <span className="text-xs font-mono text-slate-400">ID: {selectedAlert.rule_id}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-emerald-400">{selectedAlert.rule_id}</span>
                <span className="text-slate-400">•</span>
                <span className="text-xs text-slate-200 font-medium">{selectedAlert.rule_name}</span>
              </div>
            </div>

            {/* Rule 18: Forensic "Why It Triggered" Card */}
            <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-lg p-3.5 space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
                <FileText className="w-3.5 h-3.5" />
                <span>Detection Rationale (Why Triggered)</span>
              </div>
              <p className="text-xs text-slate-200 font-mono leading-relaxed">
                {selectedAlert.why_triggered}
              </p>
            </div>

            {/* Forensic Evidence Used Panel */}
            {evidenceData && (
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-cyan-400">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Evidence Used in Detection</span>
                </div>
                <div className="space-y-1.5 font-mono text-xs">
                  {evidenceData.matched_criteria && Array.isArray(evidenceData.matched_criteria) && (
                    <div className="space-y-1">
                      {evidenceData.matched_criteria.map((crit: string, i: number) => (
                        <div key={i} className="flex items-start gap-1.5 text-slate-300">
                          <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                          <span>{crit}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {evidenceData.process_name && (
                    <div className="p-1.5 rounded bg-slate-900 border border-slate-800/80 text-[11px]">
                      <span className="text-slate-400">Process Name:</span> <span className="text-emerald-300">{evidenceData.process_name}</span>
                    </div>
                  )}
                  {evidenceData.parent_process && (
                    <div className="p-1.5 rounded bg-slate-900 border border-slate-800/80 text-[11px]">
                      <span className="text-slate-400">Parent Process:</span> <span className="text-cyan-300">{evidenceData.parent_process}</span>
                    </div>
                  )}
                  {evidenceData.command_line && (
                    <div className="p-1.5 rounded bg-slate-900 border border-slate-800/80 text-[11px] break-all">
                      <span className="text-slate-400">Command Line:</span> <span className="text-slate-200">{evidenceData.command_line}</span>
                    </div>
                  )}
                  {evidenceData.executable_path && (
                    <div className="p-1.5 rounded bg-slate-900 border border-slate-800/80 text-[11px] break-all">
                      <span className="text-slate-400">Executable Path:</span> <span className="text-amber-300">{evidenceData.executable_path}</span>
                    </div>
                  )}
                  {evidenceData.hash && (
                    <div className="p-1.5 rounded bg-slate-900 border border-slate-800/80 text-[11px] break-all">
                      <span className="text-slate-400">Hash:</span> <span className="text-rose-300">{evidenceData.hash}</span>
                    </div>
                  )}
                  {evidenceData.username && (
                    <div className="p-1.5 rounded bg-slate-900 border border-slate-800/80 text-[11px]">
                      <span className="text-slate-400">Security Principal:</span> <span className="text-indigo-300">{evidenceData.username}</span>
                    </div>
                  )}
                  {evidenceData.process_relationships && (
                    <div className="p-1.5 rounded bg-slate-900 border border-slate-800/80 text-[11px]">
                      <span className="text-slate-400">Relationship Evidence:</span> <span className="text-purple-300">{evidenceData.process_relationships}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Recommended Action Card */}
            {selectedAlert.recommended_action && (
              <div className="bg-amber-950/20 border border-amber-500/30 rounded-lg p-3.5 space-y-1.5">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-400">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Recommended Action &amp; Remediation</span>
                </div>
                <p className="text-xs text-slate-200 leading-relaxed font-mono">
                  {selectedAlert.recommended_action}
                </p>
              </div>
            )}

            {/* MITRE ATT&CK Context Card (Rule 19) */}
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400 font-mono">MITRE ATT&amp;CK Mapping</span>
                <a
                  href={`https://attack.mitre.org/techniques/${selectedAlert.mitre_technique_id.replace('.', '/')}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-emerald-400 hover:underline flex items-center gap-1 font-mono text-[11px]"
                >
                  attack.mitre.org <ExternalLink className="w-3 h-3" />
                </a>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <div className="px-2 py-1 bg-slate-900 border border-slate-800 rounded text-xs font-mono text-slate-300">
                  Tactic: <span className="text-emerald-400 font-medium">{selectedAlert.mitre_tactic}</span>
                </div>
                <div className="px-2 py-1 bg-slate-900 border border-slate-800 rounded text-xs font-mono text-slate-300">
                  Technique: <span className="text-emerald-400 font-medium">{selectedAlert.mitre_technique_id} - {selectedAlert.mitre_technique_name}</span>
                </div>
                {(selectedAlert.mitre_subtechnique_id || selectedAlert.mitre_technique_id.includes('.')) && (
                  <div className="px-2 py-1 bg-cyan-950/40 border border-cyan-800/60 rounded text-xs font-mono text-slate-300">
                    Sub-technique: <span className="text-cyan-300 font-medium">{selectedAlert.mitre_subtechnique_id || selectedAlert.mitre_technique_id}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Process Tree Lineage Visualizer */}
            {lineageNodes.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300">
                  <GitBranch className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Process Lineage &amp; Execution Tree</span>
                </div>
                <div className="space-y-2 font-mono text-xs">
                  {lineageNodes.map((node, idx) => (
                    <div
                      key={idx}
                      className={`p-3 rounded-lg border ${
                        node.role === 'parent'
                          ? 'bg-slate-950/60 border-slate-800 ml-0'
                          : 'bg-slate-950 border-rose-500/30 ml-4 ring-1 ring-rose-500/20'
                      }`}
                    >
                      <div className="flex items-center justify-between text-[11px] mb-1">
                        <span className="font-semibold text-slate-300 flex items-center gap-1">
                          {node.role === 'parent' ? 'Parent Process' : 'Target / Triggered Process'}
                          <span className="text-slate-500">• PID {node.process_id}</span>
                        </span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                          {node.process_name}
                        </span>
                      </div>
                      {node.command_line && (
                        <div className="mt-1 p-1.5 rounded bg-slate-900 text-slate-300 text-[11px] break-all border border-slate-800/80">
                          {node.command_line}
                        </div>
                      )}
                      {node.file_hash && (
                        <div className="mt-1 text-[10px] text-slate-400 truncate">
                          SHA256: <span className="text-slate-300">{node.file_hash}</span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Status Workflow Controls */}
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <span className="text-xs font-semibold text-slate-400 block">Incident Status</span>
              <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                <button
                  onClick={() => onUpdateAlertStatus(selectedAlert.id, 'INVESTIGATING')}
                  className={`py-1.5 rounded border transition cursor-pointer ${
                    selectedAlert.status === 'INVESTIGATING'
                      ? 'bg-amber-950 border-amber-600 text-amber-300'
                      : 'bg-slate-950 border-slate-800 hover:bg-slate-800 text-slate-300'
                  }`}
                >
                  Investigating
                </button>
                <button
                  onClick={() => onUpdateAlertStatus(selectedAlert.id, 'RESOLVED')}
                  className={`py-1.5 rounded border transition cursor-pointer ${
                    selectedAlert.status === 'RESOLVED'
                      ? 'bg-emerald-950 border-emerald-600 text-emerald-300'
                      : 'bg-slate-950 border-slate-800 hover:bg-slate-800 text-slate-300'
                  }`}
                >
                  Resolved
                </button>
                <button
                  onClick={() => onUpdateAlertStatus(selectedAlert.id, 'FALSE_POSITIVE')}
                  className={`py-1.5 rounded border transition cursor-pointer ${
                    selectedAlert.status === 'FALSE_POSITIVE'
                      ? 'bg-slate-800 border-slate-600 text-slate-300'
                      : 'bg-slate-950 border-slate-800 hover:bg-slate-800 text-slate-400'
                  }`}
                >
                  False Positive
                </button>
              </div>
            </div>

            {/* Defensive Response Actions (Rule 10: Explicit Confirmation Required) */}
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                  Staged Defensive Actions
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                  Rule 10 Confirmation Req.
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <button
                  onClick={() => {
                    const targetNode = lineageNodes.find(n => n.role === 'target');
                    handleStageAction(
                      'KILL_PROCESS',
                      targetNode ? `PID ${targetNode.process_id} (${targetNode.process_name})` : 'Target Process',
                      'Immediately terminate hostile process handle on Windows host.'
                    );
                  }}
                  className="p-2 rounded bg-slate-950 hover:bg-rose-950/60 border border-slate-800 hover:border-rose-700/60 text-slate-300 hover:text-rose-200 transition text-left cursor-pointer"
                >
                  <div className="font-semibold text-rose-400">Kill Process</div>
                  <div className="text-[10px] text-slate-400">Terminate PID</div>
                </button>

                <button
                  onClick={() => {
                    const targetNode = lineageNodes.find(n => n.role === 'target');
                    handleStageAction(
                      'QUARANTINE_FILE',
                      targetNode?.image_path || 'Target Executable',
                      'Move hostile file to secure LocalEDR quarantine vault.'
                    );
                  }}
                  className="p-2 rounded bg-slate-950 hover:bg-amber-950/60 border border-slate-800 hover:border-amber-700/60 text-slate-300 hover:text-amber-200 transition text-left cursor-pointer"
                >
                  <div className="font-semibold text-amber-400">Quarantine File</div>
                  <div className="text-[10px] text-slate-400">Vault &amp; isolate</div>
                </button>

                <button
                  onClick={() => {
                    handleStageAction(
                      'BLOCK_IP',
                      'Hostile C2 Address',
                      'Add outbound block rule in Windows Advanced Firewall.'
                    );
                  }}
                  className="p-2 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 transition text-left cursor-pointer"
                >
                  <div className="font-semibold text-cyan-400">Block Network IP</div>
                  <div className="text-[10px] text-slate-400">Windows Firewall</div>
                </button>

                <button
                  onClick={() => {
                    handleStageAction(
                      'ISOLATE_HOST_SIM',
                      'Windows Endpoint',
                      'Sever non-management network interfaces to halt lateral movement.'
                    );
                  }}
                  className="p-2 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 transition text-left cursor-pointer"
                >
                  <div className="font-semibold text-indigo-400">Isolate Endpoint</div>
                  <div className="text-[10px] text-slate-400">Contain host</div>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Explicit Confirmation Modal for Dangerous Actions (Rule 10) */}
      {stagedAction && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-rose-500/50 rounded-xl max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3 text-rose-400">
              <ShieldAlert className="w-6 h-6 flex-shrink-0" />
              <div>
                <h4 className="font-bold text-white text-sm">Dangerous Action Confirmation Required</h4>
                <p className="text-xs text-slate-400">LocalEDR Response Safety Gate (Rule 10)</p>
              </div>
            </div>

            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1.5 text-xs font-mono">
              <div>
                <span className="text-slate-400">Action:</span>{' '}
                <span className="text-rose-300 font-semibold">{stagedAction.actionType}</span>
              </div>
              <div>
                <span className="text-slate-400">Target:</span>{' '}
                <span className="text-white">{stagedAction.target}</span>
              </div>
              <div>
                <span className="text-slate-400">Details:</span>{' '}
                <span className="text-slate-300">{stagedAction.details}</span>
              </div>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Are you sure you want to execute this defensive remediation? This will alter host state and will be written to the local SQLite audit log.
            </p>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setStagedAction(null)}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmAction}
                className="px-4 py-1.5 rounded bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-lg shadow-rose-950 cursor-pointer"
              >
                <Check className="w-3.5 h-3.5" />
                Confirm &amp; Execute
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Risk Scoring Engine Modal */}
      <RiskScoringModal
        isOpen={isScoringModalOpen}
        onClose={() => setIsScoringModalOpen(false)}
      />
    </div>
  );
};
