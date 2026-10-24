import React, { useEffect, useState, useMemo } from 'react';
import { 
  Grid3X3, 
  ShieldAlert, 
  ExternalLink, 
  Download, 
  Clock, 
  Laptop, 
  Layers, 
  Search, 
  Filter, 
  CheckCircle2, 
  AlertTriangle, 
  Info, 
  ChevronRight, 
  X, 
  Copy, 
  Check, 
  RefreshCw,
  Eye,
  Sliders,
  Database,
  Calendar,
  Crosshair
} from 'lucide-react';
import { 
  MitreMatrixTactic, 
  MitreCoverageStats, 
  MitreHostCoverage, 
  MitreTimelinePoint, 
  MitreTechniqueDetail,
  MitreVersionMeta 
} from '../types';
import { safeFetchJson } from '../utils/api';

interface MitreMatrixViewProps {
  onNavigateTab: (tab: string) => void;
  onSelectAlertId?: (alertId: string) => void;
}

export const MitreMatrixView: React.FC<MitreMatrixViewProps> = ({ onNavigateTab, onSelectAlertId }) => {
  const [activeSubTab, setActiveSubTab] = useState<'matrix' | 'tactics' | 'timeline' | 'hosts' | 'techniques'>('matrix');
  const [matrixData, setMatrixData] = useState<MitreMatrixTactic[]>([]);
  const [stats, setStats] = useState<MitreCoverageStats | null>(null);
  const [versions, setVersions] = useState<MitreVersionMeta[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedTacticFilter, setSelectedTacticFilter] = useState<string>('all');
  const [filterObservedOnly, setFilterObservedOnly] = useState<boolean>(false);
  const [filterCoveredOnly, setFilterCoveredOnly] = useState<boolean>(false);
  const [showSubtechniques, setShowSubtechniques] = useState<boolean>(true);

  // Technique Inspector Drawer
  const [selectedTechniqueId, setSelectedTechniqueId] = useState<string | null>(null);
  const [techniqueDetail, setTechniqueDetail] = useState<MitreTechniqueDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);

  // Export Feedback
  const [copiedNavigator, setCopiedNavigator] = useState<boolean>(false);
  const [isExporting, setIsExporting] = useState<boolean>(false);

  // Version Switch Feedback
  const [switchingVersion, setSwitchingVersion] = useState<boolean>(false);

  const fetchMitreData = async () => {
    try {
      setRefreshing(true);
      const [matrixRes, statsRes, verRes] = await Promise.all([
        safeFetchJson<MitreMatrixTactic[]>('/api/mitre/matrix', []),
        safeFetchJson<MitreCoverageStats | null>('/api/mitre/stats', null),
        safeFetchJson<MitreVersionMeta[]>('/api/mitre/versions', [])
      ]);

      if (matrixRes && matrixRes.length > 0) {
        setMatrixData(matrixRes);
      }
      if (statsRes) {
        setStats(statsRes);
      }
      if (verRes && verRes.length > 0) {
        setVersions(verRes);
      }
    } catch (err) {
      console.warn('[LocalEDR] Failed to load MITRE ATT&CK datasets:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchMitreData();
  }, []);

  // Fetch technique detail when clicked
  useEffect(() => {
    if (!selectedTechniqueId) {
      setTechniqueDetail(null);
      return;
    }

    setLoadingDetail(true);
    safeFetchJson<MitreTechniqueDetail | null>(`/api/mitre/techniques/${selectedTechniqueId}`, null)
      .then(data => {
        setTechniqueDetail(data);
      })
      .catch(err => {
        console.warn(`[LocalEDR] Failed to fetch technique ${selectedTechniqueId}:`, err);
      })
      .finally(() => {
        setLoadingDetail(false);
      });
  }, [selectedTechniqueId]);

  // Handle Export Navigator JSON
  const handleExportNavigator = async (downloadDirect: boolean = true) => {
    try {
      setIsExporting(true);
      const res = await fetch('/api/mitre/navigator');
      if (!res.ok) throw new Error('Failed to generate Navigator layer');
      const layer = await res.json();

      if (downloadDirect) {
        const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `localedr-attack-navigator-${stats?.activeVersion || 'v15.1'}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else {
        await navigator.clipboard.writeText(JSON.stringify(layer, null, 2));
        setCopiedNavigator(true);
        setTimeout(() => setCopiedNavigator(false), 2500);
      }
    } catch (err) {
      console.error('Navigator export error:', err);
    } finally {
      setIsExporting(false);
    }
  };

  // Switch Active Version
  const handleSwitchVersion = async (version: string) => {
    try {
      setSwitchingVersion(true);
      const res = await fetch('/api/mitre/version', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ version })
      });
      if (res.ok) {
        await fetchMitreData();
      }
    } catch (err) {
      console.error('Failed to switch MITRE version:', err);
    } finally {
      setSwitchingVersion(false);
    }
  };

  // Filtered Matrix Data
  const filteredMatrix = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();

    return matrixData.map(tacticGroup => {
      // Check tactic filter
      if (selectedTacticFilter !== 'all' && tacticGroup.tactic.toLowerCase() !== selectedTacticFilter.toLowerCase()) {
        return { ...tacticGroup, techniques: [] };
      }

      const filteredTechniques = tacticGroup.techniques.filter(tech => {
        // Query match
        const matchesQuery = !q || 
          tech.id.toLowerCase().includes(q) || 
          tech.name.toLowerCase().includes(q) ||
          tech.rules.some(r => r.id.toLowerCase().includes(q) || r.name.toLowerCase().includes(q)) ||
          (tech.subtechniques && tech.subtechniques.some(st => st.id.toLowerCase().includes(q) || st.name.toLowerCase().includes(q)));

        if (!matchesQuery) return false;

        // Observed filter
        if (filterObservedOnly && tech.alertsCount === 0 && (!tech.subtechniques || !tech.subtechniques.some(st => st.alertsCount > 0))) {
          return false;
        }

        // Covered by rule filter
        if (filterCoveredOnly && tech.rules.length === 0) {
          return false;
        }

        return true;
      });

      return {
        ...tacticGroup,
        techniques: filteredTechniques
      };
    });
  }, [matrixData, searchQuery, selectedTacticFilter, filterObservedOnly, filterCoveredOnly]);

  const totalFilteredTechniques = useMemo(() => {
    return filteredMatrix.reduce((acc, t) => acc + t.techniques.length, 0);
  }, [filteredMatrix]);

  return (
    <div className="space-y-6">
      {/* Top Banner & Control Deck */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden">
        <div className="absolute right-0 top-0 bottom-0 w-96 bg-gradient-to-l from-emerald-500/5 to-transparent pointer-events-none" />
        
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <Grid3X3 className="w-5 h-5" />
              </span>
              <h2 className="text-xl font-bold text-white tracking-tight">MITRE ATT&amp;CK Enterprise Defense Hub</h2>
              <span className="text-xs font-mono px-2 py-0.5 rounded-md bg-emerald-950 text-emerald-300 border border-emerald-800 font-semibold">
                {stats?.activeVersion || 'v15.1'}
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 border border-slate-700">
                Windows Endpoint Detections
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Versioned MITRE ATT&amp;CK data layer mapped dynamically to local EDR telemetry. Correlates adversary tactics, sub-techniques, and host exposure with zero external cloud dependencies.
            </p>
          </div>

          {/* Action Tools */}
          <div className="flex items-center gap-2.5 flex-wrap">
            <button
              onClick={() => handleExportNavigator(true)}
              disabled={isExporting}
              className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs flex items-center gap-1.5 shadow transition cursor-pointer disabled:opacity-50"
              title="Export valid JSON layer for MITRE ATT&CK Navigator"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Navigator Layer</span>
            </button>

            <button
              onClick={() => handleExportNavigator(false)}
              disabled={isExporting}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-xs flex items-center gap-1.5 transition cursor-pointer"
              title="Copy Navigator JSON to clipboard"
            >
              {copiedNavigator ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedNavigator ? 'Copied JSON!' : 'Copy Layer'}</span>
            </button>

            <a
              href="https://attack.mitre.org"
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700 font-mono text-xs flex items-center gap-1 transition"
            >
              <span>ATT&amp;CK Docs</span>
              <ExternalLink className="w-3 h-3 text-slate-400" />
            </a>

            <button
              onClick={fetchMitreData}
              disabled={refreshing}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer"
              title="Refresh MITRE telemetry"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-emerald-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Quick Metrics Ticker */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3 mt-4 pt-4 border-t border-slate-800/80 text-xs font-mono">
          <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[10px] block uppercase">Tactics Observed</span>
            <div className="flex items-baseline gap-1 mt-0.5">
              <span className="text-base font-bold text-rose-400">{stats?.tacticsObservedCount ?? 0}</span>
              <span className="text-[10px] text-slate-500">/ {stats?.totalTactics ?? 14}</span>
            </div>
          </div>

          <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[10px] block uppercase">Techniques Observed</span>
            <div className="flex items-baseline gap-1 mt-0.5">
              <span className="text-base font-bold text-amber-400">{stats?.techniquesObservedCount ?? 0}</span>
              <span className="text-[10px] text-slate-500">active alerts</span>
            </div>
          </div>

          <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[10px] block uppercase">Total Alerts</span>
            <div className="flex items-baseline gap-1 mt-0.5">
              <span className="text-base font-bold text-white">{stats?.totalAlertsCount ?? 0}</span>
              <span className="text-[10px] text-slate-500">correlated</span>
            </div>
          </div>

          <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[10px] block uppercase">Detection Rules</span>
            <div className="flex items-baseline gap-1 mt-0.5">
              <span className="text-base font-bold text-emerald-400">{stats?.totalCoveredTechniquesByRules ?? 0}</span>
              <span className="text-[10px] text-slate-500">techniques covered</span>
            </div>
          </div>

          <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[10px] block uppercase">Host Endpoints</span>
            <div className="flex items-baseline gap-1 mt-0.5">
              <span className="text-base font-bold text-cyan-400">{stats?.hostCoverage?.length ?? 1}</span>
              <span className="text-[10px] text-slate-500">protected</span>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-2 flex-wrap">
        <div className="flex items-center gap-1.5 bg-slate-900/80 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveSubTab('matrix')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer ${
              activeSubTab === 'matrix'
                ? 'bg-emerald-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Grid3X3 className="w-3.5 h-3.5" />
            <span>ATT&amp;CK Matrix</span>
          </button>

          <button
            onClick={() => setActiveSubTab('tactics')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer ${
              activeSubTab === 'tactics'
                ? 'bg-emerald-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Tactics Observed</span>
            {stats && stats.tacticsObservedCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-rose-500/20 text-rose-300 font-mono font-bold">
                {stats.tacticsObservedCount}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveSubTab('timeline')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer ${
              activeSubTab === 'timeline'
                ? 'bg-emerald-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>Timeline</span>
            {stats && stats.timeline.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
                {stats.timeline.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveSubTab('hosts')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer ${
              activeSubTab === 'hosts'
                ? 'bg-emerald-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Laptop className="w-3.5 h-3.5" />
            <span>Host Coverage</span>
          </button>

          <button
            onClick={() => setActiveSubTab('techniques')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer ${
              activeSubTab === 'techniques'
                ? 'bg-emerald-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>Techniques Observed</span>
            {stats && stats.techniquesObservedCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-amber-500/20 text-amber-300 font-mono font-bold">
                {stats.techniquesObservedCount}
              </span>
            )}
          </button>
        </div>

        {/* Version Switcher dropdown */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <Database className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-400 text-[11px]">Data Layer:</span>
          <select
            value={stats?.activeVersion || 'v15.1'}
            onChange={(e) => handleSwitchVersion(e.target.value)}
            disabled={switchingVersion}
            className="bg-slate-900 border border-slate-800 text-slate-200 px-2.5 py-1 rounded-lg text-xs cursor-pointer focus:outline-none focus:border-emerald-500"
          >
            {versions.map(v => (
              <option key={v.version} value={v.version}>
                {v.name} ({v.version})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SUB-TAB 1: ATT&CK Matrix View */}
      {/* ========================================================================= */}
      {activeSubTab === 'matrix' && (
        <div className="space-y-4">
          {/* Matrix Filter Bar */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2 flex-1 min-w-[240px]">
              <Search className="w-4 h-4 text-slate-400 shrink-0" />
              <input
                type="text"
                placeholder="Search technique ID (e.g. T1059, T1053.005, T1547.001), name, or rule..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 text-xs font-mono"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="text-slate-400 hover:text-slate-200 cursor-pointer p-1"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="flex items-center gap-2 flex-wrap font-mono">
              <select
                value={selectedTacticFilter}
                onChange={(e) => setSelectedTacticFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-slate-300 px-2.5 py-1.5 rounded-lg text-xs cursor-pointer focus:outline-none focus:border-emerald-500"
              >
                <option value="all">All Tactics (14)</option>
                {matrixData.map(m => (
                  <option key={m.tactic} value={m.tactic}>{m.tactic}</option>
                ))}
              </select>

              <button
                onClick={() => setFilterObservedOnly(!filterObservedOnly)}
                className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center gap-1.5 transition cursor-pointer ${
                  filterObservedOnly
                    ? 'bg-rose-950/80 border-rose-700 text-rose-300'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Observed Only</span>
              </button>

              <button
                onClick={() => setFilterCoveredOnly(!filterCoveredOnly)}
                className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center gap-1.5 transition cursor-pointer ${
                  filterCoveredOnly
                    ? 'bg-emerald-950/80 border-emerald-700 text-emerald-300'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Rule Covered</span>
              </button>

              <button
                onClick={() => setShowSubtechniques(!showSubtechniques)}
                className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center gap-1.5 transition cursor-pointer ${
                  showSubtechniques
                    ? 'bg-slate-800 border-slate-700 text-cyan-300'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <span>Sub-techniques: {showSubtechniques ? 'Shown' : 'Hidden'}</span>
              </button>
            </div>
          </div>

          {/* Matrix Heatmap Grid */}
          {loading ? (
            <div className="p-16 text-center text-slate-500 flex flex-col items-center gap-3">
              <RefreshCw className="w-6 h-6 animate-spin text-emerald-400" />
              <span>Loading MITRE ATT&amp;CK Matrix &amp; Telemetry...</span>
            </div>
          ) : (
            <div className="overflow-x-auto pb-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-7 gap-3 min-w-[900px]">
                {filteredMatrix.map((tacticGroup) => {
                  const hasCoverage = tacticGroup.techniques.length > 0;
                  const totalAlertsInTactic = tacticGroup.techniques.reduce((acc, tech) => {
                    const subAlerts = (tech.subtechniques || []).reduce((sacc, st) => sacc + st.alertsCount, 0);
                    return acc + tech.alertsCount + subAlerts;
                  }, 0);

                  return (
                    <div
                      key={tacticGroup.tactic}
                      className={`rounded-xl border flex flex-col justify-between transition ${
                        totalAlertsInTactic > 0
                          ? 'bg-slate-900 border-rose-900/60 shadow-md shadow-rose-950/20'
                          : hasCoverage
                          ? 'bg-slate-900 border-slate-800'
                          : 'bg-slate-950/40 border-slate-800/40 opacity-60'
                      }`}
                    >
                      <div className="p-3">
                        {/* Tactic Header */}
                        <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2.5">
                          <div>
                            <span className="text-xs font-bold text-white uppercase tracking-wider block">
                              {tacticGroup.tactic}
                            </span>
                            {tacticGroup.tactic_id && (
                              <span className="text-[10px] text-slate-500 font-mono">
                                {tacticGroup.tactic_id}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-1">
                            {totalAlertsInTactic > 0 && (
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800 font-bold">
                                {totalAlertsInTactic}
                              </span>
                            )}
                            <span
                              className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                                hasCoverage
                                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                  : 'bg-slate-900 text-slate-500'
                              }`}
                            >
                              {tacticGroup.techniques.length}
                            </span>
                          </div>
                        </div>

                        {/* Techniques List in Tactic Column */}
                        {hasCoverage ? (
                          <div className="space-y-2">
                            {tacticGroup.techniques.map((tech) => {
                              const hasAlerts = tech.alertsCount > 0;
                              const hasRules = tech.rules.length > 0;
                              const subCount = tech.subtechniques?.length || 0;

                              return (
                                <div
                                  key={tech.id}
                                  onClick={() => setSelectedTechniqueId(tech.id)}
                                  className={`p-2.5 rounded-lg border transition cursor-pointer group text-xs font-mono ${
                                    hasAlerts
                                      ? 'bg-rose-950/20 border-rose-800/80 hover:border-rose-500 hover:bg-rose-950/40'
                                      : hasRules
                                      ? 'bg-slate-950 border-slate-800/80 hover:border-emerald-500/60 hover:bg-slate-900'
                                      : 'bg-slate-950/60 border-slate-850 hover:border-slate-700'
                                  }`}
                                >
                                  {/* Technique Header */}
                                  <div className="flex items-center justify-between mb-1">
                                    <div className="flex items-center gap-1.5">
                                      <span className={`font-bold ${hasAlerts ? 'text-rose-400 group-hover:text-rose-300' : 'text-emerald-400 group-hover:text-emerald-300'}`}>
                                        {tech.id}
                                      </span>
                                      {subCount > 0 && (
                                        <span className="text-[9px] px-1 py-0.2 rounded bg-slate-800 text-slate-400 font-mono">
                                          {subCount} sub
                                        </span>
                                      )}
                                    </div>

                                    {hasAlerts ? (
                                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-700 font-bold animate-pulse">
                                        {tech.alertsCount} alert{tech.alertsCount > 1 ? 's' : ''}
                                      </span>
                                    ) : hasRules ? (
                                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/80">
                                        Covered
                                      </span>
                                    ) : (
                                      <span className="text-[10px] px-1 rounded text-slate-600">
                                        Dataset
                                      </span>
                                    )}
                                  </div>

                                  <div className="text-slate-300 text-[11px] font-medium leading-tight truncate group-hover:text-white">
                                    {tech.name}
                                  </div>

                                  {/* Rules list */}
                                  {hasRules && (
                                    <div className="mt-1.5 flex items-center gap-1 flex-wrap text-[9px] text-slate-500">
                                      {tech.rules.map(r => (
                                        <span
                                          key={r.id}
                                          className={`px-1 rounded border ${
                                            r.enabled ? 'bg-slate-900 text-slate-400 border-slate-800' : 'bg-slate-900/40 text-slate-600 border-slate-850 line-through'
                                          }`}
                                        >
                                          {r.id.split('-').slice(0, 2).join('-')}
                                        </span>
                                      ))}
                                    </div>
                                  )}

                                  {/* Subtechniques accordion if enabled */}
                                  {showSubtechniques && tech.subtechniques && tech.subtechniques.length > 0 && (
                                    <div className="mt-2 pt-2 border-t border-slate-800/60 space-y-1">
                                      {tech.subtechniques.map(st => (
                                        <div
                                          key={st.id}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            setSelectedTechniqueId(st.id);
                                          }}
                                          className={`flex items-center justify-between p-1 rounded text-[10px] transition ${
                                            st.alertsCount > 0
                                              ? 'bg-rose-950/40 text-rose-300 border border-rose-800/60'
                                              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200'
                                          }`}
                                        >
                                          <span className="truncate">{st.id}</span>
                                          {st.alertsCount > 0 ? (
                                            <span className="px-1 rounded bg-rose-900 text-white font-bold text-[9px]">
                                              {st.alertsCount}
                                            </span>
                                          ) : (
                                            <ChevronRight className="w-2.5 h-2.5 text-slate-600" />
                                          )}
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        ) : (
                          <div className="py-6 text-center text-[11px] text-slate-600 font-mono">
                            No techniques matched current filters.
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUB-TAB 2: Tactics Observed */}
      {/* ========================================================================= */}
      {activeSubTab === 'tactics' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <h3 className="font-bold text-white text-sm mb-1 flex items-center gap-2">
              <Layers className="w-4 h-4 text-rose-400" />
              <span>Adversary Tactics Observed on Protected Endpoints</span>
            </h3>
            <p className="text-xs text-slate-400">
              Aggregated view of MITRE ATT&amp;CK tactics actively triggered by endpoint detections. Tactics with active alerts require prioritized containment.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {stats?.tacticsObserved.map((tactic) => (
              <div
                key={tactic.tactic}
                className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between hover:border-slate-700 transition"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold font-mono text-emerald-400">
                      {tactic.tactic_id || 'TACTIC'}
                    </span>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                      {tactic.alertsCount} Alert{tactic.alertsCount > 1 ? 's' : ''}
                    </span>
                  </div>

                  <h4 className="text-base font-bold text-white mb-2">{tactic.tactic}</h4>

                  <div className="space-y-1.5 text-xs font-mono text-slate-400">
                    <div className="flex items-center justify-between">
                      <span>Unique Techniques:</span>
                      <span className="text-slate-200 font-semibold">{tactic.techniquesCount}</span>
                    </div>
                    <div className="flex items-start justify-between gap-2">
                      <span>Observed IDs:</span>
                      <div className="flex flex-wrap gap-1 justify-end">
                        {tactic.techniques.map(techId => (
                          <button
                            key={techId}
                            onClick={() => setSelectedTechniqueId(techId)}
                            className="px-1.5 py-0.5 rounded bg-slate-950 text-emerald-300 border border-slate-800 text-[10px] hover:border-emerald-500 cursor-pointer"
                          >
                            {techId}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
                  <button
                    onClick={() => {
                      setSelectedTacticFilter(tactic.tactic);
                      setActiveSubTab('matrix');
                    }}
                    className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 font-mono cursor-pointer"
                  >
                    <span>View in Matrix</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => onNavigateTab('alerts')}
                    className="text-xs text-slate-400 hover:text-slate-200 font-mono cursor-pointer"
                  >
                    Investigate Alerts &rarr;
                  </button>
                </div>
              </div>
            ))}

            {(!stats || stats.tacticsObserved.length === 0) && (
              <div className="col-span-full p-12 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800/60 font-mono">
                No adversary tactics currently observed. Run safe simulations or trigger test telemetry to populate real-time observations.
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUB-TAB 3: Timeline of Detections */}
      {/* ========================================================================= */}
      {activeSubTab === 'timeline' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between gap-4">
            <div>
              <h3 className="font-bold text-white text-sm flex items-center gap-2">
                <Clock className="w-4 h-4 text-emerald-400" />
                <span>MITRE ATT&amp;CK Telemetry Timeline</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Chronological timeline of detected techniques across all monitored endpoint workloads.
              </p>
            </div>
            <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800">
              {stats?.timeline.length ?? 0} Timeline Events
            </span>
          </div>

          <div className="space-y-2">
            {stats?.timeline.map((point, index) => {
              const dateStr = new Date(point.timestamp).toLocaleString();
              const isCritical = point.severity === 'CRITICAL';
              const isHigh = point.severity === 'HIGH';

              return (
                <div
                  key={`${point.id}-${index}`}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-3.5 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 font-mono hover:border-slate-700 transition"
                >
                  <div className="flex items-start md:items-center gap-3">
                    <div className="w-2 h-2 rounded-full mt-1.5 md:mt-0 shrink-0 bg-emerald-400 shadow-sm shadow-emerald-400" />
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <button
                          onClick={() => setSelectedTechniqueId(point.technique_id)}
                          className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-xs font-bold hover:border-emerald-500 cursor-pointer"
                        >
                          {point.technique_id}
                        </button>
                        <span className="text-white font-bold text-xs">
                          {point.technique_name}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {point.tactic}
                        </span>
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                            isCritical
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : isHigh
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : 'bg-slate-800 text-slate-300 border border-slate-700'
                          }`}
                        >
                          {point.severity} ({point.score}/100)
                        </span>
                      </div>

                      <div className="text-xs text-slate-400 mt-1 flex items-center gap-2 flex-wrap">
                        <span>Host: <span className="text-slate-300">{point.hostname}</span></span>
                        {point.process_name && (
                          <span>• Process: <span className="text-cyan-300">{point.process_name}</span></span>
                        )}
                        <span>• Rule: <span className="text-slate-400">{point.rule_name}</span></span>
                      </div>

                      {point.command_line && (
                        <div className="text-[11px] text-slate-500 bg-slate-950 px-2 py-1 rounded mt-1.5 border border-slate-850 truncate max-w-2xl">
                          {point.command_line}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 self-end md:self-center">
                    <span className="text-[11px] text-slate-500">
                      {dateStr}
                    </span>
                    <button
                      onClick={() => onNavigateTab('alerts')}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-sans cursor-pointer transition"
                    >
                      Inspect Alert
                    </button>
                  </div>
                </div>
              );
            })}

            {(!stats || stats.timeline.length === 0) && (
              <div className="p-12 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800/60 font-mono">
                Timeline is currently empty. Run simulation tests or inject telemetry to record attack events.
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUB-TAB 4: Host Coverage */}
      {/* ========================================================================= */}
      {activeSubTab === 'hosts' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <h3 className="font-bold text-white text-sm mb-1 flex items-center gap-2">
              <Laptop className="w-4 h-4 text-cyan-400" />
              <span>Host Workstation &amp; Server Coverage</span>
            </h3>
            <p className="text-xs text-slate-400">
              Correlates MITRE ATT&amp;CK tactics and technique exposure across endpoints. Displays highest calculated risk scores and alert concentrations per host.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {stats?.hostCoverage.map((host) => {
              const isCritical = host.riskLevel === 'Critical';
              const isHigh = host.riskLevel === 'High';

              return (
                <div
                  key={host.hostname}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between font-mono"
                >
                  <div>
                    <div className="flex items-center justify-between mb-3 border-b border-slate-800 pb-2">
                      <div className="flex items-center gap-2">
                        <Laptop className="w-4 h-4 text-cyan-400" />
                        <span className="font-bold text-white text-sm">{host.hostname}</span>
                      </div>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                          isCritical
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : isHigh
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-slate-800 text-slate-300 border border-slate-700'
                        }`}
                      >
                        {host.riskLevel} Risk
                      </span>
                    </div>

                    <div className="space-y-2 text-xs text-slate-400">
                      <div className="flex items-center justify-between">
                        <span>Total Alerts:</span>
                        <span className="text-white font-bold">{host.totalAlerts}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span>Active Unresolved:</span>
                        <span className="text-rose-400 font-bold">{host.activeAlerts}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span>Max Risk Score:</span>
                        <span className="text-amber-300 font-bold">{host.maxScore} / 100</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span>Last Telemetry:</span>
                        <span className="text-slate-300 text-[11px]">{new Date(host.lastSeen).toLocaleTimeString()}</span>
                      </div>
                    </div>

                    {/* Techniques on this host */}
                    <div className="mt-3 pt-3 border-t border-slate-800">
                      <span className="text-[10px] text-slate-500 uppercase block mb-1.5">
                        Observed Techniques ({host.techniquesObserved.length}):
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {host.techniquesObserved.map(techId => (
                          <button
                            key={techId}
                            onClick={() => setSelectedTechniqueId(techId)}
                            className="px-1.5 py-0.5 rounded bg-slate-950 text-emerald-300 border border-slate-800 text-[10px] hover:border-emerald-500 cursor-pointer"
                          >
                            {techId}
                          </button>
                        ))}
                        {host.techniquesObserved.length === 0 && (
                          <span className="text-slate-600 text-[11px]">No malicious techniques observed.</span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800">
                    <button
                      onClick={() => onNavigateTab('alerts')}
                      className="w-full py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-sans cursor-pointer transition text-center"
                    >
                      View Host Telemetry &amp; Alerts
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUB-TAB 5: Techniques Observed Table */}
      {/* ========================================================================= */}
      {activeSubTab === 'techniques' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <h3 className="font-bold text-white text-sm mb-1 flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-amber-400" />
              <span>All Techniques Observed in Active Telemetry</span>
            </h3>
            <p className="text-xs text-slate-400">
              Direct table listing every ATT&amp;CK technique triggered by real-time rules and events on this system.
            </p>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden font-mono text-xs">
            <table className="w-full text-left">
              <thead className="bg-slate-950 text-slate-400 text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4">Technique ID</th>
                  <th className="py-2.5 px-4">Technique Name</th>
                  <th className="py-2.5 px-4">Tactic</th>
                  <th className="py-2.5 px-4 text-center">Alerts</th>
                  <th className="py-2.5 px-4 text-center">Max Score</th>
                  <th className="py-2.5 px-4">Highest Severity</th>
                  <th className="py-2.5 px-4">Last Observed</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {stats?.techniquesObserved.map((tech) => (
                  <tr key={tech.id} className="hover:bg-slate-850/50 transition">
                    <td className="py-2.5 px-4 font-bold text-emerald-400">
                      {tech.id}
                    </td>
                    <td className="py-2.5 px-4 text-white font-medium">
                      {tech.name}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400">
                      {tech.tactic}
                    </td>
                    <td className="py-2.5 px-4 text-center">
                      <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                        {tech.alertsCount}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-center text-amber-300 font-bold">
                      {tech.maxScore}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                        tech.highestSeverity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        tech.highestSeverity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-slate-800 text-slate-300 border border-slate-700'
                      }`}>
                        {tech.highestSeverity}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                      {new Date(tech.lastSeen).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => setSelectedTechniqueId(tech.id)}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer transition text-[11px]"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}

                {(!stats || stats.techniquesObserved.length === 0) && (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-slate-500">
                      No techniques observed yet. Run safe simulations to trigger Windows detections.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TECHNIQUE INSPECTOR DRAWER / MODAL */}
      {/* ========================================================================= */}
      {selectedTechniqueId && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex justify-end z-50">
          <div className="bg-slate-900 border-l border-slate-800 w-full max-w-xl h-full overflow-y-auto p-6 flex flex-col justify-between shadow-2xl">
            <div className="space-y-5">
              {/* Header */}
              <div className="flex items-start justify-between border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-emerald-400 font-mono text-base font-bold">
                      {selectedTechniqueId}
                    </span>
                    {techniqueDetail?.is_subtechnique && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">
                        Sub-technique of {techniqueDetail.parent_id}
                      </span>
                    )}
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                      {techniqueDetail?.tactic}
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-white mt-1">
                    {techniqueDetail?.name || selectedTechniqueId}
                  </h3>
                </div>

                <button
                  onClick={() => setSelectedTechniqueId(null)}
                  className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {loadingDetail ? (
                <div className="p-8 text-center text-slate-500">
                  <RefreshCw className="w-5 h-5 animate-spin mx-auto text-emerald-400 mb-2" />
                  Loading technique metadata...
                </div>
              ) : (
                <div className="space-y-4 text-xs font-mono">
                  {/* ATT&CK Description */}
                  <div>
                    <h4 className="text-slate-400 uppercase text-[10px] font-bold mb-1">
                      ATT&amp;CK Description
                    </h4>
                    <p className="text-slate-300 font-sans leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                      {techniqueDetail?.description || 'No description available for this technique in active version dataset.'}
                    </p>
                  </div>

                  {/* Windows Relevance */}
                  {techniqueDetail?.windows_relevance && (
                    <div>
                      <h4 className="text-slate-400 uppercase text-[10px] font-bold mb-1">
                        Windows Endpoint Relevance
                      </h4>
                      <p className="text-cyan-300 font-sans bg-cyan-950/30 p-2.5 rounded-lg border border-cyan-800/50 leading-relaxed">
                        {techniqueDetail.windows_relevance}
                      </p>
                    </div>
                  )}

                  {/* Detection Guidance */}
                  {techniqueDetail?.detection_guidance && (
                    <div>
                      <h4 className="text-slate-400 uppercase text-[10px] font-bold mb-1">
                        Detection Engineering Guidance
                      </h4>
                      <p className="text-emerald-300 font-sans bg-emerald-950/30 p-2.5 rounded-lg border border-emerald-800/50 leading-relaxed">
                        {techniqueDetail.detection_guidance}
                      </p>
                    </div>
                  )}

                  {/* Data Sources */}
                  {techniqueDetail?.data_sources && techniqueDetail.data_sources.length > 0 && (
                    <div>
                      <h4 className="text-slate-400 uppercase text-[10px] font-bold mb-1">
                        Recommended Data Sources
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                        {techniqueDetail.data_sources.map(ds => (
                          <span key={ds} className="px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800 text-[10px]">
                            {ds}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Subtechniques if any */}
                  {techniqueDetail?.subtechniques && techniqueDetail.subtechniques.length > 0 && (
                    <div>
                      <h4 className="text-slate-400 uppercase text-[10px] font-bold mb-1">
                        Sub-techniques ({techniqueDetail.subtechniques.length})
                      </h4>
                      <div className="space-y-1">
                        {techniqueDetail.subtechniques.map(st => (
                          <div
                            key={st.id}
                            onClick={() => setSelectedTechniqueId(st.id)}
                            className="p-2 rounded bg-slate-950 border border-slate-800 flex items-center justify-between hover:border-emerald-500 cursor-pointer transition"
                          >
                            <div>
                              <span className="text-emerald-400 font-bold block">{st.id}</span>
                              <span className="text-slate-300 text-[11px]">{st.name}</span>
                            </div>
                            <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Mapped LocalEDR Detection Rules */}
                  <div>
                    <h4 className="text-slate-400 uppercase text-[10px] font-bold mb-1">
                      Mapped LocalEDR Detection Rules ({techniqueDetail?.rules?.length || 0})
                    </h4>
                    {techniqueDetail?.rules && techniqueDetail.rules.length > 0 ? (
                      <div className="space-y-1.5">
                        {techniqueDetail.rules.map(r => (
                          <div key={r.id} className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                            <div>
                              <div className="flex items-center gap-1.5">
                                <span className="font-bold text-white">{r.name}</span>
                                <span className={`text-[9px] px-1 rounded ${r.enabled ? 'bg-emerald-950 text-emerald-400' : 'bg-slate-800 text-slate-500'}`}>
                                  {r.enabled ? 'ACTIVE' : 'DISABLED'}
                                </span>
                              </div>
                              <span className="text-slate-500 text-[10px]">{r.id} • Score: {r.score}</span>
                            </div>
                            <span className="text-slate-400 font-bold text-[10px]">{r.severity}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-3 text-center text-slate-600 bg-slate-950 rounded border border-slate-800">
                        No custom detection rules currently mapped to this technique.
                      </div>
                    )}
                  </div>

                  {/* Correlated Alerts */}
                  <div>
                    <h4 className="text-slate-400 uppercase text-[10px] font-bold mb-1">
                      Correlated Endpoint Alerts ({techniqueDetail?.recentAlerts?.length || 0})
                    </h4>
                    {techniqueDetail?.recentAlerts && techniqueDetail.recentAlerts.length > 0 ? (
                      <div className="space-y-1.5">
                        {techniqueDetail.recentAlerts.map(a => (
                          <div
                            key={a.id}
                            onClick={() => {
                              setSelectedTechniqueId(null);
                              onNavigateTab('alerts');
                            }}
                            className="p-2.5 rounded bg-rose-950/30 border border-rose-800/60 flex items-center justify-between hover:border-rose-500 cursor-pointer transition"
                          >
                            <div>
                              <span className="font-bold text-white text-[11px] block">{a.title}</span>
                              <span className="text-slate-400 text-[10px]">{a.id} • {new Date(a.timestamp).toLocaleString()}</span>
                            </div>
                            <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold text-[10px]">
                              {a.score}/100
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-3 text-center text-slate-600 bg-slate-950 rounded border border-slate-800">
                        0 alerts observed for this technique on this system.
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Drawer Footer */}
            <div className="pt-4 border-t border-slate-800 flex items-center justify-between mt-4">
              <a
                href={`https://attack.mitre.org/techniques/${selectedTechniqueId.replace('.', '/')}`}
                target="_blank"
                rel="noreferrer"
                className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 font-mono"
              >
                <span>View on attack.mitre.org</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>

              <button
                onClick={() => setSelectedTechniqueId(null)}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono cursor-pointer"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
