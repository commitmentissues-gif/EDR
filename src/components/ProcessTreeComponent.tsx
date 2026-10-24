import React, { useState } from 'react';
import { 
  GitBranch, 
  Search, 
  ChevronRight, 
  ChevronDown, 
  ShieldCheck, 
  ShieldAlert, 
  Copy, 
  Check, 
  User, 
  Terminal, 
  FileCode, 
  Clock, 
  AlertTriangle, 
  X, 
  Maximize2, 
  Minimize2, 
  Filter, 
  Activity,
  Layers,
  ArrowRight
} from 'lucide-react';
import { ProcessTreeNode } from '../types';

interface ProcessTreeComponentProps {
  tree: ProcessTreeNode[];
  loading?: boolean;
  onRefresh?: () => void;
  onSelectProcess?: (node: ProcessTreeNode) => void;
}

export const ProcessTreeComponent: React.FC<ProcessTreeComponentProps> = ({
  tree,
  loading = false,
  onRefresh
}) => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [riskFilter, setRiskFilter] = useState<'all' | 'high_critical' | 'medium' | 'low'>('all');
  const [sourceFilter, setSourceFilter] = useState<'all' | 'live' | 'baseline' | 'simulated'>('all');
  const [showTerminatedOnly, setShowTerminatedOnly] = useState<boolean>(false);
  const [expandAll, setExpandAll] = useState<boolean>(true);
  const [selectedProcess, setSelectedProcess] = useState<ProcessTreeNode | null>(null);
  const [copiedLabel, setCopiedLabel] = useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedLabel(label);
    setTimeout(() => setCopiedLabel(null), 2000);
  };

  // Helper to find node in tree by PID for breadcrumb jumping
  const findNodeByPid = (nodes: ProcessTreeNode[], pid: number): ProcessTreeNode | null => {
    for (const n of nodes) {
      if (n.pid === pid) return n;
      const found = findNodeByPid(n.children, pid);
      if (found) return found;
    }
    return null;
  };

  // Count total processes recursively
  const countNodes = (nodes: ProcessTreeNode[]): { total: number; terminated: number; highRisk: number } => {
    let total = 0;
    let terminated = 0;
    let highRisk = 0;

    const traverse = (items: ProcessTreeNode[]) => {
      for (const item of items) {
        total++;
        if (item.is_terminated) terminated++;
        if ((item.risk_score || 0) >= 50) highRisk++;
        if (item.children && item.children.length > 0) {
          traverse(item.children);
        }
      }
    };
    traverse(nodes);
    return { total, terminated, highRisk };
  };

  const stats = countNodes(tree);

  // Helper to filter nodes based on user search & risk level
  const filterNode = (node: ProcessTreeNode): boolean => {
    // Source filter
    const isLive = node.source === 'sysmon_live' || node.source === 'live_monitor' || node.source === 'sysmon_agent';
    const isSim = node.source === 'safe_simulator';
    const isBase = node.source === 'baseline_seed' || (!isLive && !isSim);

    if (sourceFilter === 'live' && !isLive && !node.children.some(child => filterNode(child))) return false;
    if (sourceFilter === 'baseline' && !isBase && !node.children.some(child => filterNode(child))) return false;
    if (sourceFilter === 'simulated' && !isSim && !node.children.some(child => filterNode(child))) return false;

    // Risk filter
    if (riskFilter === 'high_critical' && (node.risk_score || 0) < 50) return false;
    if (riskFilter === 'medium' && ((node.risk_score || 0) < 25 || (node.risk_score || 0) >= 50)) return false;
    if (riskFilter === 'low' && (node.risk_score || 0) >= 25) return false;

    // Terminated filter
    if (showTerminatedOnly && !node.is_terminated) return false;

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match = (
        node.process_name.toLowerCase().includes(q) ||
        node.pid.toString().includes(q) ||
        node.parent_pid.toString().includes(q) ||
        node.command_line.toLowerCase().includes(q) ||
        node.username.toLowerCase().includes(q) ||
        (node.sha256 && node.sha256.toLowerCase().includes(q))
      );
      if (!match) {
        // Check if any descendant matches
        return node.children.some(child => filterNode(child));
      }
    }
    return true;
  };

  return (
    <div className="space-y-4 font-sans">
      {/* Top Controls & Filter Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <GitBranch className="w-5 h-5 text-cyan-400" />
              <h3 className="font-bold text-white text-base">Hierarchical Process Execution Tree</h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                Lineage Reconstructed
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Reconstructs exact parent-child causality using PID, PPID, creation timestamps, and binary paths. Correctly handles terminated parents.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <button
              onClick={() => setExpandAll(!expandAll)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1.5 transition cursor-pointer"
            >
              {expandAll ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
              <span>{expandAll ? 'Collapse All' : 'Expand All'}</span>
            </button>
            {onRefresh && (
              <button
                onClick={onRefresh}
                disabled={loading}
                className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
              >
                <Activity className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>
            )}
          </div>
        </div>

        {/* Filters and Stats Strip */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800 text-xs font-mono">
          <div className="flex items-center gap-2.5 flex-wrap">
            {/* Search Box */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search PID, name, cmdline, SHA-256..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-64"
              />
            </div>

            {/* Risk Filter */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 px-1">Risk:</span>
              {[
                { id: 'all', label: 'All' },
                { id: 'high_critical', label: 'High / Critical' },
                { id: 'medium', label: 'Medium' },
                { id: 'low', label: 'Low' }
              ].map(opt => (
                <button
                  key={opt.id}
                  onClick={() => setRiskFilter(opt.id as any)}
                  className={`px-2 py-0.5 rounded text-[11px] transition cursor-pointer ${
                    riskFilter === opt.id
                      ? 'bg-slate-800 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>

            {/* Telemetry Source Filter */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 px-1">Source:</span>
              {[
                { id: 'all', label: 'All' },
                { id: 'live', label: '🟢 Live Endpoint' },
                { id: 'baseline', label: '⚪ Baseline' },
                { id: 'simulated', label: '🟣 Simulated' }
              ].map(opt => (
                <button
                  key={opt.id}
                  onClick={() => setSourceFilter(opt.id as any)}
                  className={`px-2 py-0.5 rounded text-[11px] transition cursor-pointer ${
                    sourceFilter === opt.id
                      ? 'bg-slate-800 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>

            {/* Terminated Parent Filter */}
            <button
              onClick={() => setShowTerminatedOnly(!showTerminatedOnly)}
              className={`px-2.5 py-1 rounded-lg border text-[11px] transition cursor-pointer flex items-center gap-1.5 ${
                showTerminatedOnly
                  ? 'bg-slate-800 border-amber-600/60 text-amber-300 font-semibold'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Clock className="w-3 h-3" />
              <span>Terminated Only</span>
            </button>
          </div>

          {/* Quick Metrics Badges */}
          <div className="flex items-center gap-3 text-[11px] text-slate-400">
            <div>
              Total Nodes: <span className="text-white font-bold">{stats.total}</span>
            </div>
            <div>
              Terminated: <span className="text-slate-300 font-bold">{stats.terminated}</span>
            </div>
            <div>
              High Risk: <span className="text-rose-400 font-bold">{stats.highRisk}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Process Tree Canvas */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        {tree.length === 0 ? (
          <div className="p-8 text-center text-slate-500 font-mono text-xs">
            No process execution trees recorded yet.
          </div>
        ) : (
          <div className="space-y-3">
            {tree.filter(filterNode).map((rootNode) => (
              <ProcessTreeBranch
                key={rootNode.id || rootNode.pid}
                node={rootNode}
                level={0}
                expandAllDefault={expandAll}
                searchQuery={searchQuery}
                onSelectProcess={(node) => setSelectedProcess(node)}
                copyToClipboard={copyToClipboard}
                copiedLabel={copiedLabel}
              />
            ))}
          </div>
        )}
      </div>

      {/* Comprehensive Process Inspector Drawer / Modal */}
      {selectedProcess && (
        <ProcessDetailInspector
          node={selectedProcess}
          allTree={tree}
          onClose={() => setSelectedProcess(null)}
          onNavigateProcess={(pid) => {
            const target = findNodeByPid(tree, pid);
            if (target) setSelectedProcess(target);
          }}
          copyToClipboard={copyToClipboard}
          copiedLabel={copiedLabel}
        />
      )}
    </div>
  );
};

interface ProcessTreeBranchProps {
  node: ProcessTreeNode;
  level: number;
  expandAllDefault: boolean;
  searchQuery: string;
  onSelectProcess: (node: ProcessTreeNode) => void;
  copyToClipboard: (text: string, label: string) => void;
  copiedLabel: string | null;
}

const ProcessTreeBranch: React.FC<ProcessTreeBranchProps> = ({
  node,
  level,
  expandAllDefault,
  searchQuery,
  onSelectProcess,
  copyToClipboard,
  copiedLabel
}) => {
  const [collapsed, setCollapsed] = useState<boolean>(false);
  const hasChildren = node.children && node.children.length > 0;
  const isExpanded = expandAllDefault ? !collapsed : collapsed;

  // Determine Risk Badge Colors
  const riskScore = node.risk_score ?? 0;
  let riskBadgeColor = 'bg-emerald-950 text-emerald-400 border-emerald-800';
  if (riskScore >= 75) {
    riskBadgeColor = 'bg-rose-950 text-rose-300 border-rose-800';
  } else if (riskScore >= 50) {
    riskBadgeColor = 'bg-orange-950 text-orange-300 border-orange-800';
  } else if (riskScore >= 25) {
    riskBadgeColor = 'bg-amber-950 text-amber-300 border-amber-800';
  }

  // Signature status color
  const isValidSig = node.signature_status === 'Valid';
  const isUnsigned = node.signature_status === 'Unsigned';

  // Highlight matching search text
  const isMatched = searchQuery.trim() && (
    node.process_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    node.pid.toString().includes(searchQuery) ||
    node.command_line.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className={`relative ${level > 0 ? 'ml-6 sm:ml-8 pl-3 border-l-2 border-slate-800' : ''}`}>
      {/* Node Card Displaying All 8 Required Fields */}
      <div
        onClick={() => onSelectProcess(node)}
        className={`group p-3 rounded-xl border transition cursor-pointer space-y-2.5 ${
          isMatched
            ? 'bg-cyan-950/40 border-cyan-500/80 shadow-md ring-1 ring-cyan-500/40'
            : node.is_terminated
            ? 'bg-slate-950/70 border-slate-800/80 hover:border-slate-700'
            : 'bg-slate-950 border-slate-800 hover:border-slate-700 hover:bg-slate-900/90'
        }`}
      >
        {/* Header Line: Process Name, PID, PPID, Expand Toggle, Status & Risk Score */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            {hasChildren && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setCollapsed(!collapsed);
                }}
                className="p-1 rounded bg-slate-850 hover:bg-slate-800 text-slate-400 hover:text-white transition cursor-pointer"
                title={isExpanded ? 'Collapse branch' : 'Expand branch'}
              >
                {isExpanded ? <ChevronDown className="w-3.5 h-3.5 text-cyan-400" /> : <ChevronRight className="w-3.5 h-3.5" />}
              </button>
            )}

            {/* Process Name */}
            <span className="font-bold text-white text-sm font-mono tracking-tight flex items-center gap-1.5">
              <FileCode className="w-4 h-4 text-slate-400 group-hover:text-cyan-400 transition" />
              <span>{node.process_name}</span>
            </span>

            {/* PID Badge */}
            <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
              PID {node.pid}
            </span>

            {/* Parent PID Badge */}
            <span className="px-2 py-0.5 rounded text-[11px] font-mono text-slate-300 bg-slate-900 border border-slate-700 flex items-center gap-1">
              <span>PPID {node.parent_pid}</span>
              {node.parent_pid > 0 && node.is_synthetic && (
                <span className="text-[9px] text-amber-400 font-semibold">• Defunct</span>
              )}
            </span>

            {/* Terminated Status Indicator */}
            {node.is_terminated ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1">
                <Clock className="w-3 h-3 text-slate-400" />
                <span>Terminated</span>
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800/80 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                <span>Active</span>
              </span>
            )}

            {/* Telemetry Source Provenance Badge */}
            {node.source === 'sysmon_live' || node.source === 'live_monitor' || node.source === 'sysmon_agent' ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/70 flex items-center gap-1 shadow-sm">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                <span>Live Endpoint</span>
              </span>
            ) : node.source === 'safe_simulator' ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold bg-purple-950/80 text-purple-300 border border-purple-800 flex items-center gap-1">
                <span>Simulated</span>
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold bg-slate-800/80 text-slate-400 border border-slate-700 flex items-center gap-1">
                <span>Baseline</span>
              </span>
            )}
          </div>

          {/* Right Badges: Signature Status & Risk Score */}
          <div className="flex items-center gap-2">
            {/* Signature Status */}
            <span
              className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold flex items-center gap-1 border ${
                isValidSig
                  ? 'bg-emerald-950/70 text-emerald-400 border-emerald-800'
                  : isUnsigned
                  ? 'bg-amber-950/70 text-amber-300 border-amber-800'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}
            >
              {isValidSig ? <ShieldCheck className="w-3 h-3 text-emerald-400" /> : <ShieldAlert className="w-3 h-3 text-amber-400" />}
              <span>{node.signature_status}</span>
            </span>

            {/* Risk Score Badge */}
            <span
              className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold border flex items-center gap-1 ${riskBadgeColor}`}
            >
              {riskScore >= 50 && <AlertTriangle className="w-3 h-3" />}
              <span>Risk: {riskScore} ({node.risk_level || (riskScore >= 50 ? 'HIGH' : 'LOW')})</span>
            </span>
          </div>
        </div>

        {/* Second Line: User Context & Publisher */}
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-slate-400 pt-0.5">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1 text-slate-300">
              <User className="w-3.5 h-3.5 text-slate-500" />
              <span>{node.username}</span>
            </span>

            {node.hostname && (
              <>
                <span className="text-slate-600">•</span>
                <span className="text-slate-400 text-[11px]">
                  Host: <span className="text-slate-200">{node.hostname}</span>
                </span>
              </>
            )}

            <span className="text-slate-600">•</span>

            <span className="text-slate-400 text-[11px]">
              Integrity: <span className="text-slate-200 font-semibold">{node.integrity_level}</span>
            </span>

            {node.publisher && (
              <>
                <span className="text-slate-600">•</span>
                <span className="text-slate-400 text-[11px] truncate max-w-[200px]" title={node.publisher}>
                  {node.publisher}
                </span>
              </>
            )}
          </div>

          {hasChildren && (
            <span className="text-[11px] text-cyan-400 font-semibold">
              {node.children.length} {node.children.length === 1 ? 'child process' : 'child processes'}
            </span>
          )}
        </div>

        {/* Third Line: Command Line */}
        <div className="bg-slate-900/90 rounded-lg p-2 border border-slate-850 flex items-start justify-between gap-2 font-mono text-[11px]">
          <div className="flex items-start gap-1.5 text-slate-300 truncate">
            <Terminal className="w-3.5 h-3.5 text-slate-500 shrink-0 mt-0.5" />
            <span className="truncate select-all text-slate-200">
              {node.command_line || node.executable_path}
            </span>
          </div>
          <button
            onClick={(e) => {
              e.stopPropagation();
              copyToClipboard(node.command_line || node.executable_path, `cmd-${node.pid}`);
            }}
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition shrink-0 cursor-pointer"
            title="Copy command line"
          >
            {copiedLabel === `cmd-${node.pid}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          </button>
        </div>

        {/* Fourth Line: SHA-256 Hash */}
        <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 bg-slate-900/50 px-2 py-1 rounded border border-slate-850/60">
          <div className="flex items-center gap-1.5 truncate">
            <span className="text-slate-500 text-[10px] uppercase">SHA-256:</span>
            <span className="text-cyan-300/90 truncate font-mono text-[10px]">
              {node.sha256 || 'Not computed'}
            </span>
          </div>
          {node.sha256 && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                copyToClipboard(node.sha256, `hash-${node.pid}`);
              }}
              className="text-slate-400 hover:text-cyan-300 transition text-[10px] flex items-center gap-1 cursor-pointer shrink-0 ml-2"
            >
              {copiedLabel === `hash-${node.pid}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedLabel === `hash-${node.pid}` ? 'Copied' : 'Copy'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Render Recursive Children Branches */}
      {hasChildren && isExpanded && (
        <div className="mt-2.5 space-y-2.5">
          {node.children.map((child) => (
            <ProcessTreeBranch
              key={child.id || child.pid}
              node={child}
              level={level + 1}
              expandAllDefault={expandAllDefault}
              searchQuery={searchQuery}
              onSelectProcess={onSelectProcess}
              copyToClipboard={copyToClipboard}
              copiedLabel={copiedLabel}
            />
          ))}
        </div>
      )}
    </div>
  );
};

interface ProcessDetailInspectorProps {
  node: ProcessTreeNode;
  allTree: ProcessTreeNode[];
  onClose: () => void;
  onNavigateProcess: (pid: number) => void;
  copyToClipboard: (text: string, label: string) => void;
  copiedLabel: string | null;
}

const ProcessDetailInspector: React.FC<ProcessDetailInspectorProps> = ({
  node,
  allTree,
  onClose,
  onNavigateProcess,
  copyToClipboard,
  copiedLabel
}) => {
  // Reconstruct Ancestor Path for Breadcrumbs
  const buildAncestorPath = (
    current: ProcessTreeNode,
    targetPid: number,
    path: ProcessTreeNode[]
  ): ProcessTreeNode[] | null => {
    if (current.pid === targetPid) return [...path, current];
    for (const child of current.children) {
      const found = buildAncestorPath(child, targetPid, [...path, current]);
      if (found) return found;
    }
    return null;
  };

  let ancestors: ProcessTreeNode[] = [];
  for (const root of allTree) {
    const p = buildAncestorPath(root, node.pid, []);
    if (p) {
      ancestors = p;
      break;
    }
  }

  const riskScore = node.risk_score ?? 0;

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full p-6 space-y-5 shadow-2xl overflow-y-auto max-h-[90vh]">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-slate-800 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="font-bold text-white text-lg font-mono">{node.process_name}</span>
              <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                PID {node.pid}
              </span>
              <span className="px-2 py-0.5 rounded text-xs font-mono text-slate-300 bg-slate-800 border border-slate-700">
                PPID {node.parent_pid}
              </span>
              <span
                className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${
                  node.source === 'sysmon_live' || node.source === 'live_monitor' || node.source === 'sysmon_agent'
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-500/70'
                    : node.source === 'safe_simulator'
                    ? 'bg-purple-950 text-purple-300 border-purple-800'
                    : 'bg-slate-800 text-slate-300 border-slate-700'
                }`}
              >
                {node.source === 'sysmon_live' || node.source === 'live_monitor' || node.source === 'sysmon_agent'
                  ? '🟢 Live Endpoint'
                  : node.source === 'safe_simulator'
                  ? '🟣 Simulation'
                  : '⚪ Baseline Seed'}
              </span>
              <span
                className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${
                  riskScore >= 75
                    ? 'bg-rose-950 text-rose-300 border-rose-800'
                    : riskScore >= 50
                    ? 'bg-orange-950 text-orange-300 border-orange-800'
                    : riskScore >= 25
                    ? 'bg-amber-950 text-amber-300 border-amber-800'
                    : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                }`}
              >
                Risk: {riskScore} ({node.risk_level || 'LOW'})
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Started: {new Date(node.creation_timestamp).toLocaleString()}
              {node.is_terminated && node.termination_timestamp && (
                <span> • Terminated: {new Date(node.termination_timestamp).toLocaleString()}</span>
              )}
            </p>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Upstream Ancestor Lineage Breadcrumb */}
        {ancestors.length > 1 && (
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1 text-xs font-mono">
            <span className="text-[10px] uppercase text-slate-500 font-bold block">Execution Lineage Path</span>
            <div className="flex items-center gap-1.5 flex-wrap">
              {ancestors.map((anc, idx) => (
                <React.Fragment key={anc.pid}>
                  <button
                    onClick={() => onNavigateProcess(anc.pid)}
                    className={`px-2 py-0.5 rounded transition cursor-pointer ${
                      anc.pid === node.pid
                        ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800'
                        : 'bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-white'
                    }`}
                  >
                    {anc.process_name} ({anc.pid})
                  </button>
                  {idx < ancestors.length - 1 && (
                    <ArrowRight className="w-3 h-3 text-slate-600" />
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>
        )}

        {/* Risk Score Assessment Breakdown */}
        <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2.5 font-mono text-xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] uppercase text-slate-400 font-bold flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Security Risk Assessment &amp; Factors
            </span>
            <span className="font-bold text-white">{riskScore} / 100</span>
          </div>

          {/* Progress bar */}
          <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full transition-all ${
                riskScore >= 75
                  ? 'bg-rose-500'
                  : riskScore >= 50
                  ? 'bg-orange-500'
                  : riskScore >= 25
                  ? 'bg-amber-400'
                  : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.max(5, riskScore)}%` }}
            />
          </div>

          {/* Risk Factors Bullet List */}
          <div className="space-y-1 pt-1">
            {(node.risk_factors && node.risk_factors.length > 0) ? (
              node.risk_factors.map((factor, i) => (
                <div key={i} className="flex items-start gap-2 text-slate-300 text-[11px]">
                  <span className="text-cyan-400 font-bold">•</span>
                  <span>{factor}</span>
                </div>
              ))
            ) : (
              <div className="text-slate-500 text-[11px]">No abnormal risk indicators observed.</div>
            )}
          </div>
        </div>

        {/* Process Attributes Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase block">User Security Context</span>
            <span className="text-white font-semibold">{node.username}</span>
            <span className="text-slate-400 text-[11px] block">Integrity Level: {node.integrity_level}</span>
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase block">Authenticode Digital Signature</span>
            <span className={`font-semibold ${node.signature_status === 'Valid' ? 'text-emerald-400' : 'text-amber-400'}`}>
              {node.signature_status}
            </span>
            <span className="text-slate-400 text-[11px] block">{node.publisher || 'Publisher not registered'}</span>
          </div>
        </div>

        {/* Executable Path */}
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1 text-xs font-mono">
          <div className="flex items-center justify-between text-[10px] text-slate-500">
            <span>EXECUTABLE BINARY PATH</span>
            <button
              onClick={() => copyToClipboard(node.executable_path, 'inspect-path')}
              className="flex items-center gap-1 text-cyan-400 hover:underline cursor-pointer"
            >
              {copiedLabel === 'inspect-path' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedLabel === 'inspect-path' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="text-slate-200 break-all select-all">{node.executable_path}</div>
        </div>

        {/* Command Line */}
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1 text-xs font-mono">
          <div className="flex items-center justify-between text-[10px] text-slate-500">
            <span>FULL COMMAND LINE ARGUMENTS</span>
            <button
              onClick={() => copyToClipboard(node.command_line, 'inspect-cmd')}
              className="flex items-center gap-1 text-cyan-400 hover:underline cursor-pointer"
            >
              {copiedLabel === 'inspect-cmd' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedLabel === 'inspect-cmd' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="text-slate-200 break-all select-all bg-slate-900 p-2.5 rounded border border-slate-800">
            {node.command_line || node.executable_path}
          </div>
        </div>

        {/* SHA-256 Hash */}
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1 text-xs font-mono">
          <div className="flex items-center justify-between text-[10px] text-slate-500">
            <span>BINARY SHA-256 HASH</span>
            {node.sha256 && (
              <button
                onClick={() => copyToClipboard(node.sha256, 'inspect-sha')}
                className="flex items-center gap-1 text-cyan-400 hover:underline cursor-pointer"
              >
                {copiedLabel === 'inspect-sha' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedLabel === 'inspect-sha' ? 'Copied' : 'Copy'}</span>
              </button>
            )}
          </div>
          <div className="text-cyan-300 break-all font-mono text-[11px] select-all">
            {node.sha256 || 'Hash not available.'}
          </div>
        </div>

        {/* Direct Children Sub-processes */}
        {node.children && node.children.length > 0 && (
          <div className="space-y-2 text-xs font-mono">
            <span className="text-[10px] uppercase text-slate-500 font-bold block">
              Direct Child Processes Spawned ({node.children.length})
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {node.children.map(child => (
                <div
                  key={child.pid}
                  onClick={() => onNavigateProcess(child.pid)}
                  className="p-2.5 bg-slate-950 rounded border border-slate-800 hover:border-cyan-500 transition cursor-pointer flex items-center justify-between"
                >
                  <div>
                    <span className="font-bold text-white block">{child.process_name}</span>
                    <span className="text-[10px] text-slate-400">PID {child.pid} • {child.username}</span>
                  </div>
                  <span className="text-xs text-cyan-400 hover:underline flex items-center gap-1">
                    <span>Inspect</span>
                    <ArrowRight className="w-3 h-3" />
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Footer actions */}
        <div className="flex items-center justify-between pt-3 border-t border-slate-800 text-xs font-mono">
          <div className="text-slate-500 text-[11px]">
            {node.is_terminated ? 'Parent/Process terminated; relationship preserved.' : 'Process is actively executing.'}
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold cursor-pointer"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
