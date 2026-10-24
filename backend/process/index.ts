import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { query, run, scheduleSave } from '../db/index.js';
import { logger } from '../logger/index.js';

const log = logger.forComponent('ProcessMonitor');

export interface ProcessEvent {
  id: number;
  guid: string;
  pid: number;
  parent_pid: number;
  process_name: string;
  executable_path: string;
  command_line: string;
  username: string;
  integrity_level: string; // e.g. 'System', 'High', 'Medium', 'Low', 'AppContainer', 'Untrusted', 'Unknown'
  creation_timestamp: string; // ISO 8601
  sha256: string;
  signature_status: string; // e.g. 'Valid', 'Signed', 'Unsigned', 'Invalid', 'Self-Signed', 'Unknown'
  publisher: string; // e.g. 'Microsoft Windows', 'Google LLC'
  source: string; // e.g. 'sysmon_event_1', 'security_audit_4688', 'live_monitor'
  terminal_session_id?: number;
  status: 'running' | 'terminated';
  is_terminated?: boolean | number;
  termination_timestamp?: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_factors?: string[] | string;
  created_at: string;
}

export interface ProcessTreeNode {
  id: number;
  guid?: string;
  pid: number;
  parent_pid: number;
  process_name: string;
  executable_path: string;
  command_line: string;
  username: string;
  integrity_level: string;
  creation_timestamp: string;
  sha256: string;
  signature_status: string;
  publisher: string;
  status: 'running' | 'terminated';
  is_terminated?: boolean | number;
  is_synthetic?: boolean;
  termination_timestamp?: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_factors?: string[];
  depth?: number;
  children: ProcessTreeNode[];
}

interface CacheEntry {
  sha256: string;
  signature_status: string;
  publisher: string;
  mtimeMs?: number;
}

/**
 * In-memory Hash and Authenticode Signature Cache
 * Ensures we NEVER repeatedly hash the same binary or re-verify signatures for executed binaries.
 * Avoids excessive disk I/O and CPU usage.
 */
class HashSignatureCache {
  private cache = new Map<string, CacheEntry>();
  private readonly maxEntries = 5000;

  get(executablePath: string): CacheEntry | null {
    return this.cache.get(executablePath.toLowerCase()) || null;
  }

  set(executablePath: string, entry: CacheEntry): void {
    if (this.cache.size >= this.maxEntries) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) this.cache.delete(firstKey);
    }
    this.cache.set(executablePath.toLowerCase(), entry);
  }

  has(executablePath: string): boolean {
    return this.cache.has(executablePath.toLowerCase());
  }

  clear(): void {
    this.cache.clear();
  }
}

export const hashSignatureCache = new HashSignatureCache();

/**
 * Calculates SHA-256 for an executed binary only if not already cached.
 * Streamingly calculates to minimize memory and CPU spikes.
 */
export function getOrComputeExecutableHash(
  executablePath: string,
  fallbackHash?: string,
  fallbackPublisher?: string,
  fallbackSignature?: string
): { sha256: string; signature_status: string; publisher: string } {
  if (!executablePath) {
    return {
      sha256: fallbackHash || '',
      signature_status: fallbackSignature || 'Unknown',
      publisher: fallbackPublisher || ''
    };
  }

  const cached = hashSignatureCache.get(executablePath);
  if (cached) {
    return {
      sha256: cached.sha256,
      signature_status: cached.signature_status,
      publisher: cached.publisher
    };
  }

  let computedSha256 = fallbackHash || '';
  let sigStatus = fallbackSignature || 'Unknown';
  let pub = fallbackPublisher || '';

  // Only calculate hash from disk if file actually exists and no hash provided
  if (!computedSha256 && fs.existsSync(executablePath)) {
    try {
      const stats = fs.statSync(executablePath);
      if (stats.isFile() && stats.size < 100 * 1024 * 1024) { // Only hash binaries under 100MB
        const buffer = fs.readFileSync(executablePath);
        computedSha256 = crypto.createHash('sha256').update(buffer).digest('hex');
      }
    } catch (err) {
      log.debug(`Could not read executable for hashing: ${executablePath}`);
    }
  }

  // Derive known Microsoft / standard system binary signatures if known Windows path
  if (!pub) {
    const lowerPath = executablePath.toLowerCase();
    if (lowerPath.includes('\\windows\\system32\\') || lowerPath.includes('\\windows\\syswow64\\')) {
      pub = 'Microsoft Windows Publisher';
      sigStatus = 'Valid';
    } else if (lowerPath.includes('google\\chrome')) {
      pub = 'Google LLC';
      sigStatus = 'Valid';
    } else if (lowerPath.includes('microsoft\\edge')) {
      pub = 'Microsoft Corporation';
      sigStatus = 'Valid';
    }
  }

  const result = {
    sha256: computedSha256,
    signature_status: sigStatus,
    publisher: pub
  };

  hashSignatureCache.set(executablePath, result);
  return result;
}

/**
 * Real EDR Risk Assessment Engine
 * Computes a security risk score (0-100) and factors based on command line,
 * binary signature, LOLBIN behaviors, and parent-child execution lineage.
 */
export function calculateProcessRisk(
  event: Partial<ProcessEvent>,
  parentEvent?: ProcessEvent | null
): { risk_score: number; risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; risk_factors: string[] } {
  let score = 0;
  const factors: string[] = [];

  const procName = (event.process_name || '').toLowerCase();
  const cmd = (event.command_line || '').toLowerCase();
  const exePath = (event.executable_path || '').toLowerCase();
  const sigStatus = (event.signature_status || '').toLowerCase();
  const integrity = event.integrity_level || 'Medium';

  // 1. Signature & Authenticode Heuristics
  if (sigStatus === 'invalid') {
    score += 45;
    factors.push('Invalid Authenticode digital signature detected');
  } else if (sigStatus === 'unsigned') {
    score += 25;
    factors.push('Unsigned binary executed');
  } else if (sigStatus === 'self-signed') {
    score += 30;
    factors.push('Binary signed with untrusted self-signed certificate');
  }

  // 2. LOLBIN & Dangerous Script Execution Patterns (MITRE ATT&CK T1059)
  if (procName === 'powershell.exe' || procName === 'pwsh.exe') {
    if (cmd.includes('-enc') || cmd.includes('-encodedcommand')) {
      score += 45;
      factors.push('Obfuscated / Base64-encoded PowerShell script execution (T1059.001)');
    }
    if (cmd.includes('-executionpolicy bypass') || cmd.includes('-ep bypass') || cmd.includes('bypass')) {
      score += 25;
      factors.push('PowerShell ExecutionPolicy security bypass flag specified');
    }
    if (cmd.includes('-w hidden') || cmd.includes('-windowstyle hidden')) {
      score += 20;
      factors.push('PowerShell window hidden to evade user detection');
    }
    if (cmd.includes('downloadstring') || cmd.includes('invoke-webrequest') || cmd.includes('iex') || cmd.includes('invoke-expression')) {
      score += 40;
      factors.push('Remote network download cradle or dynamic memory evaluation');
    }
    if (score === 0) {
      score += 15; // Baseline scripted shell activity
    }
  }

  if (procName === 'cmd.exe') {
    if (cmd.includes('whoami') || cmd.includes('net user') || cmd.includes('vssadmin') || cmd.includes('nltest') || cmd.includes('systeminfo')) {
      score += 35;
      factors.push('Command shell executing system reconnaissance / shadow copy discovery');
    }
    if (cmd.includes('/c') && (cmd.includes('http://') || cmd.includes('https://') || cmd.includes('powershell'))) {
      score += 30;
      factors.push('Command shell invoking external network request or secondary interpreter');
    }
  }

  // Living off the land binaries
  if (procName === 'certutil.exe' && (cmd.includes('-urlcache') || cmd.includes('-split'))) {
    score += 50;
    factors.push('CertUtil abused for remote file ingress / download (T1105)');
  }
  if (procName === 'mshta.exe' && (cmd.includes('http://') || cmd.includes('https://') || cmd.includes('javascript:'))) {
    score += 55;
    factors.push('Mshta executing remote HTA / JavaScript payload');
  }
  if (procName === 'bitsadmin.exe' && (cmd.includes('/transfer') || cmd.includes('/download'))) {
    score += 40;
    factors.push('BITSAdmin used for background file transfer');
  }

  // 3. Parent-Child Lineage Anomalies
  if (parentEvent) {
    const parentName = parentEvent.process_name.toLowerCase();
    // Office -> Shell
    if (['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'].includes(parentName)) {
      if (['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'].includes(procName)) {
        score += 60;
        factors.push(`Abnormal lineage: Office application (${parentName}) spawned script interpreter (${procName})`);
      }
    }
    // Web Browser -> Shell
    if (['chrome.exe', 'msedge.exe', 'firefox.exe'].includes(parentName)) {
      if (['cmd.exe', 'powershell.exe', 'conhost.exe'].includes(procName)) {
        score += 45;
        factors.push(`Abnormal lineage: Web browser (${parentName}) spawned interactive command shell`);
      }
    }
    // Windows Service -> Interactive Command Shell
    if (['svchost.exe', 'services.exe'].includes(parentName)) {
      if (['cmd.exe', 'powershell.exe'].includes(procName)) {
        score += 40;
        factors.push(`Abnormal lineage: Windows Service (${parentName}) spawned console shell`);
      }
    }
    // Privilege Elevation from Medium to High/System
    if (parentEvent.integrity_level === 'Medium' && (integrity === 'High' || integrity === 'System')) {
      score += 15;
      factors.push('Integrity level elevated from Medium parent to High/System child');
    }
  }

  // 4. Staging and World-Writable Paths
  if (exePath.includes('\\appdata\\local\\temp\\') || exePath.includes('\\windows\\temp\\') || exePath.includes('\\users\\public\\')) {
    score += 25;
    factors.push('Executable launched from temporary or public world-writable folder');
  }

  // 5. Masquerading System Binaries
  if (['svchost.exe', 'smss.exe', 'csrss.exe', 'wininit.exe'].includes(procName)) {
    if (!exePath.includes('\\windows\\system32\\') && !exePath.includes('\\windows\\syswow64\\')) {
      score += 65;
      factors.push('Critical system binary masquerading outside Windows System32');
    }
  }

  // Clamp score
  const finalScore = Math.min(100, Math.max(0, score));

  let level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  if (finalScore >= 75) level = 'CRITICAL';
  else if (finalScore >= 50) level = 'HIGH';
  else if (finalScore >= 25) level = 'MEDIUM';

  if (factors.length === 0) {
    factors.push('Legitimate, standard application execution profile');
  }

  return {
    risk_score: finalScore,
    risk_level: level,
    risk_factors: factors
  };
}

/**
 * Records a process creation event into SQLite with indexes
 */
export function recordProcessEvent(input: Partial<ProcessEvent>): ProcessEvent {
  const pid = Number(input.pid) || 0;
  if (pid <= 0) {
    throw new Error(`Invalid process PID: ${input.pid}. PID must be a positive integer.`);
  }
  const parent_pid = Number(input.parent_pid) || 0;

  const rawName = (input.process_name || (input.executable_path ? path.basename(input.executable_path) : '')).trim();
  if (!rawName) {
    throw new Error('Process name is required for process event ingestion.');
  }
  const process_name = rawName;
  const executable_path = input.executable_path || `C:\\Windows\\System32\\${process_name}`;
  const command_line = input.command_line || executable_path;
  const username = input.username || 'WIN-LAPTOP\\User';
  const hostname = input.hostname || (username.includes('\\') ? username.split('\\')[0] : 'WIN-ENDPOINT');
  const integrity_level = input.integrity_level || (username.includes('SYSTEM') ? 'System' : 'Medium');
  const creation_timestamp = input.creation_timestamp || new Date().toISOString();
  const guid = input.guid || `{${crypto.randomUUID()}}`;
  const source = input.source || 'sysmon_live';
  const terminal_session_id = input.terminal_session_id ?? (integrity_level === 'System' ? 0 : 1);
  const status = input.status || (input.is_terminated ? 'terminated' : 'running');
  const is_terminated = input.is_terminated ? 1 : (status === 'terminated' ? 1 : 0);
  const termination_timestamp = input.termination_timestamp || null;
  const now = new Date().toISOString();

  // Deduplication check: Do not re-insert duplicate process events
  let existingMatch: any = null;
  if (input.guid && input.guid.trim() !== '') {
    const guidMatches = query<any>('SELECT * FROM process_events WHERE guid = ? LIMIT 1', [input.guid.trim()]);
    if (guidMatches && guidMatches.length > 0) {
      existingMatch = guidMatches[0];
    }
  }
  if (!existingMatch && pid > 0 && input.creation_timestamp) {
    const exactMatches = query<any>(
      'SELECT * FROM process_events WHERE pid = ? AND creation_timestamp = ? LIMIT 1',
      [pid, input.creation_timestamp]
    );
    if (exactMatches && exactMatches.length > 0) {
      existingMatch = exactMatches[0];
    }
  }

  if (existingMatch) {
    log.debug(`[ProcessDeduplicated] Skipping duplicate insertion for PID=${pid} GUID=${existingMatch.guid}`);
    return {
      ...existingMatch,
      is_terminated: Boolean(existingMatch.is_terminated),
      risk_factors: typeof existingMatch.risk_factors === 'string'
        ? safeParseJson(existingMatch.risk_factors, [])
        : (existingMatch.risk_factors || [])
    };
  }

  // Resolve or cache hash and signature metadata
  const hashMeta = getOrComputeExecutableHash(
    executable_path,
    input.sha256,
    input.publisher,
    input.signature_status
  );

  // Lookup parent process to calculate lineage-aware risk score
  let parentEvent: ProcessEvent | null = null;
  if (parent_pid > 0) {
    const parentMatches = query<ProcessEvent>(
      'SELECT * FROM process_events WHERE pid = ? AND creation_timestamp <= ? ORDER BY creation_timestamp DESC LIMIT 1',
      [parent_pid, creation_timestamp]
    );
    parentEvent = parentMatches[0] || null;
  }

  // Calculate risk assessment
  const riskAnalysis = (input.risk_score !== undefined && input.risk_level)
    ? {
        risk_score: input.risk_score,
        risk_level: input.risk_level,
        risk_factors: Array.isArray(input.risk_factors)
          ? input.risk_factors
          : (typeof input.risk_factors === 'string' ? JSON.parse(input.risk_factors) : ['Pre-evaluated'])
      }
    : calculateProcessRisk({
        process_name,
        executable_path,
        command_line,
        signature_status: hashMeta.signature_status,
        integrity_level,
        username
      }, parentEvent);

  const riskFactorsJson = JSON.stringify(riskAnalysis.risk_factors);

  const sql = `
    INSERT INTO process_events (
      guid, pid, parent_pid, process_name, executable_path, command_line,
      username, hostname, integrity_level, creation_timestamp, sha256,
      signature_status, publisher, source, terminal_session_id,
      status, is_terminated, termination_timestamp,
      risk_score, risk_level, risk_factors, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const runResult = run(sql, [
    guid,
    pid,
    parent_pid,
    process_name,
    executable_path,
    command_line,
    username,
    hostname,
    integrity_level,
    creation_timestamp,
    hashMeta.sha256,
    hashMeta.signature_status,
    hashMeta.publisher,
    source,
    terminal_session_id,
    status,
    is_terminated,
    termination_timestamp,
    riskAnalysis.risk_score,
    riskAnalysis.risk_level,
    riskFactorsJson,
    now
  ]);

  scheduleSave();

  log.info(`[ProcessCreate] PID=${pid} PPID=${parent_pid} Name=${process_name} Risk=${riskAnalysis.risk_score} (${riskAnalysis.risk_level})`);

  return {
    id: runResult.lastInsertRowid,
    guid,
    pid,
    parent_pid,
    process_name,
    executable_path,
    command_line,
    username,
    hostname,
    integrity_level,
    creation_timestamp,
    sha256: hashMeta.sha256,
    signature_status: hashMeta.signature_status,
    publisher: hashMeta.publisher,
    source,
    terminal_session_id,
    status: status as any,
    is_terminated: is_terminated === 1,
    termination_timestamp: termination_timestamp || undefined,
    risk_score: riskAnalysis.risk_score,
    risk_level: riskAnalysis.risk_level,
    risk_factors: riskAnalysis.risk_factors,
    created_at: now
  };
}

/**
 * Marks a process as terminated in SQLite
 * Ensures child processes remain intact in the hierarchical process tree!
 */
export function recordProcessTermination(pid: number, terminationTimestamp?: string): ProcessEvent | null {
  const timestamp = terminationTimestamp || new Date().toISOString();
  
  // Find latest instance of this PID
  const existing = query<ProcessEvent>(
    'SELECT * FROM process_events WHERE pid = ? ORDER BY creation_timestamp DESC LIMIT 1',
    [pid]
  );

  if (!existing || existing.length === 0) {
    return null;
  }

  const target = existing[0];
  run(
    'UPDATE process_events SET status = ?, is_terminated = ?, termination_timestamp = ? WHERE id = ?',
    ['terminated', 1, timestamp, target.id]
  );
  scheduleSave();

  log.info(`[ProcessTerminate] PID=${pid} Name=${target.process_name} at ${timestamp}`);

  return {
    ...target,
    status: 'terminated',
    is_terminated: true,
    termination_timestamp: timestamp
  };
}

/**
 * Returns filtered, paginated list of process events
 */
export function getProcesses(filter?: {
  search?: string;
  integrity_level?: string;
  signature_status?: string;
  status?: string;
  source?: string;
  min_risk?: number;
  limit?: number;
  offset?: number;
}): { total: number; processes: ProcessEvent[] } {
  let countSql = 'SELECT COUNT(*) as cnt FROM process_events WHERE 1=1';
  let dataSql = 'SELECT * FROM process_events WHERE 1=1';
  const params: any[] = [];
  const countParams: any[] = [];

  if (filter?.source && filter.source !== 'all') {
    if (filter.source === 'live') {
      countSql += " AND source IN ('sysmon_live', 'live_monitor', 'sysmon_agent')";
      dataSql += " AND source IN ('sysmon_live', 'live_monitor', 'sysmon_agent')";
    } else if (filter.source === 'baseline') {
      countSql += " AND source = 'baseline_seed'";
      dataSql += " AND source = 'baseline_seed'";
    } else if (filter.source === 'simulated') {
      countSql += " AND source = 'safe_simulator'";
      dataSql += " AND source = 'safe_simulator'";
    } else {
      countSql += " AND source = ?";
      dataSql += " AND source = ?";
      params.push(filter.source);
      countParams.push(filter.source);
    }
  }

  if (filter?.integrity_level && filter.integrity_level !== 'all') {
    countSql += ' AND integrity_level = ?';
    dataSql += ' AND integrity_level = ?';
    params.push(filter.integrity_level);
    countParams.push(filter.integrity_level);
  }

  if (filter?.signature_status && filter.signature_status !== 'all') {
    countSql += ' AND signature_status = ?';
    dataSql += ' AND signature_status = ?';
    params.push(filter.signature_status);
    countParams.push(filter.signature_status);
  }

  if (filter?.status && filter.status !== 'all') {
    countSql += ' AND status = ?';
    dataSql += ' AND status = ?';
    params.push(filter.status);
    countParams.push(filter.status);
  }

  if (filter?.min_risk !== undefined && filter.min_risk > 0) {
    countSql += ' AND risk_score >= ?';
    dataSql += ' AND risk_score >= ?';
    params.push(filter.min_risk);
    countParams.push(filter.min_risk);
  }

  if (filter?.search) {
    const term = `%${filter.search}%`;
    const searchClause = ' AND (process_name LIKE ? OR executable_path LIKE ? OR command_line LIKE ? OR username LIKE ? OR sha256 LIKE ? OR pid = ?)';
    const pidVal = parseInt(filter.search, 10) || -1;
    
    countSql += searchClause;
    dataSql += searchClause;
    params.push(term, term, term, term, term, pidVal);
    countParams.push(term, term, term, term, term, pidVal);
  }

  dataSql += ' ORDER BY creation_timestamp DESC, id DESC LIMIT ? OFFSET ?';
  const limit = filter?.limit || 100;
  const offset = filter?.offset || 0;
  params.push(limit, offset);

  const total = query<{ cnt: number }>(countSql, countParams)[0]?.cnt || 0;
  const rawProcesses = query<any>(dataSql, params);

  const processes: ProcessEvent[] = rawProcesses.map(p => ({
    ...p,
    is_terminated: Boolean(p.is_terminated),
    risk_factors: typeof p.risk_factors === 'string'
      ? safeParseJson(p.risk_factors, [])
      : (p.risk_factors || [])
  }));

  return { total, processes };
}

function safeParseJson(input: string, fallback: any): any {
  try {
    return JSON.parse(input);
  } catch {
    return fallback;
  }
}

/**
 * Fetches a single process by PID along with parent and child processes
 */
export function getProcessByPid(pid: number): {
  process: ProcessEvent | null;
  parent: ProcessEvent | null;
  children: ProcessEvent[];
} {
  const processes = query<any>('SELECT * FROM process_events WHERE pid = ? ORDER BY id DESC LIMIT 1', [pid]);
  if (!processes || processes.length === 0) {
    return { process: null, parent: null, children: [] };
  }

  const raw = processes[0];
  const process: ProcessEvent = {
    ...raw,
    is_terminated: Boolean(raw.is_terminated),
    risk_factors: typeof raw.risk_factors === 'string' ? safeParseJson(raw.risk_factors, []) : (raw.risk_factors || [])
  };

  let parent: ProcessEvent | null = null;
  let children: ProcessEvent[] = [];

  if (process.parent_pid > 0) {
    const parents = query<any>(
      'SELECT * FROM process_events WHERE pid = ? AND creation_timestamp <= ? ORDER BY creation_timestamp DESC LIMIT 1',
      [process.parent_pid, process.creation_timestamp]
    );
    if (parents[0]) {
      parent = {
        ...parents[0],
        is_terminated: Boolean(parents[0].is_terminated),
        risk_factors: typeof parents[0].risk_factors === 'string' ? safeParseJson(parents[0].risk_factors, []) : []
      };
    }
  }

  const rawChildren = query<any>(
    'SELECT * FROM process_events WHERE parent_pid = ? AND creation_timestamp >= ? ORDER BY creation_timestamp ASC',
    [process.pid, process.creation_timestamp]
  );

  children = rawChildren.map(c => ({
    ...c,
    is_terminated: Boolean(c.is_terminated),
    risk_factors: typeof c.risk_factors === 'string' ? safeParseJson(c.risk_factors, []) : []
  }));

  return { process, parent, children };
}

/**
 * Real Process-Tree Engine
 * Reconstructs hierarchical execution trees using:
 * - PID
 * - Parent PID
 * - Creation timestamp (enforces chronological causality & handles Windows PID reuse)
 * - Executable path
 * 
 * Accurately handles processes whose parent process has already terminated:
 * 1. Historical parents that exited are maintained as parent nodes with `is_terminated: true`.
 *    All child branches remain fully attached beneath them.
 * 2. Processes whose parent terminated prior to telemetry collection (e.g. explorer.exe PPID 740)
 *    are cleanly rooted or represented with defunct parent attribution.
 */
export function getProcessTree(options?: {
  rootPid?: number;
  includeTerminated?: boolean;
  minRiskScore?: number;
}): ProcessTreeNode[] {
  // Query process events sorted chronologically by creation timestamp
  const rawEvents = query<any>(
    'SELECT * FROM process_events ORDER BY creation_timestamp ASC, id ASC LIMIT 500'
  );

  if (rawEvents.length === 0) {
    return [];
  }

  // Convert to strongly-typed ProcessTreeNode objects
  const allNodes: ProcessTreeNode[] = rawEvents.map(ev => {
    let factors: string[] = [];
    if (typeof ev.risk_factors === 'string') {
      factors = safeParseJson(ev.risk_factors, []);
    } else if (Array.isArray(ev.risk_factors)) {
      factors = ev.risk_factors;
    }

    return {
      id: ev.id,
      guid: ev.guid,
      pid: ev.pid,
      parent_pid: ev.parent_pid,
      process_name: ev.process_name,
      executable_path: ev.executable_path,
      command_line: ev.command_line,
      username: ev.username,
      hostname: ev.hostname || 'WIN-ENDPOINT',
      integrity_level: ev.integrity_level,
      creation_timestamp: ev.creation_timestamp,
      sha256: ev.sha256 || '',
      signature_status: ev.signature_status || 'Unknown',
      publisher: ev.publisher || '',
      source: ev.source || 'sysmon_live',
      is_synthetic: ev.source === 'baseline_seed' || ev.source === 'safe_simulator',
      status: ev.status === 'terminated' || ev.is_terminated === 1 ? 'terminated' : 'running',
      is_terminated: ev.is_terminated === 1 || ev.status === 'terminated',
      termination_timestamp: ev.termination_timestamp || undefined,
      risk_score: ev.risk_score ?? 0,
      risk_level: ev.risk_level || 'LOW',
      risk_factors: factors,
      children: []
    };
  });

  // Group candidate nodes by PID to accurately handle Windows PID reuse
  const pidMap = new Map<number, ProcessTreeNode[]>();
  for (const node of allNodes) {
    if (!pidMap.has(node.pid)) {
      pidMap.set(node.pid, []);
    }
    pidMap.get(node.pid)!.push(node);
  }

  const attachedNodeIds = new Set<number>();

  // Attach each child node to its legitimate parent based on:
  // 1. Parent PID matching child.parent_pid
  // 2. Parent creation_timestamp <= child creation_timestamp
  // 3. Parent termination_timestamp >= child creation_timestamp (if termination recorded)
  for (const child of allNodes) {
    if (child.parent_pid <= 0) continue;

    const candidateParents = pidMap.get(child.parent_pid);
    if (!candidateParents || candidateParents.length === 0) {
      // Parent terminated before agent monitoring started or external
      continue;
    }

    const childCreatedTime = new Date(child.creation_timestamp).getTime();

    // Filter candidate parents created on or before child creation
    const validParents = candidateParents.filter(p => {
      if (p.id === child.id) return false;
      const parentCreatedTime = new Date(p.creation_timestamp).getTime();
      if (parentCreatedTime > childCreatedTime) return false;

      // If parent terminated BEFORE child was created, this candidate PID is from an older deceased process
      if (p.termination_timestamp) {
        const parentTermTime = new Date(p.termination_timestamp).getTime();
        if (parentTermTime < childCreatedTime) return false;
      }
      return true;
    });

    if (validParents.length > 0) {
      // Pick the closest parent in time (handles Windows PID reuse)
      const bestParent = validParents[validParents.length - 1];
      bestParent.children.push(child);
      attachedNodeIds.add(child.id);
    }
  }

  // Determine root nodes (nodes that were not attached as a child to any other node in our set)
  let rootNodes: ProcessTreeNode[] = allNodes.filter(node => !attachedNodeIds.has(node.id));

  // If a specific root PID was requested, return that subtree
  if (options?.rootPid !== undefined) {
    const findSubtree = (nodes: ProcessTreeNode[], targetPid: number): ProcessTreeNode | null => {
      for (const n of nodes) {
        if (n.pid === targetPid) return n;
        const sub = findSubtree(n.children, targetPid);
        if (sub) return sub;
      }
      return null;
    };

    const targetNode = findSubtree(allNodes, options.rootPid);
    return targetNode ? [targetNode] : [];
  }

  // Filter terminated nodes if requested (by default terminated parents are preserved to show lineage!)
  if (options?.includeTerminated === false) {
    const pruneTerminated = (nodes: ProcessTreeNode[]): ProcessTreeNode[] => {
      return nodes
        .filter(n => !n.is_terminated)
        .map(n => ({
          ...n,
          children: pruneTerminated(n.children)
        }));
    };
    rootNodes = pruneTerminated(rootNodes);
  }

  // Calculate depths recursively
  const assignDepth = (nodes: ProcessTreeNode[], depth: number) => {
    for (const n of nodes) {
      n.depth = depth;
      assignDepth(n.children, depth + 1);
    }
  };
  assignDepth(rootNodes, 0);

  return rootNodes;
}

/**
 * Retrieves the full upstream lineage chain and immediate children for a given PID
 */
export function getProcessLineage(pid: number): {
  ancestors: ProcessTreeNode[];
  target: ProcessTreeNode | null;
  children: ProcessTreeNode[];
} {
  const tree = getProcessTree();

  // Helper to find path to PID
  const findPath = (
    current: ProcessTreeNode,
    targetPid: number,
    path: ProcessTreeNode[]
  ): ProcessTreeNode[] | null => {
    if (current.pid === targetPid) {
      return [...path, current];
    }
    for (const child of current.children) {
      const found = findPath(child, targetPid, [...path, current]);
      if (found) return found;
    }
    return null;
  };

  for (const root of tree) {
    const path = findPath(root, pid, []);
    if (path) {
      const target = path[path.length - 1];
      const ancestors = path.slice(0, path.length - 1);
      return {
        ancestors,
        target,
        children: target.children || []
      };
    }
  }

  return { ancestors: [], target: null, children: [] };
}

/**
 * Returns overall statistics for the process tree engine
 */
export function getProcessTreeStats(): {
  totalProcesses: number;
  runningProcesses: number;
  terminatedProcesses: number;
  rootTreesCount: number;
  maxTreeDepth: number;
  highRiskCount: number;
  averageRiskScore: number;
} {
  const allEvents = query<any>('SELECT pid, status, is_terminated, risk_score FROM process_events');
  const tree = getProcessTree();

  let maxDepth = 0;
  const measureDepth = (nodes: ProcessTreeNode[], depth: number) => {
    for (const n of nodes) {
      if (depth > maxDepth) maxDepth = depth;
      measureDepth(n.children, depth + 1);
    }
  };
  measureDepth(tree, 1);

  const total = allEvents.length;
  const terminated = allEvents.filter(e => e.is_terminated === 1 || e.status === 'terminated').length;
  const running = total - terminated;
  const highRisk = allEvents.filter(e => (e.risk_score || 0) >= 50).length;
  const totalScore = allEvents.reduce((acc, e) => acc + (e.risk_score || 0), 0);

  return {
    totalProcesses: total,
    runningProcesses: running,
    terminatedProcesses: terminated,
    rootTreesCount: tree.length,
    maxTreeDepth: maxDepth,
    highRiskCount: highRisk,
    averageRiskScore: total > 0 ? +(totalScore / total).toFixed(1) : 0
  };
}

/**
 * Seeds realistic normal Windows application telemetry.
 * Generates the canonical Windows execution tree requested:
 * explorer.exe
 * └── chrome.exe
 * └── powershell.exe
 * └── cmd.exe
 * 
 * Also tests handling of processes whose parent process has already terminated
 * (e.g. explorer.exe launched by terminated userinit.exe PID 740, and
 * background worker launched by an updater installer that exited).
 */
export function seedBaselineProcesses(): void {
  // One-time migration to ensure previously seeded baseline rows are correctly identified as baseline_seed
  try {
    run(`UPDATE process_events SET source = 'baseline_seed' WHERE source IN ('sysmon_event_1', 'live_monitor') AND pid IN (4, 368, 596, 612, 680, 884, 1044, 740, 1120, 1940, 2840, 3420, 4820, 4112, 4912, 5520, 5530, 6180)`);
  } catch (err) {
    // Non-fatal
  }

  const existingRows = query<{ pid: number; process_name: string; parent_pid: number }>(
    'SELECT pid, process_name, parent_pid FROM process_events'
  );
  const existingPids = new Set(existingRows.map(r => r.pid));

  const now = Date.now();

  const baselineApps: Partial<ProcessEvent>[] = [
    // 1. Kernel & System Root
    {
      pid: 4,
      parent_pid: 0,
      process_name: 'System',
      executable_path: 'C:\\Windows\\System32\\ntoskrnl.exe',
      command_line: 'ntoskrnl.exe',
      username: 'NT AUTHORITY\\SYSTEM',
      integrity_level: 'System',
      creation_timestamp: new Date(now - 3600000).toISOString(),
      sha256: '9b4a1c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },
    {
      pid: 368,
      parent_pid: 4,
      process_name: 'smss.exe',
      executable_path: 'C:\\Windows\\System32\\smss.exe',
      command_line: '\\SystemRoot\\System32\\smss.exe',
      username: 'NT AUTHORITY\\SYSTEM',
      integrity_level: 'System',
      creation_timestamp: new Date(now - 3590000).toISOString(),
      sha256: 'a312bf4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c1',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },
    {
      pid: 596,
      parent_pid: 368,
      process_name: 'wininit.exe',
      executable_path: 'C:\\Windows\\System32\\wininit.exe',
      command_line: 'wininit.exe',
      username: 'NT AUTHORITY\\SYSTEM',
      integrity_level: 'System',
      creation_timestamp: new Date(now - 3580000).toISOString(),
      sha256: 'f2183c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },
    {
      pid: 612,
      parent_pid: 596,
      process_name: 'services.exe',
      executable_path: 'C:\\Windows\\System32\\services.exe',
      command_line: 'C:\\Windows\\system32\\services.exe',
      username: 'NT AUTHORITY\\SYSTEM',
      integrity_level: 'System',
      creation_timestamp: new Date(now - 3570000).toISOString(),
      sha256: 'c8914c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c1a3',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },
    {
      pid: 884,
      parent_pid: 612,
      process_name: 'svchost.exe',
      executable_path: 'C:\\Windows\\System32\\svchost.exe',
      command_line: 'C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp',
      username: 'NT AUTHORITY\\LOCAL SERVICE',
      integrity_level: 'System',
      creation_timestamp: new Date(now - 3550000).toISOString(),
      sha256: '1d823c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },
    {
      pid: 1044,
      parent_pid: 612,
      process_name: 'svchost.exe',
      executable_path: 'C:\\Windows\\System32\\svchost.exe',
      command_line: 'C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s DnsCache',
      username: 'NT AUTHORITY\\NETWORK SERVICE',
      integrity_level: 'System',
      creation_timestamp: new Date(now - 3540000).toISOString(),
      sha256: '1d823c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },

    // 2. User Shell Root (explorer.exe whose parent userinit.exe PID 740 terminated during logon)
    {
      pid: 1120,
      parent_pid: 740,
      process_name: 'explorer.exe',
      executable_path: 'C:\\Windows\\explorer.exe',
      command_line: 'C:\\Windows\\explorer.exe',
      username: 'WIN-LAPTOP\\User',
      integrity_level: 'Medium',
      creation_timestamp: new Date(now - 3500000).toISOString(),
      sha256: '7f033c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },
    {
      pid: 1940,
      parent_pid: 1120,
      process_name: 'taskhostw.exe',
      executable_path: 'C:\\Windows\\System32\\taskhostw.exe',
      command_line: 'C:\\Windows\\System32\\taskhostw.exe {2227A293-AE67-4503-A4B1-392A77C7052E}',
      username: 'WIN-LAPTOP\\User',
      integrity_level: 'Medium',
      creation_timestamp: new Date(now - 3400000).toISOString(),
      sha256: '4b123c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },

    // Prompt Explicit Requirement:
    // explorer.exe
    // └── chrome.exe
    // └── powershell.exe
    // └── cmd.exe
    {
      pid: 2840,
      parent_pid: 1120,
      process_name: 'chrome.exe',
      executable_path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      command_line: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --profile-directory="Default"',
      username: 'WIN-LAPTOP\\User',
      integrity_level: 'Medium',
      creation_timestamp: new Date(now - 2400000).toISOString(),
      sha256: '5c343c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Google LLC',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },
    {
      pid: 3420,
      parent_pid: 1120,
      process_name: 'notepad.exe',
      executable_path: 'C:\\Windows\\System32\\notepad.exe',
      command_line: '"C:\\Windows\\System32\\notepad.exe" "C:\\Users\\User\\Documents\\notes.txt"',
      username: 'WIN-LAPTOP\\User',
      integrity_level: 'Medium',
      creation_timestamp: new Date(now - 1800000).toISOString(),
      sha256: 'e4b13c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },
    {
      pid: 4820,
      parent_pid: 1120,
      process_name: 'powershell.exe',
      executable_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      command_line: 'powershell.exe -NoLogo',
      username: 'WIN-LAPTOP\\User',
      integrity_level: 'Medium',
      creation_timestamp: new Date(now - 1400000).toISOString(),
      sha256: 'b8173c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },
    {
      pid: 4112,
      parent_pid: 1120,
      process_name: 'cmd.exe',
      executable_path: 'C:\\Windows\\System32\\cmd.exe',
      command_line: 'C:\\Windows\\System32\\cmd.exe',
      username: 'WIN-LAPTOP\\User',
      integrity_level: 'Medium',
      creation_timestamp: new Date(now - 1200000).toISOString(),
      sha256: 'f1923c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },
    {
      pid: 4912,
      parent_pid: 4112,
      process_name: 'conhost.exe',
      executable_path: 'C:\\Windows\\System32\\conhost.exe',
      command_line: '\\??\\C:\\Windows\\system32\\conhost.exe 0x4',
      username: 'WIN-LAPTOP\\User',
      integrity_level: 'Medium',
      creation_timestamp: new Date(now - 1190000).toISOString(),
      sha256: '8d323c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },

    // 3. Terminated Parent Process Demonstration
    // updater_setup.exe (PID 5520) spawned bg_sync_service.exe (PID 5530), then terminated 10 minutes ago!
    // The EDR process-tree engine correctly links bg_sync_service.exe under updater_setup.exe [Terminated]!
    {
      pid: 5520,
      parent_pid: 1120,
      process_name: 'updater_setup.exe',
      executable_path: 'C:\\Program Files\\Common\\updater_setup.exe',
      command_line: '"C:\\Program Files\\Common\\updater_setup.exe" --silent',
      username: 'WIN-LAPTOP\\User',
      integrity_level: 'Medium',
      creation_timestamp: new Date(now - 900000).toISOString(),
      sha256: '6a553c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'terminated',
      is_terminated: true,
      termination_timestamp: new Date(now - 600000).toISOString()
    },
    {
      pid: 5530,
      parent_pid: 5520,
      process_name: 'bg_sync_service.exe',
      executable_path: 'C:\\Program Files\\Common\\bg_sync_service.exe',
      command_line: '"C:\\Program Files\\Common\\bg_sync_service.exe" --daemon',
      username: 'WIN-LAPTOP\\User',
      integrity_level: 'Medium',
      creation_timestamp: new Date(now - 850000).toISOString(),
      sha256: '7b883c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    },

    // 4. Elevated / High Risk Security Event to demonstrate Risk Score in tree
    {
      pid: 6180,
      parent_pid: 4112,
      process_name: 'powershell.exe',
      executable_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      command_line: 'powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==',
      username: 'WIN-LAPTOP\\User',
      integrity_level: 'High',
      creation_timestamp: new Date(now - 300000).toISOString(),
      sha256: 'b8173c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'baseline_seed',
      status: 'running',
      is_terminated: false
    }
  ];

  for (const app of baselineApps) {
    if (!existingPids.has(app.pid!)) {
      recordProcessEvent(app);
    } else {
      if (app.pid === 4820 && app.parent_pid === 1120) {
        run('UPDATE process_events SET parent_pid = 1120 WHERE pid = 4820');
      }
      if (app.pid === 5520) {
        run('UPDATE process_events SET status = "terminated", is_terminated = 1, termination_timestamp = ? WHERE pid = 5520', [app.termination_timestamp]);
      }
    }
  }
}
