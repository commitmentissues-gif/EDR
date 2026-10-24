import { query, run, scheduleSave } from '../db/index.js';
import { logger } from '../logger/index.js';
import { 
  FileEvent, 
  FileFilterOptions, 
  FileAggregatedStats, 
  FileMonitorConfig, 
  SafeFileSimulationScenario,
  IncidentTimelineItem 
} from './types.js';
import { fileMonitor, DEFAULT_FILE_MONITOR_CONFIG } from './monitor.js';
import { selectiveFileHasher } from './hasher.js';
import { SECURITY_LOCATIONS } from './locations.js';

const log = logger.forComponent('FilesystemManager');

export const SAFE_FILE_SIMULATIONS: SafeFileSimulationScenario[] = [
  {
    id: 'SIM-FILE-BENIGN-DOCUMENT',
    name: 'Benign: Normal Document Download to Downloads Folder',
    category: 'benign_file',
    description: 'Browser writes legitimate PDF invoice document to user Downloads directory.',
    expectedAlert: false,
    action: 'create',
    file_path: 'C:\\Users\\Analyst\\Downloads\\Q3_Security_Report.pdf',
    process_name: 'chrome.exe',
    pid: 3412,
    explanation: 'Clean document creation in user downloads. Not executable, no double extension. Expected outcome: Clean.'
  },
  {
    id: 'SIM-FILE-BENIGN-TEMP-LOG',
    name: 'Benign: Application Diagnostics Log in Temp Folder',
    category: 'benign_file',
    description: 'Legitimate service writing temporary log file in AppData\\Local\\Temp.',
    expectedAlert: false,
    action: 'create',
    file_path: 'C:\\Users\\Analyst\\AppData\\Local\\Temp\\update_diag.log',
    process_name: 'svchost.exe',
    pid: 1044,
    explanation: 'Standard non-executable diagnostic log file in temporary directory. Expected outcome: Clean.'
  },
  {
    id: 'SIM-FILE-STARTUP-PERSISTENCE',
    name: 'Detection: Executable Dropped into Start Menu Startup Folder',
    category: 'malicious_file_detection',
    description: 'Adversary dropper writes executable binary to Start Menu Startup folder for logon persistence.',
    expectedAlert: true,
    action: 'create',
    file_path: 'C:\\Users\\Analyst\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\security_agent_update.exe',
    process_name: 'powershell.exe',
    pid: 4890,
    explanation: 'Flags STARTUP_PERSISTENCE (MITRE ATT&CK T1547.001): unauthorized binary in Startup folder.'
  },
  {
    id: 'SIM-FILE-TEMP-EXECUTABLE-DROP',
    name: 'Detection: Binary Payload Staged in Temporary Directory',
    category: 'malicious_file_detection',
    description: 'Script drops executable binary into AppData\\Local\\Temp for subsequent execution.',
    expectedAlert: true,
    action: 'create',
    file_path: 'C:\\Users\\Analyst\\AppData\\Local\\Temp\\staged_runner.exe',
    process_name: 'cmd.exe',
    pid: 3912,
    explanation: 'Flags TEMP_EXECUTABLE_DROP (MITRE ATT&CK T1027): executable binary dropped into temporary directory.'
  },
  {
    id: 'SIM-FILE-DOUBLE-EXTENSION',
    name: 'Detection: Deceptive Double File Extension Masquerade',
    category: 'malicious_file_detection',
    description: 'Phishing payload with double extension (Quarterly_Bonus.pdf.exe) dropped into Downloads.',
    expectedAlert: true,
    action: 'create',
    file_path: 'C:\\Users\\Analyst\\Downloads\\Quarterly_Bonus_Statement.pdf.exe',
    process_name: 'outlook.exe',
    pid: 5120,
    explanation: 'Flags DOUBLE_EXTENSION_MASQUERADE (MITRE ATT&CK T1036.007): masquerading executable payload as PDF document.'
  },
  {
    id: 'SIM-FILE-SYSTEM32-DLL-DROP',
    name: 'Detection: Unauthorized DLL Dropped into Windows System32',
    category: 'malicious_file_detection',
    description: 'Untrusted process writes DLL into Windows System32 directory for DLL search-order hijacking.',
    expectedAlert: true,
    action: 'create',
    file_path: 'C:\\Windows\\System32\\version_proxy.dll',
    process_name: 'rundll32.exe',
    pid: 6140,
    explanation: 'Flags SYSTEM32_MODIFICATION (MITRE ATT&CK T1574): unauthorized DLL drop in core Windows system folder.'
  },
  {
    id: 'SIM-FILE-PERSISTENCE-TASK',
    name: 'Detection: Direct XML File Drop into Scheduled Tasks Directory',
    category: 'malicious_file_detection',
    description: 'Adversary creates XML task definition directly in System32\\Tasks to evade schtasks.exe command line telemetry.',
    expectedAlert: true,
    action: 'create',
    file_path: 'C:\\Windows\\System32\\Tasks\\AdobeFlashUpdateTask',
    process_name: 'powershell.exe',
    pid: 5880,
    explanation: 'Flags PERSISTENCE_LOCATION_MODIFICATION (MITRE ATT&CK T1053.005): file activity in persistence infrastructure.'
  }
];

export class FilesystemManager {
  constructor() {}

  initDatabase(): void {
    try {
      fileMonitor.startWatching();
      this.seedBaselineFileEvents();
      scheduleSave();
      log.info('Filesystem monitoring subsystem initialized.');
    } catch (err: any) {
      log.error('Failed to initialize filesystem subsystem:', err);
    }
  }

  seedBaselineFileEvents(): void {
    const existing = query<{ count: number }>('SELECT count(*) as count FROM file_events');
    if (existing[0] && existing[0].count > 5) {
      log.info(`Filesystem telemetry already initialized with ${existing[0].count} events.`);
      return;
    }

    log.info('Seeding baseline enterprise filesystem events into SQLite...');
    const now = Date.now();

    const baselineData = [
      {
        action: 'create' as const,
        file_path: 'C:\\Users\\Analyst\\Downloads\\Employee_Handbook_2026.pdf',
        process_name: 'chrome.exe',
        pid: 3412,
        file_size_bytes: 524288,
        timestamp: new Date(now - 320000).toISOString()
      },
      {
        action: 'modify' as const,
        file_path: 'C:\\Users\\Analyst\\AppData\\Local\\Temp\\vscode-workbench.log',
        process_name: 'Code.exe',
        pid: 2190,
        file_size_bytes: 12288,
        timestamp: new Date(now - 280000).toISOString()
      },
      {
        action: 'create' as const,
        file_path: 'C:\\Windows\\System32\\drivers\\etc\\hosts.tmp',
        process_name: 'notepad.exe',
        pid: 4120,
        file_size_bytes: 840,
        timestamp: new Date(now - 240000).toISOString()
      },
      {
        action: 'delete' as const,
        file_path: 'C:\\Users\\Analyst\\AppData\\Local\\Temp\\installer_cache.tmp',
        process_name: 'msiexec.exe',
        pid: 1890,
        file_size_bytes: 4096,
        timestamp: new Date(now - 190000).toISOString()
      },
      {
        action: 'create' as const,
        file_path: 'C:\\Users\\Analyst\\Documents\\Financial_Q2.xlsx',
        process_name: 'excel.exe',
        pid: 5100,
        file_size_bytes: 184320,
        timestamp: new Date(now - 140000).toISOString()
      }
    ];

    for (const item of baselineData) {
      fileMonitor.ingestFileEvent(item).catch(() => {});
    }
  }

  getFileEvents(options: FileFilterOptions = {}): {
    events: FileEvent[];
    total: number;
    limit: number;
    offset: number;
  } {
    const limit = Math.min(500, Math.max(1, options.limit ?? 100));
    const offset = Math.max(0, options.offset ?? 0);

    const conditions: string[] = [];
    const params: any[] = [];

    if (options.search) {
      const term = `%${options.search}%`;
      conditions.push('(file_path LIKE ? OR file_name LIKE ? OR process_name LIKE ? OR file_hash LIKE ?)');
      params.push(term, term, term, term);
    }

    if (options.action && options.action !== 'all') {
      conditions.push('action = ?');
      params.push(options.action);
    }

    if (options.category && options.category !== 'all') {
      conditions.push('file_category = ?');
      params.push(options.category);
    }

    if (options.location && options.location !== 'all') {
      conditions.push('security_location = ?');
      params.push(options.location);
    }

    if (options.is_suspicious !== undefined) {
      conditions.push('is_suspicious = ?');
      params.push(options.is_suspicious ? 1 : 0);
    }

    if (options.has_hash !== undefined) {
      if (options.has_hash) {
        conditions.push("file_hash IS NOT NULL AND file_hash != ''");
      } else {
        conditions.push("(file_hash IS NULL OR file_hash = '')");
      }
    }

    if (options.pid !== undefined && options.pid > 0) {
      conditions.push('pid = ?');
      params.push(options.pid);
    }

    if (options.process_name) {
      conditions.push('process_name LIKE ?');
      params.push(`%${options.process_name}%`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRows = query<{ total: number }>(`SELECT COUNT(*) as total FROM file_events ${whereClause}`, params);
    const total = countRows[0]?.total || 0;

    const dataQuery = `
      SELECT * FROM file_events 
      ${whereClause} 
      ORDER BY id DESC 
      LIMIT ? OFFSET ?
    `;
    const rows = query<any>(dataQuery, [...params, limit, offset]);

    const events: FileEvent[] = rows.map(r => ({
      id: r.id,
      event_uuid: r.event_uuid,
      timestamp: r.timestamp,
      action: r.action,
      file_path: r.file_path,
      old_file_path: r.old_file_path || undefined,
      file_name: r.file_name,
      file_extension: r.file_extension,
      file_size_bytes: r.file_size_bytes,
      file_category: r.file_category,
      security_location: r.security_location,
      file_hash: r.file_hash || undefined,
      hash_calculated: Boolean(r.hash_calculated),
      hash_calculation_reason: r.hash_calculation_reason || undefined,
      pid: r.pid,
      process_name: r.process_name || undefined,
      process_path: r.process_path || undefined,
      is_suspicious: Boolean(r.is_suspicious),
      detection_tags: typeof r.detection_tags === 'string' ? JSON.parse(r.detection_tags || '[]') : [],
      risk_score: r.risk_score,
      detection_reasons: typeof r.detection_reasons === 'string' ? JSON.parse(r.detection_reasons || '[]') : [],
      created_at: r.created_at
    }));

    return { events, total, limit, offset };
  }

  getAggregatedFileStats(): FileAggregatedStats {
    const totalRow = query<{ total: number }>('SELECT COUNT(*) as total FROM file_events');
    const totalEvents = totalRow[0]?.total || 0;

    const createsRow = query<{ count: number }>("SELECT COUNT(*) as count FROM file_events WHERE action = 'create'");
    const createsCount = createsRow[0]?.count || 0;

    const modifiesRow = query<{ count: number }>("SELECT COUNT(*) as count FROM file_events WHERE action = 'modify'");
    const modifiesCount = modifiesRow[0]?.count || 0;

    const deletesRow = query<{ count: number }>("SELECT COUNT(*) as count FROM file_events WHERE action = 'delete'");
    const deletesCount = deletesRow[0]?.count || 0;

    const renamesRow = query<{ count: number }>("SELECT COUNT(*) as count FROM file_events WHERE action = 'rename'");
    const renamesCount = renamesRow[0]?.count || 0;

    const exeRow = query<{ count: number }>("SELECT COUNT(*) as count FROM file_events WHERE file_category = 'executable' AND action = 'create'");
    const executablesCreatedCount = exeRow[0]?.count || 0;

    const dllRow = query<{ count: number }>("SELECT COUNT(*) as count FROM file_events WHERE file_category = 'dll' AND action = 'create'");
    const dllsCreatedCount = dllRow[0]?.count || 0;

    const scriptRow = query<{ count: number }>("SELECT COUNT(*) as count FROM file_events WHERE file_category = 'script' AND action = 'create'");
    const scriptsCreatedCount = scriptRow[0]?.count || 0;

    const suspRow = query<{ count: number }>('SELECT COUNT(*) as count FROM file_events WHERE is_suspicious = 1');
    const suspiciousCount = suspRow[0]?.count || 0;

    const hashRow = query<{ count: number }>('SELECT COUNT(*) as count FROM file_events WHERE hash_calculated = 1');
    const hashesCalculatedCount = hashRow[0]?.count || 0;

    // Top security locations
    const locRows = query<{ security_location: string; count: number; susp_count: number }>(
      `SELECT security_location, COUNT(*) as count, SUM(is_suspicious) as susp_count 
       FROM file_events 
       GROUP BY security_location 
       ORDER BY count DESC`
    );
    const topSecurityLocations = locRows.map(r => ({
      location: r.security_location as any,
      name: SECURITY_LOCATIONS.find(l => l.type === r.security_location)?.name || r.security_location,
      count: r.count,
      suspiciousCount: r.susp_count || 0
    }));

    // Top active processes
    const procRows = query<{ process_name: string; pid: number; count: number; susp_count: number }>(
      `SELECT process_name, pid, COUNT(*) as count, SUM(is_suspicious) as susp_count 
       FROM file_events 
       WHERE process_name IS NOT NULL 
       GROUP BY process_name 
       ORDER BY count DESC 
       LIMIT 6`
    );
    const topActiveProcesses = procRows.map(r => ({
      process_name: r.process_name,
      pid: r.pid,
      fileOpsCount: r.count,
      isSuspicious: (r.susp_count || 0) > 0
    }));

    // Recent detections
    const recentDetections = this.getFileEvents({ is_suspicious: true, limit: 5 }).events;

    return {
      totalEvents,
      createsCount,
      modifiesCount,
      deletesCount,
      renamesCount,
      executablesCreatedCount,
      dllsCreatedCount,
      scriptsCreatedCount,
      suspiciousCount,
      hashesCalculatedCount,
      topSecurityLocations,
      topActiveProcesses,
      recentDetections
    };
  }

  /**
   * Manually requested scan: Selective Hash Calculation
   * "Calculate hashes selectively for: ... manually requested scans"
   */
  async requestFileHash(filePath: string): Promise<{
    filePath: string;
    hash: string;
    calculated: boolean;
    fromCache: boolean;
    reason: string;
  }> {
    const res = await selectiveFileHasher.getOrComputeHash(filePath, 'manual_scan', true);
    return {
      filePath,
      hash: res.hash,
      calculated: res.calculated,
      fromCache: res.fromCache,
      reason: 'manual_scan'
    };
  }

  /**
   * Builds Unified Incident Timeline integrating File Activity, Alerts, Process Creation, and Network Sockets.
   * "Add file activity to incident timelines."
   */
  getIncidentTimeline(alertId?: string): IncidentTimelineItem[] {
    const timeline: IncidentTimelineItem[] = [];

    let targetTimestamp: string | null = null;
    let targetPid: number | null = null;
    let targetProcess: string | null = null;

    if (alertId) {
      const alertRows = query<any>('SELECT * FROM alerts WHERE id = ?', [alertId]);
      if (alertRows[0]) {
        targetTimestamp = alertRows[0].timestamp;
        try {
          const lineage = JSON.parse(alertRows[0].process_lineage_json || '[]');
          const targetNode = lineage.find((n: any) => n.role === 'target' || n.role === 'originator');
          if (targetNode) {
            targetPid = targetNode.process_id;
            targetProcess = targetNode.process_name;
          }
        } catch {}
      }
    }

    // 1. Fetch relevant Alerts
    const alerts = query<any>(
      alertId 
        ? 'SELECT * FROM alerts WHERE id = ?' 
        : 'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20',
      alertId ? [alertId] : []
    );

    for (const a of alerts) {
      timeline.push({
        id: a.id,
        timestamp: a.timestamp,
        type: 'ALERT',
        title: a.title,
        description: a.why_triggered,
        severity: a.severity,
        mitre_technique_id: a.mitre_technique_id,
        tags: [a.rule_id, a.risk_level]
      });
    }

    // 2. Correlate File Activity into Timeline
    let fileQuery = 'SELECT * FROM file_events ORDER BY timestamp DESC LIMIT 30';
    let fileParams: any[] = [];

    if (targetPid && targetPid > 0) {
      fileQuery = 'SELECT * FROM file_events WHERE pid = ? OR is_suspicious = 1 ORDER BY timestamp DESC LIMIT 30';
      fileParams = [targetPid];
    }

    const files = query<any>(fileQuery, fileParams);
    for (const f of files) {
      timeline.push({
        id: f.event_uuid || `FILE-${f.id}`,
        timestamp: f.timestamp,
        type: 'FILE',
        title: `File ${f.action.toUpperCase()}: ${f.file_name}`,
        description: `${f.process_name || 'Process'} [PID: ${f.pid}] ${f.action}d '${f.file_path}' (${f.file_category}) in ${f.security_location}. Hash: ${f.file_hash || 'Selective (skipped)'}`,
        severity: f.is_suspicious ? 'HIGH' : 'INFO',
        process_name: f.process_name,
        pid: f.pid,
        file_path: f.file_path,
        file_action: f.action,
        file_hash: f.file_hash,
        tags: typeof f.detection_tags === 'string' ? JSON.parse(f.detection_tags || '[]') : []
      });
    }

    // 3. Correlate Network Sockets into Timeline
    const networkRows = query<any>('SELECT * FROM network_events ORDER BY timestamp DESC LIMIT 20');
    for (const n of networkRows) {
      timeline.push({
        id: n.event_uuid || `NET-${n.id}`,
        timestamp: n.timestamp,
        type: 'NETWORK',
        title: `Network Socket: ${n.process_name} -> ${n.destination_ip}:${n.destination_port}`,
        description: `${n.process_name} [PID: ${n.pid}] ${n.protocol} connection (${n.connection_state}) to ${n.destination_ip}:${n.destination_port} [Domain: ${n.domain || 'N/A'}]`,
        severity: n.is_suspicious ? 'HIGH' : 'INFO',
        process_name: n.process_name,
        pid: n.pid,
        destination_ip: n.destination_ip,
        destination_port: n.destination_port,
        tags: typeof n.detection_tags === 'string' ? JSON.parse(n.detection_tags || '[]') : []
      });
    }

    // Sort chronologically ascending
    timeline.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    return timeline;
  }

  getSimulations(): SafeFileSimulationScenario[] {
    return SAFE_FILE_SIMULATIONS;
  }

  async runSimulation(scenarioId: string): Promise<{
    success: boolean;
    scenario: SafeFileSimulationScenario;
    event: FileEvent;
    detectedAlert: boolean;
    message: string;
  }> {
    const scenario = SAFE_FILE_SIMULATIONS.find(s => s.id === scenarioId);
    if (!scenario) {
      throw new Error(`Simulation scenario '${scenarioId}' not found.`);
    }

    log.info(`Executing safe filesystem simulation '${scenario.name}' [${scenario.id}]...`);

    const ingested = await fileMonitor.ingestFileEvent({
      action: scenario.action,
      file_path: scenario.file_path,
      process_name: scenario.process_name,
      pid: scenario.pid,
      timestamp: new Date().toISOString()
    });

    const detectedAlert = ingested.is_suspicious;
    const testPassed = detectedAlert === scenario.expectedAlert;

    const message = testPassed
      ? `Simulation passed: Expected Alert = ${scenario.expectedAlert}, Result = ${detectedAlert}.`
      : `Simulation mismatch: Expected Alert = ${scenario.expectedAlert}, but got ${detectedAlert}.`;

    return {
      success: testPassed,
      scenario,
      event: ingested,
      detectedAlert,
      message
    };
  }
}

export const filesystemManager = new FilesystemManager();
