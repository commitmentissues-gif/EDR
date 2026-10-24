import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { run, scheduleSave } from '../db/index.js';
import { logger } from '../logger/index.js';
import { 
  FileEvent, 
  FileActionType, 
  FileCategoryType, 
  SecurityLocationType,
  HashCalculationReason,
  FileMonitorConfig 
} from './types.js';
import { classifyFileCategory, classifyLocation } from './locations.js';
import { selectiveFileHasher } from './hasher.js';
import { fileDetector, FileDetectionResult } from './detector.js';
import { getProcessByPid } from '../process/index.js';

const log = logger.forComponent('FileMonitor');

export const DEFAULT_FILE_MONITOR_CONFIG: FileMonitorConfig = {
  enabled: true,
  watchStartupFolders: true,
  watchTempDirectories: true,
  watchDownloads: true,
  watchSystem32: true,
  watchPersistenceLocations: true,
  selectiveHashing: {
    hashExecutedFiles: true,
    hashSuspiciousFiles: true,
    hashAlertCorrelatedFiles: true,
    hashManualScans: true,
    maxFileSizeBytes: 100 * 1024 * 1024
  },
  dedupDebounceMs: 500
};

export class FileMonitor {
  private config: FileMonitorConfig = { ...DEFAULT_FILE_MONITOR_CONFIG };
  private watchers: fs.FSWatcher[] = [];
  private debounceMap = new Map<string, number>();

  constructor() {}

  updateConfig(cfg: Partial<FileMonitorConfig>): void {
    this.config = { ...this.config, ...cfg };
  }

  getConfig(): FileMonitorConfig {
    return { ...this.config };
  }

  /**
   * Ingests, normalizes, selectively hashes, evaluates, and stores a file event.
   */
  async ingestFileEvent(input: {
    action: FileActionType;
    file_path: string;
    old_file_path?: string;
    pid?: number;
    process_name?: string;
    process_path?: string;
    timestamp?: string;
    file_size_bytes?: number;
    file_hash?: string;
    hash_calculation_reason?: HashCalculationReason | string;
    forceHash?: boolean;
  }): Promise<FileEvent> {
    const timestamp = input.timestamp || new Date().toISOString();
    const event_uuid = `FILE-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const filePath = input.file_path;
    const fileName = path.basename(filePath);
    const fileExtension = path.extname(filePath).toLowerCase();
    const fileCategory = classifyFileCategory(filePath);
    const securityLocation = classifyLocation(filePath);
    const action = input.action;

    // Process enrichment
    let pid = input.pid || 0;
    let processName = input.process_name || 'explorer.exe';
    let processPath = input.process_path || '';

    if (pid > 0) {
      try {
        const proc = getProcessByPid(pid);
        if (proc.process) {
          processName = proc.process.process_name || processName;
          processPath = proc.process.executable_path || processPath;
        }
      } catch {
        // Safe fallback
      }
    }

    // First-pass heuristic detection to check if suspicious
    const preliminaryAnalysis = fileDetector.analyzeFileEvent({
      action,
      file_path: filePath,
      old_file_path: input.old_file_path,
      file_name: fileName,
      file_extension: fileExtension,
      file_category: fileCategory,
      security_location: securityLocation,
      file_hash: input.file_hash,
      process_name: processName
    });

    // Selective Hash Calculation Rule:
    // "Do NOT continuously scan the entire disk.
    // Calculate hashes selectively for:
    // * executed files
    // * suspicious files
    // * files involved in alerts
    // * manually requested scans"
    let fileHash = input.file_hash || '';
    let hashCalculated = Boolean(fileHash);
    let hashReason = input.hash_calculation_reason;

    if (!fileHash) {
      const isSuspicious = preliminaryAnalysis.isSuspicious;
      const isManual = input.forceHash === true;
      const isStartupOrPersistence = securityLocation === 'startup' || securityLocation === 'persistence';

      let candidateReason: HashCalculationReason | undefined;
      if (isManual) candidateReason = 'manual_scan';
      else if (isSuspicious) candidateReason = 'suspicious';
      else if (isStartupOrPersistence && (fileCategory === 'executable' || fileCategory === 'script')) {
        candidateReason = 'persistence_location';
      }

      if (candidateReason && selectiveFileHasher.shouldCalculateHash(candidateReason, isSuspicious)) {
        try {
          const hashRes = await selectiveFileHasher.getOrComputeHash(filePath, candidateReason, isSuspicious);
          if (hashRes.calculated) {
            fileHash = hashRes.hash;
            hashCalculated = true;
            hashReason = candidateReason;
          }
        } catch {
          // Non-fatal
        }
      }
    }

    // Final analysis with hash if calculated
    const analysis = fileDetector.analyzeFileEvent({
      action,
      file_path: filePath,
      old_file_path: input.old_file_path,
      file_name: fileName,
      file_extension: fileExtension,
      file_category: fileCategory,
      security_location: securityLocation,
      file_hash: fileHash,
      process_name: processName
    });

    const fileEvent: FileEvent = {
      event_uuid,
      timestamp,
      action,
      file_path: filePath,
      old_file_path: input.old_file_path,
      file_name: fileName,
      file_extension: fileExtension,
      file_size_bytes: input.file_size_bytes ?? 0,
      file_category: fileCategory,
      security_location: securityLocation,
      file_hash: fileHash || undefined,
      hash_calculated: hashCalculated,
      hash_calculation_reason: hashReason,
      pid,
      process_name: processName,
      process_path: processPath,
      is_suspicious: analysis.isSuspicious,
      detection_tags: analysis.tags,
      risk_score: analysis.riskScore,
      detection_reasons: analysis.reasons,
      created_at: new Date().toISOString()
    };

    // Store in SQLite file_events table
    try {
      run(
        `INSERT INTO file_events (
          event_uuid, timestamp, action, file_path, old_file_path,
          file_name, file_extension, file_size_bytes, file_category,
          security_location, file_hash, hash_calculated, hash_calculation_reason,
          pid, process_name, process_path, is_suspicious, detection_tags,
          risk_score, detection_reasons, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          fileEvent.event_uuid,
          fileEvent.timestamp,
          fileEvent.action,
          fileEvent.file_path,
          fileEvent.old_file_path || null,
          fileEvent.file_name,
          fileEvent.file_extension,
          fileEvent.file_size_bytes || 0,
          fileEvent.file_category,
          fileEvent.security_location,
          fileEvent.file_hash || null,
          fileEvent.hash_calculated ? 1 : 0,
          fileEvent.hash_calculation_reason || null,
          fileEvent.pid || 0,
          fileEvent.process_name || null,
          fileEvent.process_path || null,
          fileEvent.is_suspicious ? 1 : 0,
          JSON.stringify(fileEvent.detection_tags),
          fileEvent.risk_score,
          JSON.stringify(fileEvent.detection_reasons || []),
          fileEvent.created_at
        ]
      );
    } catch (err: any) {
      log.error('Failed to insert file event into SQLite:', err);
    }

    // Generate Alert if suspicious
    if (analysis.isSuspicious) {
      this.generateFileAlert(fileEvent, analysis);
    }

    scheduleSave();
    return fileEvent;
  }

  /**
   * Generates a first-class EDR alert for suspicious filesystem activity
   */
  private generateFileAlert(event: FileEvent, analysis: FileDetectionResult): void {
    const alertId = `ALT-FILE-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
    const primaryTechnique = analysis.mitreTechniques[0] || {
      tactic: 'Persistence',
      technique_id: 'T1547.001',
      technique_name: 'Boot or Logon Autostart Execution'
    };

    const severity = event.risk_score >= 90 ? 'CRITICAL' : event.risk_score >= 70 ? 'HIGH' : 'MEDIUM';
    const riskLevel = event.risk_score >= 90 ? 'Critical' : event.risk_score >= 70 ? 'High' : 'Medium';

    const whyTriggered = `Filesystem Telemetry Alert: Suspicious file ${event.action} in security location '${event.security_location}' (${event.file_path}). Process: '${event.process_name}' (PID: ${event.pid}). Reasons: ${analysis.reasons.join('; ')}. Tags: [${analysis.tags.join(', ')}]. Risk Score: ${event.risk_score}/100.`;

    const evidence = {
      action: event.action,
      file_path: event.file_path,
      file_name: event.file_name,
      file_category: event.file_category,
      security_location: event.security_location,
      file_hash: event.file_hash,
      hash_calculated: event.hash_calculated,
      process_name: event.process_name,
      pid: event.pid,
      detection_tags: event.detection_tags,
      reasons: analysis.reasons
    };

    const title = `Suspicious File ${event.action.toUpperCase()}: ${event.file_name} in ${event.security_location} [${analysis.tags[0] || 'ANOMALY'}]`;

    let recommendedAction = 'Inspect originating process tree, quarantine created binary or script, and audit persistence entries.';
    if (analysis.tags.includes('STARTUP_PERSISTENCE')) {
      recommendedAction = 'AUTORUN PERSISTENCE: Immediately quarantine or delete file from Startup folder and inspect originating user session.';
    } else if (analysis.tags.includes('DOUBLE_EXTENSION_MASQUERADE')) {
      recommendedAction = 'MALICIOUS MASQUERADE: Quarantine disguised payload immediately and check endpoint for phishing or download source.';
    } else if (analysis.tags.includes('SYSTEM32_MODIFICATION')) {
      recommendedAction = 'SYSTEM INTEGRITY VIOLATION: Inspect Authenticode digital signature and revert unauthorized System32 file.';
    }

    try {
      run(
        `INSERT INTO alerts (
          id, rule_id, rule_name, severity, score, base_score, risk_level,
          score_factors_json, score_calculation_json, mitre_tactic, mitre_technique_id,
          mitre_technique_name, event_id, timestamp, title, why_triggered,
          evidence_json, recommended_action, process_lineage_json, details_json, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          alertId,
          `EDR-FILE-${analysis.tags[0] || 'SUSPICIOUS'}`,
          `Filesystem: ${analysis.tags.join(' & ')}`,
          severity,
          event.risk_score,
          Math.max(30, event.risk_score - 15),
          riskLevel,
          JSON.stringify(analysis.tags.map(t => ({ factor: t, weight: 25 }))),
          JSON.stringify({ final_score: event.risk_score, risk_level: riskLevel, tags: analysis.tags }),
          primaryTechnique.tactic,
          primaryTechnique.technique_id,
          primaryTechnique.technique_name,
          0,
          event.timestamp,
          title,
          whyTriggered,
          JSON.stringify(evidence),
          recommendedAction,
          JSON.stringify([
            {
              role: 'originator',
              process_name: event.process_name || 'explorer.exe',
              process_id: event.pid || 0,
              command_line: event.process_path || ''
            }
          ]),
          JSON.stringify({ file_event: event, analysis }),
          'NEW'
        ]
      );
      log.info(`[ALERT GENERATED] ${alertId} - ${title} (Severity: ${severity}, Score: ${event.risk_score})`);
    } catch (err: any) {
      log.error('Failed to create file alert in SQLite:', err);
    }
  }

  /**
   * Starts event-driven watchers on security-relevant folders where accessible
   */
  startWatching(): void {
    if (!this.config.enabled) return;
    this.stopWatching();

    const candidateDirs = [
      path.resolve(process.cwd(), 'data', 'monitored', 'startup'),
      path.resolve(process.cwd(), 'data', 'monitored', 'temp'),
      path.resolve(process.cwd(), 'data', 'monitored', 'downloads')
    ];

    for (const dir of candidateDirs) {
      try {
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        const watcher = fs.watch(dir, { recursive: false }, (eventType, filename) => {
          if (!filename) return;
          const fullPath = path.join(dir, filename);
          const now = Date.now();
          const lastDebounce = this.debounceMap.get(fullPath) || 0;
          if (now - lastDebounce < this.config.dedupDebounceMs) return;
          this.debounceMap.set(fullPath, now);

          const exists = fs.existsSync(fullPath);
          const action: FileActionType = eventType === 'rename' 
            ? (exists ? 'create' : 'delete') 
            : 'modify';

          this.ingestFileEvent({
            action,
            file_path: fullPath,
            timestamp: new Date().toISOString()
          }).catch(err => log.warn('Watcher event error:', err.message));
        });

        this.watchers.push(watcher);
      } catch (err: any) {
        log.warn(`Could not attach watcher to ${dir}:`, err.message);
      }
    }

    log.info(`Event-driven filesystem watcher active on ${this.watchers.length} security directories.`);
  }

  stopWatching(): void {
    for (const w of this.watchers) {
      try {
        w.close();
      } catch {}
    }
    this.watchers = [];
  }
}

export const fileMonitor = new FileMonitor();
