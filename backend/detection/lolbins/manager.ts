import { query, run, scheduleSave } from '../../db/index.js';
import { logger } from '../../logger/index.js';
import { 
  MonitoredBinaryName, 
  MonitoredBinaryMeta, 
  ContextualBehaviorDefinition, 
  LolbinGlobalConfig,
  SafeSimulationScenario,
  LolbinDetectionResult
} from './types.js';
import { 
  MONITORED_BINARIES, 
  CONTEXTUAL_BEHAVIORS, 
  DEFAULT_LOLBIN_CONFIG, 
  SAFE_SIMULATIONS 
} from './definitions.js';
import { lolbinDetector } from './detector.js';
import { TelemetryEvent } from '../types.js';
import { ingestAndDetect } from '../engine.js';

const log = logger.forComponent('LolbinManager');

export class LolbinManager {
  private initialized = false;

  /**
   * Initializes SQLite tables for configurable LOLBin settings
   */
  public initDatabase(): void {
    if (this.initialized) return;

    try {
      run(`
        CREATE TABLE IF NOT EXISTS lolbin_configs (
          binary_name TEXT PRIMARY KEY,
          display_name TEXT NOT NULL,
          category TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          risk_weight INTEGER NOT NULL DEFAULT 70,
          custom_keywords TEXT,
          custom_exclusions TEXT,
          total_detections INTEGER NOT NULL DEFAULT 0,
          last_updated TEXT NOT NULL
        )
      `);

      run(`
        CREATE TABLE IF NOT EXISTS lolbin_global_settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
      `);

      // Seed initial binaries if empty
      const existing = query<{ binary_name: string }>('SELECT binary_name FROM lolbin_configs');
      const existingSet = new Set(existing.map(e => e.binary_name));

      for (const binary of MONITORED_BINARIES) {
        if (!existingSet.has(binary.name)) {
          run(
            `INSERT INTO lolbin_configs (
              binary_name, display_name, category, enabled, risk_weight,
              custom_keywords, custom_exclusions, total_detections, last_updated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              binary.name,
              binary.displayName,
              binary.category,
              binary.enabled ? 1 : 0,
              binary.riskWeight,
              JSON.stringify(binary.suspiciousKeywords),
              JSON.stringify(binary.benignExamples),
              0,
              new Date().toISOString()
            ]
          );
        } else {
          // Sync detector in-memory status from DB
          const row = query<{ enabled: number }>('SELECT enabled FROM lolbin_configs WHERE binary_name = ?', [binary.name])[0];
          if (row) {
            lolbinDetector.setBinaryEnabled(binary.name, row.enabled === 1);
          }
        }
      }

      // Check global settings
      const globalRow = query<{ value: string }>('SELECT value FROM lolbin_global_settings WHERE key = ?', ['global_config'])[0];
      if (globalRow) {
        try {
          const parsed = JSON.parse(globalRow.value);
          lolbinDetector.setConfig(parsed);
        } catch {
          // Keep defaults
        }
      } else {
        run(
          'INSERT INTO lolbin_global_settings (key, value, updated_at) VALUES (?, ?, ?)',
          ['global_config', JSON.stringify(DEFAULT_LOLBIN_CONFIG), new Date().toISOString()]
        );
      }

      this.initialized = true;
      log.info('LOLBin & PowerShell Contextual Detection Manager initialized');
    } catch (err) {
      log.error('Failed to initialize LOLBin manager schema:', err);
    }
  }

  /**
   * Retrieves all 13 monitored binaries with real-time detection counts from SQLite
   */
  public getMonitoredBinaries(): MonitoredBinaryMeta[] {
    this.initDatabase();

    try {
      const rows = query<any>('SELECT * FROM lolbin_configs');
      const rowMap = new Map(rows.map(r => [r.binary_name, r]));

      return MONITORED_BINARIES.map(meta => {
        const dbRow = rowMap.get(meta.name);
        const enabled = dbRow ? dbRow.enabled === 1 : meta.enabled;
        const totalDetections = dbRow ? (dbRow.total_detections || 0) : 0;
        const riskWeight = dbRow ? dbRow.risk_weight : meta.riskWeight;

        return {
          ...meta,
          enabled,
          riskWeight,
          totalDetections
        };
      });
    } catch {
      return [...MONITORED_BINARIES];
    }
  }

  /**
   * Updates configuration for a specific monitored LOLBin
   */
  public updateBinaryConfig(name: MonitoredBinaryName, update: { enabled?: boolean; riskWeight?: number }): boolean {
    this.initDatabase();

    try {
      if (update.enabled !== undefined) {
        run('UPDATE lolbin_configs SET enabled = ?, last_updated = ? WHERE binary_name = ?', [
          update.enabled ? 1 : 0,
          new Date().toISOString(),
          name
        ]);
        lolbinDetector.setBinaryEnabled(name, update.enabled);
      }

      if (update.riskWeight !== undefined) {
        run('UPDATE lolbin_configs SET risk_weight = ?, last_updated = ? WHERE binary_name = ?', [
          Math.min(100, Math.max(1, update.riskWeight)),
          new Date().toISOString(),
          name
        ]);
      }

      scheduleSave();
      log.info(`Updated LOLBin config for ${name}: enabled=${update.enabled}, riskWeight=${update.riskWeight}`);
      return true;
    } catch (err) {
      log.error(`Failed to update config for ${name}:`, err);
      return false;
    }
  }

  /**
   * Increments detection count for a binary
   */
  public recordDetection(name: MonitoredBinaryName): void {
    try {
      run('UPDATE lolbin_configs SET total_detections = total_detections + 1 WHERE binary_name = ?', [name]);
      scheduleSave();
    } catch {
      // Ignore
    }
  }

  /**
   * Gets the 9 contextual behaviors
   */
  public getBehaviors(): ContextualBehaviorDefinition[] {
    return [...CONTEXTUAL_BEHAVIORS];
  }

  /**
   * Gets global detector configuration
   */
  public getGlobalConfig(): LolbinGlobalConfig {
    return lolbinDetector.getConfig();
  }

  /**
   * Updates global detector configuration
   */
  public updateGlobalConfig(newConfig: Partial<LolbinGlobalConfig>): LolbinGlobalConfig {
    this.initDatabase();
    lolbinDetector.setConfig(newConfig);
    const updated = lolbinDetector.getConfig();

    try {
      run(
        'INSERT OR REPLACE INTO lolbin_global_settings (key, value, updated_at) VALUES (?, ?, ?)',
        ['global_config', JSON.stringify(updated), new Date().toISOString()]
      );
      scheduleSave();
    } catch (err) {
      log.error('Failed to persist global LOLBin config:', err);
    }

    return updated;
  }

  /**
   * Evaluates a telemetry event directly via the detector
   */
  public evaluateEvent(event: TelemetryEvent): LolbinDetectionResult {
    const res = lolbinDetector.evaluate(event);
    if (res.isSuspicious && res.monitoredBinary) {
      this.recordDetection(res.monitoredBinary);
    }
    return res;
  }

  /**
   * Retrieves all pre-built safe simulations (benign & suspicious)
   */
  public getSimulations(): SafeSimulationScenario[] {
    return [...SAFE_SIMULATIONS];
  }

  /**
   * Executes a safe simulation scenario through ingestAndDetect
   */
  public runSimulation(simId: string): {
    simulation: SafeSimulationScenario;
    detectionResult: LolbinDetectionResult;
    alertsGenerated: any[];
    isSuccess: boolean;
  } {
    const sim = SAFE_SIMULATIONS.find(s => s.id === simId);
    if (!sim) {
      throw new Error(`Simulation scenario '${simId}' not found.`);
    }

    // Build synthetic benign or test telemetry event
    const event: TelemetryEvent = {
      event_type: 'process_creation',
      event_category: 'process',
      timestamp: new Date().toISOString(),
      process_name: sim.targetBinary,
      process_id: Math.floor(Math.random() * 5000) + 1000,
      image_path: sim.imagePath,
      command_line: sim.commandLine,
      parent_process_name: sim.parentProcess,
      parent_process_id: Math.floor(Math.random() * 3000) + 500,
      user: 'WIN-CLIENT\\Admin',
      source: 'safe_lolbin_simulator'
    };

    // Evaluate through contextual detector
    const detectionResult = this.evaluateEvent(event);

    // Also run through full EDR ingestion pipeline
    const { alertsGenerated } = ingestAndDetect(event);

    const isSuccess = sim.expectedAlert
      ? (detectionResult.isSuspicious || alertsGenerated.length > 0)
      : (!detectionResult.isSuspicious && alertsGenerated.length === 0);

    log.info(`[Simulation] ${sim.name}: ExpectedAlert=${sim.expectedAlert}, Result=${detectionResult.isSuspicious}, Success=${isSuccess}`);

    return {
      simulation: sim,
      detectionResult,
      alertsGenerated,
      isSuccess
    };
  }
}

export const lolbinManager = new LolbinManager();
