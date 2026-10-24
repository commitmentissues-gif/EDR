import fs from 'node:fs';
import path from 'node:path';
import initSqlJs, { Database, SqlJsStatic } from 'sql.js';
import { getConfig } from '../config/index.js';
import { logger } from '../logger/index.js';

const log = logger.forComponent('Database');

let SQL: SqlJsStatic | null = null;
let db: Database | null = null;
let saveTimeout: NodeJS.Timeout | null = null;

export async function initDatabase(): Promise<Database> {
  if (db) return db;

  const config = getConfig();
  const dbFilePath = path.resolve(process.cwd(), config.database.filePath);
  const dbDir = path.dirname(dbFilePath);

  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  log.info(`Initializing SQLite database engine at ${dbFilePath}`);
  SQL = await initSqlJs();

  if (fs.existsSync(dbFilePath)) {
    try {
      const fileBuffer = fs.readFileSync(dbFilePath);
      db = new SQL.Database(fileBuffer);
      log.info(`Loaded existing SQLite database (${(fileBuffer.length / 1024).toFixed(1)} KB)`);
    } catch (err) {
      log.error('Failed to load existing database file, creating fresh instance:', err);
      db = new SQL.Database();
    }
  } else {
    log.info('Creating new SQLite database file');
    db = new SQL.Database();
  }

  // Apply baseline schema migrations
  applySchema(db);
  saveDatabaseImmediately();

  return db;
}

export function getDatabase(): Database {
  if (!db) {
    throw new Error('Database is not initialized. Call initDatabase() first.');
  }
  return db;
}

export function query<T = any>(sql: string, params: any[] = []): T[] {
  const database = getDatabase();
  try {
    const stmt = database.prepare(sql);
    if (params.length > 0) {
      stmt.bind(params);
    }
    const results: T[] = [];
    while (stmt.step()) {
      results.push(stmt.getAsObject() as T);
    }
    stmt.free();
    return results;
  } catch (err) {
    log.error(`SQL Query Error in [${sql}]:`, err);
    throw err;
  }
}

export function run(sql: string, params: any[] = []): { changes: number; lastInsertRowid: number } {
  const database = getDatabase();
  try {
    database.run(sql, params);
    const rowidRes = query<{ id: number }>('SELECT last_insert_rowid() as id');
    const lastInsertRowid = rowidRes[0]?.id || 0;
    scheduleSave();
    return { changes: 1, lastInsertRowid };
  } catch (err) {
    log.error(`SQL Run Error in [${sql}]:`, err);
    throw err;
  }
}

export function scheduleSave() {
  if (saveTimeout) clearTimeout(saveTimeout);
  const config = getConfig();
  saveTimeout = setTimeout(() => {
    saveDatabaseImmediately();
  }, config.database.autoSaveIntervalMs || 2000);
}

export function saveDatabaseImmediately() {
  if (!db) return;
  try {
    const config = getConfig();
    const dbFilePath = path.resolve(process.cwd(), config.database.filePath);
    const data = db.export();
    fs.writeFileSync(dbFilePath, Buffer.from(data));
  } catch (err) {
    log.error('Failed to write SQLite database to disk:', err);
  }
}

export function checkDatabaseHealth(): { healthy: boolean; latencyMs: number; error?: string } {
  const start = performance.now();
  try {
    if (!db) {
      return { healthy: false, latencyMs: 0, error: 'Database not initialized' };
    }
    const res = query<{ ok: number }>('SELECT 1 as ok');
    const latencyMs = +(performance.now() - start).toFixed(2);
    const healthy = res.length > 0 && res[0].ok === 1;
    return { healthy, latencyMs };
  } catch (err: any) {
    return { healthy: false, latencyMs: +(performance.now() - start).toFixed(2), error: err.message };
  }
}

function applySchema(database: Database) {
  log.info('Ensuring base SQLite schema tables and indexes exist');
  database.run(`
    -- Telemetry events table
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id TEXT UNIQUE,
      event_type TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      process_name TEXT,
      process_id INTEGER,
      parent_process_id INTEGER,
      parent_process_name TEXT,
      parent_command_line TEXT,
      command_line TEXT,
      user TEXT,
      image_path TEXT,
      file_hash TEXT,
      destination_ip TEXT,
      destination_port INTEGER,
      registry_key TEXT,
      source TEXT NOT NULL DEFAULT 'sysmon',
      raw_json TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
    CREATE INDEX IF NOT EXISTS idx_events_process_name ON events(process_name);

    -- Detection rules table
    CREATE TABLE IF NOT EXISTS rules (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      severity TEXT NOT NULL,
      score INTEGER NOT NULL DEFAULT 50,
      mitre_tactic TEXT NOT NULL,
      mitre_technique_id TEXT NOT NULL,
      mitre_technique_name TEXT NOT NULL,
      mitre_subtechnique_id TEXT,
      enabled INTEGER NOT NULL DEFAULT 1,
      conditions_json TEXT NOT NULL,
      recommended_action TEXT DEFAULT 'Inspect process execution tree and quarantine if unverified.',
      why_explanation TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    -- Alerts generated by detection engine
    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      rule_id TEXT NOT NULL,
      rule_name TEXT NOT NULL,
      severity TEXT NOT NULL,
      score INTEGER NOT NULL DEFAULT 50,
      base_score INTEGER NOT NULL DEFAULT 0,
      risk_level TEXT NOT NULL DEFAULT 'Medium',
      score_factors_json TEXT,
      score_calculation_json TEXT,
      mitre_tactic TEXT NOT NULL,
      mitre_technique_id TEXT NOT NULL,
      mitre_technique_name TEXT NOT NULL,
      mitre_subtechnique_id TEXT,
      mitre_subtechnique_name TEXT,
      event_id INTEGER,
      timestamp TEXT NOT NULL,
      title TEXT NOT NULL,
      why_triggered TEXT NOT NULL,
      evidence_json TEXT,
      recommended_action TEXT,
      process_lineage_json TEXT,
      details_json TEXT,
      status TEXT NOT NULL DEFAULT 'NEW',
      resolved_at TEXT,
      resolved_by TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

    -- Threat intelligence indicators (IoCs)
    CREATE TABLE IF NOT EXISTS threat_intel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      value TEXT NOT NULL UNIQUE,
      description TEXT,
      threat_actor TEXT,
      severity TEXT NOT NULL DEFAULT 'HIGH',
      confidence INTEGER NOT NULL DEFAULT 90,
      added_at TEXT NOT NULL
    );

    -- Staged response actions requiring confirmation (Rule 10)
    CREATE TABLE IF NOT EXISTS response_actions (
      id TEXT PRIMARY KEY,
      alert_id TEXT,
      action_type TEXT NOT NULL,
      target TEXT NOT NULL,
      target_details TEXT,
      status TEXT NOT NULL DEFAULT 'PENDING_CONFIRMATION',
      requested_at TEXT NOT NULL,
      confirmed_at TEXT,
      confirmed_by TEXT,
      result_message TEXT
    );

    -- Immutable audit log table
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      action TEXT NOT NULL,
      actor TEXT NOT NULL,
      details TEXT
    );

    -- Internal system state & migrations metadata
    CREATE TABLE IF NOT EXISTS system_metadata (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    -- Dedicated Process Creation Events Table
    CREATE TABLE IF NOT EXISTS process_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      guid TEXT UNIQUE,
      pid INTEGER NOT NULL,
      parent_pid INTEGER NOT NULL,
      process_name TEXT NOT NULL,
      executable_path TEXT NOT NULL,
      command_line TEXT NOT NULL,
      username TEXT NOT NULL,
      hostname TEXT DEFAULT 'WIN-HOST',
      integrity_level TEXT NOT NULL DEFAULT 'Medium',
      creation_timestamp TEXT NOT NULL,
      sha256 TEXT,
      signature_status TEXT NOT NULL DEFAULT 'Unknown',
      publisher TEXT DEFAULT '',
      source TEXT NOT NULL DEFAULT 'sysmon_event_1',
      terminal_session_id INTEGER DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'running',
      is_terminated INTEGER NOT NULL DEFAULT 0,
      termination_timestamp TEXT,
      risk_score INTEGER NOT NULL DEFAULT 0,
      risk_level TEXT NOT NULL DEFAULT 'LOW',
      risk_factors TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_process_events_pid ON process_events(pid);
    CREATE INDEX IF NOT EXISTS idx_process_events_ppid ON process_events(parent_pid);
    CREATE INDEX IF NOT EXISTS idx_process_events_name ON process_events(process_name);
    CREATE INDEX IF NOT EXISTS idx_process_events_timestamp ON process_events(creation_timestamp);
    CREATE INDEX IF NOT EXISTS idx_process_events_sha256 ON process_events(sha256);
    CREATE INDEX IF NOT EXISTS idx_process_events_exe ON process_events(executable_path);

    -- Common Normalized Events Table
    CREATE TABLE IF NOT EXISTS normalized_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_uuid TEXT UNIQUE,
      event_category TEXT NOT NULL,
      event_type TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      hostname TEXT NOT NULL,
      provider TEXT,
      channel TEXT,
      windows_event_id INTEGER,
      severity TEXT NOT NULL DEFAULT 'INFORMATIONAL',
      action TEXT NOT NULL,
      user_name TEXT,
      user_domain TEXT,
      user_sid TEXT,
      logon_id TEXT,
      logon_type INTEGER,
      process_id INTEGER,
      process_name TEXT,
      process_path TEXT,
      command_line TEXT,
      parent_process_id INTEGER,
      parent_process_name TEXT,
      file_hash TEXT,
      source_ip TEXT,
      source_port INTEGER,
      destination_ip TEXT,
      destination_port INTEGER,
      protocol TEXT,
      target_user TEXT,
      target_resource TEXT,
      file_path TEXT,
      registry_key TEXT,
      service_name TEXT,
      service_file_name TEXT,
      task_name TEXT,
      script_text TEXT,
      message TEXT,
      data_json TEXT,
      is_alerted INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_norm_events_ts ON normalized_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_norm_events_cat ON normalized_events(event_category);
    CREATE INDEX IF NOT EXISTS idx_norm_events_channel ON normalized_events(channel);
    CREATE INDEX IF NOT EXISTS idx_norm_events_eid ON normalized_events(windows_event_id);
    CREATE INDEX IF NOT EXISTS idx_norm_events_user ON normalized_events(user_name);
    CREATE INDEX IF NOT EXISTS idx_norm_events_proc ON normalized_events(process_name);

    -- Lightweight Network Events and Connection Metadata Table
    CREATE TABLE IF NOT EXISTS network_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_uuid TEXT UNIQUE,
      timestamp TEXT NOT NULL,
      pid INTEGER NOT NULL,
      process_name TEXT NOT NULL,
      process_path TEXT,
      source_ip TEXT NOT NULL,
      source_port INTEGER NOT NULL,
      destination_ip TEXT NOT NULL,
      destination_port INTEGER NOT NULL,
      protocol TEXT NOT NULL DEFAULT 'TCP',
      connection_state TEXT NOT NULL DEFAULT 'ESTABLISHED',
      domain TEXT,
      direction TEXT NOT NULL DEFAULT 'outbound',
      bytes_sent INTEGER DEFAULT 0,
      bytes_received INTEGER DEFAULT 0,
      is_suspicious INTEGER NOT NULL DEFAULT 0,
      detection_tags TEXT,
      risk_score INTEGER DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_net_events_ts ON network_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_net_events_dest_ip ON network_events(destination_ip);
    CREATE INDEX IF NOT EXISTS idx_net_events_pid ON network_events(pid);
    CREATE INDEX IF NOT EXISTS idx_net_events_proc ON network_events(process_name);
    CREATE INDEX IF NOT EXISTS idx_net_events_suspicious ON network_events(is_suspicious);
    CREATE INDEX IF NOT EXISTS idx_net_events_port ON network_events(destination_port);

    -- Dedicated Event-Driven Filesystem Activity Table
    CREATE TABLE IF NOT EXISTS file_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_uuid TEXT UNIQUE,
      timestamp TEXT NOT NULL,
      action TEXT NOT NULL,
      file_path TEXT NOT NULL,
      old_file_path TEXT,
      file_name TEXT NOT NULL,
      file_extension TEXT,
      file_size_bytes INTEGER DEFAULT 0,
      file_category TEXT NOT NULL DEFAULT 'other',
      security_location TEXT NOT NULL DEFAULT 'custom',
      file_hash TEXT,
      hash_calculated INTEGER DEFAULT 0,
      hash_calculation_reason TEXT,
      pid INTEGER DEFAULT 0,
      process_name TEXT,
      process_path TEXT,
      is_suspicious INTEGER NOT NULL DEFAULT 0,
      detection_tags TEXT,
      risk_score INTEGER DEFAULT 0,
      detection_reasons TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_file_events_ts ON file_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_file_events_path ON file_events(file_path);
    CREATE INDEX IF NOT EXISTS idx_file_events_action ON file_events(action);
    CREATE INDEX IF NOT EXISTS idx_file_events_loc ON file_events(security_location);
    CREATE INDEX IF NOT EXISTS idx_file_events_susp ON file_events(is_suspicious);
    CREATE INDEX IF NOT EXISTS idx_file_events_hash ON file_events(file_hash);
  `);

  // Safe incremental migration for process_events columns if upgrading existing db
  try {
    const tableInfo = query<{ name: string }>("PRAGMA table_info(process_events)");
    const cols = tableInfo.map(c => c.name);
    if (!cols.includes('status')) {
      database.run("ALTER TABLE process_events ADD COLUMN status TEXT NOT NULL DEFAULT 'running'");
    }
    if (!cols.includes('is_terminated')) {
      database.run("ALTER TABLE process_events ADD COLUMN is_terminated INTEGER NOT NULL DEFAULT 0");
    }
    if (!cols.includes('termination_timestamp')) {
      database.run("ALTER TABLE process_events ADD COLUMN termination_timestamp TEXT");
    }
    if (!cols.includes('risk_score')) {
      database.run("ALTER TABLE process_events ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0");
    }
    if (!cols.includes('risk_level')) {
      database.run("ALTER TABLE process_events ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'LOW'");
    }
    if (!cols.includes('risk_factors')) {
      database.run("ALTER TABLE process_events ADD COLUMN risk_factors TEXT NOT NULL DEFAULT '[]'");
    }
    if (!cols.includes('hostname')) {
      database.run("ALTER TABLE process_events ADD COLUMN hostname TEXT DEFAULT 'WIN-HOST'");
    }

    // Safe migration for rules columns
    const rulesCols = query<{ name: string }>("PRAGMA table_info(rules)").map(c => c.name);
    if (!rulesCols.includes('score')) {
      database.run("ALTER TABLE rules ADD COLUMN score INTEGER NOT NULL DEFAULT 50");
    }
    if (!rulesCols.includes('recommended_action')) {
      database.run("ALTER TABLE rules ADD COLUMN recommended_action TEXT DEFAULT 'Inspect process execution tree.'");
    }

    // Safe migration for alerts columns
    const alertsCols = query<{ name: string }>("PRAGMA table_info(alerts)").map(c => c.name);
    if (!alertsCols.includes('score')) {
      database.run("ALTER TABLE alerts ADD COLUMN score INTEGER NOT NULL DEFAULT 50");
    }
    if (!alertsCols.includes('base_score')) {
      database.run("ALTER TABLE alerts ADD COLUMN base_score INTEGER NOT NULL DEFAULT 0");
    }
    if (!alertsCols.includes('risk_level')) {
      database.run("ALTER TABLE alerts ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'Medium'");
    }
    if (!alertsCols.includes('score_factors_json')) {
      database.run("ALTER TABLE alerts ADD COLUMN score_factors_json TEXT");
    }
    if (!alertsCols.includes('score_calculation_json')) {
      database.run("ALTER TABLE alerts ADD COLUMN score_calculation_json TEXT");
    }
    if (!alertsCols.includes('evidence_json')) {
      database.run("ALTER TABLE alerts ADD COLUMN evidence_json TEXT");
    }
    if (!alertsCols.includes('recommended_action')) {
      database.run("ALTER TABLE alerts ADD COLUMN recommended_action TEXT");
    }
    if (!alertsCols.includes('mitre_subtechnique_id')) {
      database.run("ALTER TABLE alerts ADD COLUMN mitre_subtechnique_id TEXT");
    }
    if (!alertsCols.includes('mitre_subtechnique_name')) {
      database.run("ALTER TABLE alerts ADD COLUMN mitre_subtechnique_name TEXT");
    }
  } catch (err) {
    log.debug('Database tables schema check complete');
  }
}
