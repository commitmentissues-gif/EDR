import fs from 'node:fs';
import path from 'node:path';
import initSqlJs, { Database, SqlJsStatic } from 'sql.js';

let SQL: SqlJsStatic | null = null;
let db: Database | null = null;
const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'localedr.db');

let saveTimeout: NodeJS.Timeout | null = null;

export async function initDatabase(): Promise<Database> {
  if (db) return db;

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  SQL = await initSqlJs();

  if (fs.existsSync(DB_FILE)) {
    try {
      const fileBuffer = fs.readFileSync(DB_FILE);
      db = new SQL.Database(fileBuffer);
    } catch (err) {
      console.error('Failed to load existing database file, creating fresh:', err);
      db = new SQL.Database();
    }
  } else {
    db = new SQL.Database();
  }

  setupSchema(db);
  seedDefaultData(db);
  saveDatabaseImmediately();

  return db;
}

export function getDatabase(): Database {
  if (!db) {
    throw new Error('Database not initialized! Call initDatabase() first.');
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
    console.error(`SQL Query Error: ${sql}`, err);
    throw err;
  }
}

export function run(sql: string, params: any[] = []): { changes: number; lastInsertRowid: number } {
  const database = getDatabase();
  try {
    database.run(sql, params);
    
    // Get last insert rowid
    const rowidRes = query<{ id: number }>('SELECT last_insert_rowid() as id');
    const lastInsertRowid = rowidRes[0]?.id || 0;
    
    scheduleSave();
    return { changes: 1, lastInsertRowid };
  } catch (err) {
    console.error(`SQL Run Error: ${sql}`, err);
    throw err;
  }
}

export function scheduleSave() {
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(() => {
    saveDatabaseImmediately();
  }, 1000);
}

export function saveDatabaseImmediately() {
  if (!db) return;
  try {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_FILE, buffer);
  } catch (err) {
    console.error('Failed to save SQLite database to disk:', err);
  }
}

function setupSchema(database: Database) {
  database.run(`
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
    CREATE INDEX IF NOT EXISTS idx_events_hash ON events(file_hash);

    CREATE TABLE IF NOT EXISTS rules (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      severity TEXT NOT NULL,
      mitre_tactic TEXT NOT NULL,
      mitre_technique_id TEXT NOT NULL,
      mitre_technique_name TEXT NOT NULL,
      mitre_subtechnique_id TEXT,
      enabled INTEGER NOT NULL DEFAULT 1,
      conditions_json TEXT NOT NULL,
      why_explanation TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      rule_id TEXT NOT NULL,
      rule_name TEXT NOT NULL,
      severity TEXT NOT NULL,
      mitre_tactic TEXT NOT NULL,
      mitre_technique_id TEXT NOT NULL,
      mitre_technique_name TEXT NOT NULL,
      event_id INTEGER,
      timestamp TEXT NOT NULL,
      title TEXT NOT NULL,
      why_triggered TEXT NOT NULL,
      process_lineage_json TEXT,
      details_json TEXT,
      status TEXT NOT NULL DEFAULT 'NEW',
      resolved_at TEXT,
      resolved_by TEXT,
      FOREIGN KEY(event_id) REFERENCES events(id)
    );

    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

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

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      action TEXT NOT NULL,
      actor TEXT NOT NULL,
      details TEXT
    );
  `);
}

function seedDefaultData(database: Database) {
  // Check if rules exist
  const existingRules = database.exec('SELECT COUNT(*) as cnt FROM rules');
  const count = (existingRules[0]?.values[0]?.[0] as number) || 0;

  if (count === 0) {
    const defaultRules = [
      {
        id: 'EDR-001',
        name: 'Suspicious Encoded PowerShell Execution',
        description: 'Detects PowerShell executed with base64 encoded command arguments (-enc, -encodedcommand) frequently used to bypass simple text inspection.',
        severity: 'HIGH',
        mitre_tactic: 'Execution',
        mitre_technique_id: 'T1059',
        mitre_subtechnique_id: 'T1059.001',
        mitre_technique_name: 'Command and Scripting Interpreter: PowerShell',
        enabled: 1,
        conditions_json: JSON.stringify({
          event_type: 'process_creation',
          process_name: ['powershell.exe', 'pwsh.exe'],
          command_line_match: ['-enc', '-encodedcommand', '-e ', '-ec '],
          case_insensitive: true
        }),
        why_explanation: 'PowerShell was spawned with encoded execution flags (-enc/-encodedcommand). Attackers frequently obfuscate payload strings to evade signature-based detection and prevent command line auditing.',
        created_at: new Date().toISOString()
      },
      {
        id: 'EDR-002',
        name: 'LOLBAS Certutil Remote Download Syntax',
        description: 'Detects abuse of certutil.exe with -urlcache and -split parameters to download remote files from the internet.',
        severity: 'HIGH',
        mitre_tactic: 'Command and Control',
        mitre_technique_id: 'T1105',
        mitre_subtechnique_id: '',
        mitre_technique_name: 'Ingress Tool Transfer',
        enabled: 1,
        conditions_json: JSON.stringify({
          event_type: 'process_creation',
          process_name: ['certutil.exe'],
          command_line_match: ['-urlcache', '-split'],
          case_insensitive: true
        }),
        why_explanation: 'Certutil is a Windows certificate utility. Invoking it with "-urlcache" and "-split" is a well-known Living-off-the-Land (LOLBAS) technique to bypass web filtering and download malicious binaries without third-party tools.',
        created_at: new Date().toISOString()
      },
      {
        id: 'EDR-003',
        name: 'Rapid Endpoint Reconnaissance & Discovery',
        description: 'Detects standard discovery utilities (whoami, net user, systeminfo, nltest) executed to map users, domain trusts, or system privileges.',
        severity: 'MEDIUM',
        mitre_tactic: 'Discovery',
        mitre_technique_id: 'T1087',
        mitre_subtechnique_id: 'T1087.001',
        mitre_technique_name: 'Account Discovery: Local Account',
        enabled: 1,
        conditions_json: JSON.stringify({
          event_type: 'process_creation',
          process_name: ['whoami.exe', 'systeminfo.exe', 'net.exe', 'nltest.exe', 'klist.exe'],
          command_line_match: ['/priv', 'user', 'group', 'localgroup', '/dclist'],
          case_insensitive: true
        }),
        why_explanation: 'Execution of discovery binaries like whoami, net user, or nltest suggests post-compromise enumeration where an adversary or script is fingerprinting host privileges or domain environment.',
        created_at: new Date().toISOString()
      },
      {
        id: 'EDR-004',
        name: 'Shadow Copy Deletion via VSSAdmin',
        description: 'Detects attempts to delete Volume Shadow Copies using vssadmin.exe, a common ransomware tactic to inhibit data recovery.',
        severity: 'CRITICAL',
        mitre_tactic: 'Impact',
        mitre_technique_id: 'T1490',
        mitre_subtechnique_id: '',
        mitre_technique_name: 'Inhibit System Recovery',
        enabled: 1,
        conditions_json: JSON.stringify({
          event_type: 'process_creation',
          process_name: ['vssadmin.exe', 'wmic.exe'],
          command_line_match: ['delete shadows', 'shadowcopy delete'],
          case_insensitive: true
        }),
        why_explanation: 'VSSAdmin was invoked with "delete shadows". Legitimate administrative tasks rarely wipe all volume snapshots silently; this command is a hallmark indicator of ransomware preparing for irreversible file encryption.',
        created_at: new Date().toISOString()
      },
      {
        id: 'EDR-005',
        name: 'Office Application Spawning Command Interpreter',
        description: 'Detects Microsoft Office processes (Word, Excel, PowerPoint) spawning command line shells or script engines.',
        severity: 'CRITICAL',
        mitre_tactic: 'Execution',
        mitre_technique_id: 'T1204',
        mitre_subtechnique_id: 'T1204.002',
        mitre_technique_name: 'User Execution: Malicious File',
        enabled: 1,
        conditions_json: JSON.stringify({
          event_type: 'process_creation',
          parent_process_name: ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'],
          process_name: ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'],
          case_insensitive: true
        }),
        why_explanation: 'A Microsoft Office application spawned a command interpreter. This pattern almost always indicates weaponized document macros, exploit payload execution (e.g. CVE-2021-40444, Follina), or malicious attachment execution.',
        created_at: new Date().toISOString()
      },
      {
        id: 'EDR-006',
        name: 'Registry Run/RunOnce Key Persistence',
        description: 'Detects creation or modification of Windows autostart Run or RunOnce keys used to achieve persistence.',
        severity: 'HIGH',
        mitre_tactic: 'Persistence',
        mitre_technique_id: 'T1547',
        mitre_subtechnique_id: 'T1547.001',
        mitre_technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys',
        enabled: 1,
        conditions_json: JSON.stringify({
          event_type: 'registry_event',
          registry_key_match: ['\\CurrentVersion\\Run', '\\CurrentVersion\\RunOnce'],
          case_insensitive: true
        }),
        why_explanation: 'Modification of Run or RunOnce registry keys causes designated executables to launch automatically when any user logs in, establishing survivable persistence across system reboots.',
        created_at: new Date().toISOString()
      },
      {
        id: 'EDR-007',
        name: 'Windows Defender Real-time Monitoring Tampering',
        description: 'Detects commands attempting to disable or impair Microsoft Defender antivirus real-time inspection.',
        severity: 'HIGH',
        mitre_tactic: 'Defense Evasion',
        mitre_technique_id: 'T1562',
        mitre_subtechnique_id: 'T1562.001',
        mitre_technique_name: 'Impair Defenses: Disable or Modify Tools',
        enabled: 1,
        conditions_json: JSON.stringify({
          event_type: 'process_creation',
          command_line_match: ['Set-MpPreference', 'DisableRealtimeMonitoring', 'sc stop WinDefend', 'sc config WinDefend start= disabled'],
          case_insensitive: true
        }),
        why_explanation: 'Command arguments target Defender security controls directly (Set-MpPreference DisableRealtimeMonitoring or stopping WinDefend service), blinding host defenses prior to secondary stage malware execution.',
        created_at: new Date().toISOString()
      },
      {
        id: 'EDR-008',
        name: 'MSHTA Proxy Script Execution',
        description: 'Detects mshta.exe executing inline javascript/vbscript or remote HTML applications.',
        severity: 'HIGH',
        mitre_tactic: 'Defense Evasion',
        mitre_technique_id: 'T1218',
        mitre_subtechnique_id: 'T1218.005',
        mitre_technique_name: 'System Binary Proxy Execution: Mshta',
        enabled: 1,
        conditions_json: JSON.stringify({
          event_type: 'process_creation',
          process_name: ['mshta.exe'],
          command_line_match: ['javascript:', 'vbscript:', 'http://', 'https://'],
          case_insensitive: true
        }),
        why_explanation: 'MSHTA.exe is designed to execute Microsoft HTML Application (.hta) files. Invoking it with protocol handlers like javascript:, vbscript:, or remote URLs executes arbitrary code outside standard browser security sandboxes.',
        created_at: new Date().toISOString()
      },
      {
        id: 'EDR-009',
        name: 'Threat Intelligence Known Malicious Hash / IP Match',
        description: 'Detects processes matching verified malicious file hashes or outbound network connections to high-confidence threat infrastructure.',
        severity: 'CRITICAL',
        mitre_tactic: 'Command and Control',
        mitre_technique_id: 'T1071',
        mitre_subtechnique_id: '',
        mitre_technique_name: 'Application Layer Protocol',
        enabled: 1,
        conditions_json: JSON.stringify({
          threat_intel_match: true
        }),
        why_explanation: 'The observed file hash (SHA256) or destination IP address matches a verified indicator of compromise (IoC) from the LocalEDR threat intelligence database.',
        created_at: new Date().toISOString()
      }
    ];

    for (const rule of defaultRules) {
      database.run(
        `INSERT INTO rules (id, name, description, severity, mitre_tactic, mitre_technique_id, mitre_technique_name, mitre_subtechnique_id, enabled, conditions_json, why_explanation, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          rule.id,
          rule.name,
          rule.description,
          rule.severity,
          rule.mitre_tactic,
          rule.mitre_technique_id,
          rule.mitre_technique_name,
          rule.mitre_subtechnique_id,
          rule.enabled,
          rule.conditions_json,
          rule.why_explanation,
          rule.created_at
        ]
      );
    }
  }

  // Check threat intelligence table
  const existingIoCs = database.exec('SELECT COUNT(*) as cnt FROM threat_intel');
  const iocCount = (existingIoCs[0]?.values[0]?.[0] as number) || 0;
  if (iocCount === 0) {
    const defaultIoCs = [
      {
        type: 'sha256',
        value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        description: 'Emotet Dropper Generic Loader Sample',
        threat_actor: 'TA542',
        severity: 'CRITICAL',
        confidence: 95
      },
      {
        type: 'sha256',
        value: '44d88612fea8a8f36de82e1278abb02f',
        description: 'Cobalt Strike Beacon Stager Test Hash',
        threat_actor: 'Generic Red Team / APT',
        severity: 'CRITICAL',
        confidence: 90
      },
      {
        type: 'ip',
        value: '198.51.100.42',
        description: 'Known C2 Beacon IP (Simulated Threat Intel Feed)',
        threat_actor: 'FIN7 / Carbanak Simulation',
        severity: 'HIGH',
        confidence: 85
      },
      {
        type: 'ip',
        value: '203.0.113.88',
        description: 'Command & Control Relay Exfiltration Server',
        threat_actor: 'Lazarus Test Feed',
        severity: 'HIGH',
        confidence: 90
      }
    ];

    for (const ioc of defaultIoCs) {
      database.run(
        `INSERT OR IGNORE INTO threat_intel (type, value, description, threat_actor, severity, confidence, added_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [ioc.type, ioc.value, ioc.description, ioc.threat_actor, ioc.severity, ioc.confidence, new Date().toISOString()]
      );
    }
  }

  // Add initial audit log
  database.run(
    `INSERT INTO audit_logs (timestamp, action, actor, details) VALUES (?, ?, ?, ?)`,
    [new Date().toISOString(), 'SYSTEM_INITIALIZATION', 'SYSTEM', 'LocalEDR database schema initialized and rule catalog loaded.']
  );
}
