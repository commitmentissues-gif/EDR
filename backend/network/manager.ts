import { query, run, scheduleSave } from '../db/index.js';
import { logger } from '../logger/index.js';
import { 
  NetworkEvent, 
  NetworkFilterOptions, 
  NetworkAggregatedStats, 
  NetworkDetectorConfig,
  SafeNetworkSimulationScenario 
} from './types.js';
import { networkDetector, DEFAULT_NETWORK_CONFIG } from './detector.js';
import { networkCollector } from './collector.js';
import { getProcessByPid } from '../process/index.js';

const log = logger.forComponent('NetworkManager');

export const SAFE_NETWORK_SIMULATIONS: SafeNetworkSimulationScenario[] = [
  {
    id: 'SIM-NET-BENIGN-CHROME-HTTPS',
    name: 'Benign: Google Chrome Secure HTTPS Browsing',
    category: 'benign_traffic',
    description: 'Legitimate web browser connecting to Google CDN via encrypted TLS on port 443.',
    expectedAlert: false,
    process_name: 'chrome.exe',
    pid: 4120,
    source_ip: '192.168.1.105',
    source_port: 52140,
    destination_ip: '142.250.190.46',
    destination_port: 443,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    domain: 'www.google.com',
    direction: 'outbound',
    explanation: 'Standard web browsing on port 443 by a signed commercial browser. Expected result: Ingested as clean baseline traffic.'
  },
  {
    id: 'SIM-NET-BENIGN-DNS-LOOKUP',
    name: 'Benign: Localhost DNS Query to Cloudflare Resolver',
    category: 'benign_traffic',
    description: 'System DNS client issuing standard domain resolution query to 1.1.1.1 on UDP port 53.',
    expectedAlert: false,
    process_name: 'svchost.exe',
    pid: 892,
    source_ip: '192.168.1.105',
    source_port: 58219,
    destination_ip: '1.1.1.1',
    destination_port: 53,
    protocol: 'UDP',
    connection_state: 'ESTABLISHED',
    domain: 'one.one.one.one',
    direction: 'outbound',
    explanation: 'Standard UDP DNS resolution to public recursive resolver. Expected result: Ingested as clean baseline traffic.'
  },
  {
    id: 'SIM-NET-BENIGN-WINDOWS-UPDATE',
    name: 'Benign: Windows Update Service Handshake',
    category: 'benign_traffic',
    description: 'svchost.exe connecting to official Microsoft Update endpoints over standard HTTPS.',
    expectedAlert: false,
    process_name: 'svchost.exe',
    pid: 1044,
    source_ip: '192.168.1.105',
    source_port: 49812,
    destination_ip: '20.189.173.1',
    destination_port: 443,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    domain: 'windowsupdate.microsoft.com',
    direction: 'outbound',
    explanation: 'Legitimate OS update delivery connection. Expected result: Ingested as clean baseline traffic.'
  },
  {
    id: 'SIM-NET-MALICIOUS-IP',
    name: 'Detection: Outbound Connection to Known Malicious C2 IP',
    category: 'malicious_detection',
    description: 'PowerShell establishing outbound connection to a flagged adversary Command & Control IP (198.51.100.45).',
    expectedAlert: true,
    process_name: 'powershell.exe',
    pid: 2940,
    source_ip: '192.168.1.105',
    source_port: 49912,
    destination_ip: '198.51.100.45',
    destination_port: 443,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    domain: 'c2-teamserver.advesary-net.ru',
    direction: 'outbound',
    explanation: 'Flags KNOWN_MALICIOUS_IP due to threat intelligence match on Cobalt Strike C2 IP. MITRE ATT&CK T1071.'
  },
  {
    id: 'SIM-NET-UNCOMMON-PORT',
    name: 'Detection: Command Shell Reverse TCP on Port 4444',
    category: 'malicious_detection',
    description: 'cmd.exe establishing an outbound TCP socket to an external address on non-standard port 4444 (Metasploit default).',
    expectedAlert: true,
    process_name: 'cmd.exe',
    pid: 3812,
    source_ip: '192.168.1.105',
    source_port: 50114,
    destination_ip: '198.51.100.22',
    destination_port: 4444,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    direction: 'outbound',
    explanation: 'Flags UNCOMMON_PORT & SUSPICIOUS_PROCESS_NETWORK for cmd.exe connecting outbound to Metasploit port 4444. MITRE ATT&CK T1571.'
  },
  {
    id: 'SIM-NET-SUSPICIOUS-DESTINATION',
    name: 'Detection: Outbound Connection to Dynamic DNS / Risky TLD',
    category: 'malicious_detection',
    description: 'PowerShell connecting to dynamic DNS staging hostname on suspicious top-level domain (evil-host.duckdns.org / .xyz).',
    expectedAlert: true,
    process_name: 'powershell.exe',
    pid: 4812,
    source_ip: '192.168.1.105',
    source_port: 51200,
    destination_ip: '185.220.101.5',
    destination_port: 8080,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    domain: 'staged-payload.duckdns.org',
    direction: 'outbound',
    explanation: 'Flags SUSPICIOUS_DESTINATION due to dynamic DNS provider duckdns.org often leveraged for evasion. MITRE ATT&CK T1071.001.'
  },
  {
    id: 'SIM-NET-OFFICE-OUTBOUND',
    name: 'Detection: Microsoft Word Initiating Outbound Network Connection',
    category: 'malicious_detection',
    description: 'winword.exe initiating outbound network socket to external IP, typical of weaponized macro or remote template injection.',
    expectedAlert: true,
    process_name: 'winword.exe',
    pid: 5920,
    source_ip: '192.168.1.105',
    source_port: 52188,
    destination_ip: '91.240.118.172',
    destination_port: 80,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    domain: 'doc-template-render.top',
    direction: 'outbound',
    explanation: 'Flags SUSPICIOUS_PROCESS_NETWORK: Office applications should not initiate outbound internet connections. MITRE ATT&CK T1204.002.'
  },
  {
    id: 'SIM-NET-UNUSUAL-SYSTEM-OUTBOUND',
    name: 'Detection: Core Windows Process (notepad.exe) Outbound Network Socket',
    category: 'malicious_detection',
    description: 'notepad.exe connecting to remote host, indicative of process hollowing, reflective DLL injection, or shellcode execution.',
    expectedAlert: true,
    process_name: 'notepad.exe',
    pid: 6104,
    source_ip: '192.168.1.105',
    source_port: 53100,
    destination_ip: '45.142.214.123',
    destination_port: 443,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    domain: 'relay.stealer-drop.ru',
    direction: 'outbound',
    explanation: 'Flags UNUSUAL_OUTBOUND_CONNECTION: notepad.exe is a local text editor with no legitimate outbound network functionality. MITRE ATT&CK T1071.'
  },
  {
    id: 'SIM-NET-BEACONING-PATTERN',
    name: 'Detection: Rundll32 Periodic Low-Jitter C2 Beaconing',
    category: 'malicious_detection',
    description: 'rundll32.exe making repeated consecutive network requests to the same external IP at fixed intervals.',
    expectedAlert: true,
    process_name: 'rundll32.exe',
    pid: 6720,
    source_ip: '192.168.1.105',
    source_port: 54100,
    destination_ip: '203.0.113.88',
    destination_port: 8443,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    direction: 'outbound',
    explanation: 'Flags BEACONING_PATTERN & SUSPICIOUS_PROCESS_NETWORK: low jitter periodic callbacks simulate Cobalt Strike HTTP beacon. MITRE ATT&CK T1071.'
  },
  {
    id: 'SIM-NET-CERTUTIL-DOWNLOAD',
    name: 'Detection: Certutil Remote Web Payload Ingress Transfer',
    category: 'malicious_detection',
    description: 'certutil.exe establishing an outbound HTTP socket to download external binary files.',
    expectedAlert: true,
    process_name: 'certutil.exe',
    pid: 7210,
    source_ip: '192.168.1.105',
    source_port: 55420,
    destination_ip: '194.26.29.114',
    destination_port: 80,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    domain: 'staging.dropper-cdn.com',
    direction: 'outbound',
    explanation: 'Flags SUSPICIOUS_PROCESS_NETWORK: certutil.exe download syntax / ingress tool transfer. MITRE ATT&CK T1105.'
  }
];

export class NetworkManager {
  constructor() {}

  /**
   * Initializes network subsystem tables and default config
   */
  initDatabase(): void {
    try {
      // Ensure network_events table has all expected columns
      const tableInfo = query<{ name: string }>('PRAGMA table_info(network_events)');
      const colNames = tableInfo.map(c => c.name);

      if (!colNames.includes('parent_pid')) {
        run('ALTER TABLE network_events ADD COLUMN parent_pid INTEGER DEFAULT 0');
      }
      if (!colNames.includes('parent_process_name')) {
        run('ALTER TABLE network_events ADD COLUMN parent_process_name TEXT');
      }
      if (!colNames.includes('username')) {
        run('ALTER TABLE network_events ADD COLUMN username TEXT');
      }
      if (!colNames.includes('signature_status')) {
        run("ALTER TABLE network_events ADD COLUMN signature_status TEXT DEFAULT 'Unknown'");
      }
      if (!colNames.includes('detection_reasons')) {
        run('ALTER TABLE network_events ADD COLUMN detection_reasons TEXT');
      }

      // Check stored config in system_metadata
      const cfgRow = query<{ value: string }>(
        'SELECT value FROM system_metadata WHERE key = "network_detector_config"'
      );
      if (cfgRow && cfgRow[0]) {
        try {
          const parsed = JSON.parse(cfgRow[0].value);
          networkDetector.updateConfig(parsed);
          log.info('Loaded persisted NetworkDetectorConfig from SQLite.');
        } catch {
          // Keep defaults
        }
      } else {
        // Save initial default
        run(
          'INSERT OR REPLACE INTO system_metadata (key, value, updated_at) VALUES (?, ?, ?)',
          ['network_detector_config', JSON.stringify(DEFAULT_NETWORK_CONFIG), new Date().toISOString()]
        );
      }

      // Seed baseline traffic
      networkCollector.seedBaselineConnections();
      scheduleSave();
    } catch (err: any) {
      log.error('Failed to initialize network subsystem in database:', err);
    }
  }

  /**
   * Query filtered network events with pagination
   */
  getNetworkEvents(options: NetworkFilterOptions = {}): {
    events: NetworkEvent[];
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
      conditions.push('(process_name LIKE ? OR destination_ip LIKE ? OR domain LIKE ? OR source_ip LIKE ?)');
      params.push(term, term, term, term);
    }

    if (options.pid !== undefined && options.pid > 0) {
      conditions.push('pid = ?');
      params.push(options.pid);
    }

    if (options.process_name) {
      conditions.push('process_name LIKE ?');
      params.push(`%${options.process_name}%`);
    }

    if (options.destination_ip) {
      conditions.push('destination_ip LIKE ?');
      params.push(`%${options.destination_ip}%`);
    }

    if (options.destination_port !== undefined && options.destination_port > 0) {
      conditions.push('destination_port = ?');
      params.push(options.destination_port);
    }

    if (options.protocol && options.protocol !== 'all') {
      conditions.push('protocol = ?');
      params.push(options.protocol);
    }

    if (options.is_suspicious !== undefined) {
      conditions.push('is_suspicious = ?');
      params.push(options.is_suspicious ? 1 : 0);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countQuery = `SELECT COUNT(*) as total FROM network_events ${whereClause}`;
    const countRows = query<{ total: number }>(countQuery, params);
    const total = countRows[0] ? countRows[0].total : 0;

    const dataQuery = `
      SELECT * FROM network_events 
      ${whereClause} 
      ORDER BY id DESC 
      LIMIT ? OFFSET ?
    `;
    const rows = query<any>(dataQuery, [...params, limit, offset]);

    const events: NetworkEvent[] = rows.map(r => ({
      id: r.id,
      event_uuid: r.event_uuid,
      timestamp: r.timestamp,
      pid: r.pid,
      process_name: r.process_name,
      process_path: r.process_path,
      parent_pid: r.parent_pid,
      parent_process_name: r.parent_process_name,
      username: r.username,
      signature_status: r.signature_status,
      source_ip: r.source_ip,
      source_port: r.source_port,
      destination_ip: r.destination_ip,
      destination_port: r.destination_port,
      protocol: r.protocol,
      connection_state: r.connection_state,
      domain: r.domain,
      direction: r.direction,
      bytes_sent: r.bytes_sent,
      bytes_received: r.bytes_received,
      is_suspicious: Boolean(r.is_suspicious),
      detection_tags: typeof r.detection_tags === 'string' ? JSON.parse(r.detection_tags || '[]') : (r.detection_tags || []),
      risk_score: r.risk_score,
      detection_reasons: typeof r.detection_reasons === 'string' ? JSON.parse(r.detection_reasons || '[]') : [],
      created_at: r.created_at
    }));

    return { events, total, limit, offset };
  }

  /**
   * Aggregates key network dashboard statistics
   */
  getAggregatedStats(): NetworkAggregatedStats {
    const totalRow = query<{ total: number }>('SELECT COUNT(*) as total FROM network_events');
    const totalEvents = totalRow[0]?.total || 0;

    const activeRow = query<{ count: number }>(
      "SELECT COUNT(*) as count FROM network_events WHERE connection_state IN ('ESTABLISHED', 'LISTENING')"
    );
    const activeConnectionsCount = activeRow[0]?.count || 0;

    const outboundRow = query<{ count: number }>(
      "SELECT COUNT(*) as count FROM network_events WHERE direction = 'outbound'"
    );
    const outboundCount = outboundRow[0]?.count || 0;

    const inboundRow = query<{ count: number }>(
      "SELECT COUNT(*) as count FROM network_events WHERE direction = 'inbound'"
    );
    const inboundCount = inboundRow[0]?.count || 0;

    const suspRow = query<{ count: number }>(
      'SELECT COUNT(*) as count FROM network_events WHERE is_suspicious = 1'
    );
    const suspiciousCount = suspRow[0]?.count || 0;

    const uniqueProcRow = query<{ count: number }>(
      'SELECT COUNT(DISTINCT process_name) as count FROM network_events'
    );
    const uniqueProcessesCount = uniqueProcRow[0]?.count || 0;

    const uniqueDestRow = query<{ count: number }>(
      'SELECT COUNT(DISTINCT destination_ip) as count FROM network_events WHERE destination_ip != "0.0.0.0"'
    );
    const uniqueDestinationsCount = uniqueDestRow[0]?.count || 0;

    // Top destinations
    const topDestRows = query<{ destination_ip: string; domain: string | null; count: number; max_susp: number }>(
      `SELECT destination_ip, domain, COUNT(*) as count, MAX(is_suspicious) as max_susp
       FROM network_events 
       WHERE destination_ip != '0.0.0.0' AND destination_ip != '127.0.0.1'
       GROUP BY destination_ip 
       ORDER BY count DESC 
       LIMIT 8`
    );

    const topDestinations = topDestRows.map(r => ({
      ip: r.destination_ip,
      domain: r.domain || undefined,
      count: r.count,
      isSuspicious: Boolean(r.max_susp)
    }));

    // Top ports
    const portServiceMap: Record<number, string> = {
      80: 'HTTP',
      443: 'HTTPS / TLS',
      53: 'DNS',
      22: 'SSH',
      123: 'NTP Time',
      445: 'SMB / IPC',
      3389: 'RDP',
      4444: 'Metasploit C2',
      1337: 'Hacker Shell',
      6667: 'IRC Botnet',
      8080: 'HTTP Proxy',
      8443: 'HTTPS Alternate',
      9001: 'Tor Relay'
    };

    const topPortRows = query<{ destination_port: number; count: number }>(
      `SELECT destination_port, COUNT(*) as count 
       FROM network_events 
       WHERE destination_port > 0 
       GROUP BY destination_port 
       ORDER BY count DESC 
       LIMIT 8`
    );

    const commonPorts = new Set(networkDetector.getConfig().commonAllowedPorts);
    const topPorts = topPortRows.map(r => ({
      port: r.destination_port,
      count: r.count,
      serviceName: portServiceMap[r.destination_port] || (r.destination_port > 1024 ? 'High Ephemeral Port' : 'TCP/UDP Service'),
      isCommon: commonPorts.has(r.destination_port)
    }));

    // Top processes
    const topProcRows = query<{ process_name: string; pid: number; count: number; max_susp: number }>(
      `SELECT process_name, pid, COUNT(*) as count, MAX(is_suspicious) as max_susp 
       FROM network_events 
       GROUP BY process_name 
       ORDER BY count DESC 
       LIMIT 8`
    );

    const topProcesses = topProcRows.map(r => ({
      process_name: r.process_name,
      pid: r.pid,
      connectionCount: r.count,
      isSuspicious: Boolean(r.max_susp)
    }));

    return {
      totalEvents,
      activeConnectionsCount,
      outboundCount,
      inboundCount,
      suspiciousCount,
      uniqueProcessesCount,
      uniqueDestinationsCount,
      topDestinations,
      topPorts,
      topProcesses
    };
  }

  /**
   * Retrieves all network connections associated with a specific process PID
   */
  getProcessNetworkConnections(pid: number): {
    processInfo: any;
    connections: NetworkEvent[];
  } {
    const procInfo = getProcessByPid(pid);
    const rows = query<any>(
      'SELECT * FROM network_events WHERE pid = ? ORDER BY id DESC LIMIT 100',
      [pid]
    );

    const connections: NetworkEvent[] = rows.map(r => ({
      id: r.id,
      event_uuid: r.event_uuid,
      timestamp: r.timestamp,
      pid: r.pid,
      process_name: r.process_name,
      process_path: r.process_path,
      parent_pid: r.parent_pid,
      parent_process_name: r.parent_process_name,
      username: r.username,
      signature_status: r.signature_status,
      source_ip: r.source_ip,
      source_port: r.source_port,
      destination_ip: r.destination_ip,
      destination_port: r.destination_port,
      protocol: r.protocol,
      connection_state: r.connection_state,
      domain: r.domain,
      direction: r.direction,
      bytes_sent: r.bytes_sent,
      bytes_received: r.bytes_received,
      is_suspicious: Boolean(r.is_suspicious),
      detection_tags: typeof r.detection_tags === 'string' ? JSON.parse(r.detection_tags || '[]') : [],
      risk_score: r.risk_score,
      detection_reasons: typeof r.detection_reasons === 'string' ? JSON.parse(r.detection_reasons || '[]') : [],
      created_at: r.created_at
    }));

    return {
      processInfo: procInfo.process,
      connections
    };
  }

  /**
   * Returns list of safe simulation scenarios
   */
  getSimulations(): SafeNetworkSimulationScenario[] {
    return SAFE_NETWORK_SIMULATIONS;
  }

  /**
   * Executes a safe simulation scenario and returns the generated event and alert status
   */
  runSimulation(scenarioId: string): {
    success: boolean;
    scenario: SafeNetworkSimulationScenario;
    event: NetworkEvent;
    detectedAlert: boolean;
    message: string;
  } {
    const scenario = SAFE_NETWORK_SIMULATIONS.find(s => s.id === scenarioId);
    if (!scenario) {
      throw new Error(`Simulation scenario '${scenarioId}' not found.`);
    }

    log.info(`Executing safe network simulation '${scenario.name}' [${scenario.id}]...`);

    let ingestedEvent!: NetworkEvent;

    // Special handling for beaconing pattern to send multiple sequential entries
    if (scenario.id === 'SIM-NET-BEACONING-PATTERN') {
      const baseTime = Date.now();
      // Send 4 periodic requests with exactly 5 second intervals to simulate low-jitter beaconing
      for (let i = 0; i < 4; i++) {
        ingestedEvent = networkCollector.ingestConnection({
          process_name: scenario.process_name,
          pid: scenario.pid,
          source_ip: scenario.source_ip,
          source_port: scenario.source_port + i,
          destination_ip: scenario.destination_ip,
          destination_port: scenario.destination_port,
          protocol: scenario.protocol,
          connection_state: scenario.connection_state,
          direction: scenario.direction,
          domain: scenario.domain,
          timestamp: new Date(baseTime + (i * 5000)).toISOString()
        });
      }
    } else {
      ingestedEvent = networkCollector.ingestConnection({
        process_name: scenario.process_name,
        pid: scenario.pid,
        source_ip: scenario.source_ip,
        source_port: scenario.source_port,
        destination_ip: scenario.destination_ip,
        destination_port: scenario.destination_port,
        protocol: scenario.protocol,
        connection_state: scenario.connection_state,
        direction: scenario.direction,
        domain: scenario.domain,
        timestamp: new Date().toISOString()
      });
    }

    const detectedAlert = ingestedEvent.is_suspicious;
    const testPassed = detectedAlert === scenario.expectedAlert;

    const message = testPassed
      ? `Simulation passed: Expected Alert = ${scenario.expectedAlert}, Result = ${detectedAlert}.`
      : `Simulation mismatch: Expected Alert = ${scenario.expectedAlert}, but got ${detectedAlert}.`;

    log.info(`[Simulation Result] ${scenario.id}: ${message}`);

    return {
      success: testPassed,
      scenario,
      event: ingestedEvent,
      detectedAlert,
      message
    };
  }

  /**
   * Updates configuration and persists to SQLite system_metadata
   */
  updateConfig(cfg: Partial<NetworkDetectorConfig>): NetworkDetectorConfig {
    networkDetector.updateConfig(cfg);
    const updated = networkDetector.getConfig();

    try {
      run(
        'INSERT OR REPLACE INTO system_metadata (key, value, updated_at) VALUES (?, ?, ?)',
        ['network_detector_config', JSON.stringify(updated), new Date().toISOString()]
      );
      scheduleSave();
    } catch (err: any) {
      log.error('Failed to save network detector config to SQLite:', err);
    }

    return updated;
  }

  getConfig(): NetworkDetectorConfig {
    return networkDetector.getConfig();
  }
}

export const networkManager = new NetworkManager();
