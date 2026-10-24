import { initDatabase, query } from '../backend/db/index.js';
import { 
  networkCollector, 
  networkDetector, 
  networkManager, 
  DEFAULT_NETWORK_CONFIG,
  SAFE_NETWORK_SIMULATIONS,
  isPrivateOrLocalIp
} from '../backend/network/index.js';
import { recordProcessEvent } from '../backend/process/index.js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    console.log(`  \x1b[32m✔\x1b[0m ${message}`);
    passed++;
  } else {
    console.error(`  \x1b[31m✖\x1b[0m ${message}`);
    failed++;
  }
}

export async function runNetworkTelemetryTests(): Promise<{ passed: number; failed: number }> {
  passed = 0;
  failed = 0;
  console.log('\n\x1b[1m=== Running LocalEDR Lightweight Network Telemetry Test Suite ===\x1b[0m\n');

  await initDatabase();
  networkManager.initDatabase();

  // Test Suite 1: SQLite Schema & Storage
  console.log('\x1b[36m[Test Suite 1: SQLite Storage & Schema Verification]\x1b[0m');
  const tableCheck = query<{ count: number }>(
    "SELECT COUNT(*) as count FROM sqlite_master WHERE type='table' AND name='network_events'"
  );
  assert(tableCheck[0]?.count === 1, 'network_events table exists in SQLite database');

  const baselineStats = networkManager.getAggregatedStats();
  assert(baselineStats.totalEvents > 0, `Baseline network connections seeded (found ${baselineStats.totalEvents})`);
  assert(baselineStats.activeConnectionsCount > 0, 'Active connections counted correctly');
  assert(baselineStats.topDestinations.length > 0, 'Top destinations aggregated');
  assert(baselineStats.topPorts.length > 0, 'Top ports aggregated');

  // Test Suite 2: Process Association
  console.log('\n\x1b[36m[Test Suite 2: Network Connection Process Association]\x1b[0m');
  
  // Register a test process in process_events
  const testPid = 8844;
  recordProcessEvent({
    pid: testPid,
    parent_pid: 1000,
    process_name: 'custom_daemon.exe',
    executable_path: 'C:\\Program Files\\CustomDaemon\\custom_daemon.exe',
    command_line: 'custom_daemon.exe --worker',
    username: 'CORP\\service_user',
    signature_status: 'Valid'
  });

  const assocConn = networkCollector.ingestConnection({
    pid: testPid,
    source_ip: '192.168.1.105',
    source_port: 48999,
    destination_ip: '93.184.216.34',
    destination_port: 443,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    domain: 'example.com'
  });

  assert(assocConn.process_name === 'custom_daemon.exe', 'Associated connection with registered process_name');
  assert(assocConn.parent_pid === 1000, 'Associated parent_pid correctly');
  assert(assocConn.username === 'CORP\\service_user', 'Associated username context');
  assert(assocConn.signature_status === 'Valid', 'Associated digital signature status');

  const procConnections = networkManager.getProcessNetworkConnections(testPid);
  assert(procConnections.connections.length >= 1, 'Retrieved connections by PID');
  assert(procConnections.processInfo?.process_name === 'custom_daemon.exe', 'Retrieved associated processInfo');

  // Test Suite 3: Benign Traffic Immunity (Zero False Positives)
  console.log('\n\x1b[36m[Test Suite 3: Benign Traffic Immunity (No False Alerts)]\x1b[0m');
  
  // Chrome HTTPS browsing
  const benignChrome = networkCollector.ingestConnection({
    pid: 5010,
    process_name: 'chrome.exe',
    source_ip: '192.168.1.105',
    source_port: 51220,
    destination_ip: '142.250.190.46',
    destination_port: 443,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    domain: 'www.google.com'
  });
  assert(!benignChrome.is_suspicious, 'Chrome HTTPS browsing is classified as benign (0 alerts)');

  // Localhost DNS query
  const benignDns = networkCollector.ingestConnection({
    pid: 412,
    process_name: 'svchost.exe',
    source_ip: '192.168.1.105',
    source_port: 53112,
    destination_ip: '1.1.1.1',
    destination_port: 53,
    protocol: 'UDP',
    connection_state: 'ESTABLISHED',
    domain: 'one.one.one.one'
  });
  assert(!benignDns.is_suspicious, 'Standard DNS query to 1.1.1.1 is classified as benign');

  // Private RFC1918 check
  assert(isPrivateOrLocalIp('127.0.0.1'), '127.0.0.1 recognized as private/local');
  assert(isPrivateOrLocalIp('192.168.1.1'), '192.168.1.1 recognized as private RFC1918');
  assert(isPrivateOrLocalIp('10.0.0.5'), '10.0.0.5 recognized as private RFC1918');
  assert(!isPrivateOrLocalIp('198.51.100.45'), 'Public IP correctly identified as non-private');

  // Test Suite 4: Contextual Network Detection Categories
  console.log('\n\x1b[36m[Test Suite 4: Detection Categories Verification]\x1b[0m');

  // 1. Known Malicious IP
  const malIpConn = networkCollector.ingestConnection({
    pid: 2940,
    process_name: 'powershell.exe',
    source_ip: '192.168.1.105',
    source_port: 50110,
    destination_ip: '198.51.100.45', // Embedded malicious C2
    destination_port: 443,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED'
  });
  assert(malIpConn.is_suspicious, 'Detected known malicious C2 IP');
  assert(malIpConn.detection_tags.includes('KNOWN_MALICIOUS_IP'), 'Tagged as KNOWN_MALICIOUS_IP');
  assert(malIpConn.risk_score >= 90, 'High risk score assigned for malicious C2 IP');

  // 2. Suspicious Destination (Risky TLD & Dynamic DNS)
  const dynDnsConn = networkCollector.ingestConnection({
    pid: 3100,
    process_name: 'powershell.exe',
    source_ip: '192.168.1.105',
    source_port: 50111,
    destination_ip: '185.220.101.5',
    destination_port: 8080,
    protocol: 'TCP',
    domain: 'advesary-c2.duckdns.org',
    connection_state: 'ESTABLISHED'
  });
  assert(dynDnsConn.is_suspicious, 'Detected suspicious dynamic DNS destination');
  assert(dynDnsConn.detection_tags.includes('SUSPICIOUS_DESTINATION'), 'Tagged as SUSPICIOUS_DESTINATION');

  // 3. Unusual Outbound Connection (System binary to public IP)
  const notepadConn = networkCollector.ingestConnection({
    pid: 6104,
    process_name: 'notepad.exe',
    source_ip: '192.168.1.105',
    source_port: 50220,
    destination_ip: '45.142.214.123',
    destination_port: 443,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED'
  });
  assert(notepadConn.is_suspicious, 'Detected unusual outbound connection from notepad.exe');
  assert(notepadConn.detection_tags.includes('UNUSUAL_OUTBOUND_CONNECTION'), 'Tagged as UNUSUAL_OUTBOUND_CONNECTION');

  // 4. Suspicious Process Network Connection (Office application)
  const officeConn = networkCollector.ingestConnection({
    pid: 5920,
    process_name: 'winword.exe',
    source_ip: '192.168.1.105',
    source_port: 50330,
    destination_ip: '91.240.118.172',
    destination_port: 80,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED',
    domain: 'template-download.top'
  });
  assert(officeConn.is_suspicious, 'Detected suspicious process network connection from winword.exe');
  assert(officeConn.detection_tags.includes('SUSPICIOUS_PROCESS_NETWORK'), 'Tagged as SUSPICIOUS_PROCESS_NETWORK');

  // 5. Uncommon Ports (Port 4444 Metasploit)
  const uncommonPortConn = networkCollector.ingestConnection({
    pid: 3812,
    process_name: 'cmd.exe',
    source_ip: '192.168.1.105',
    source_port: 50440,
    destination_ip: '198.51.100.22',
    destination_port: 4444,
    protocol: 'TCP',
    connection_state: 'ESTABLISHED'
  });
  assert(uncommonPortConn.is_suspicious, 'Detected connection on uncommon port 4444');
  assert(uncommonPortConn.detection_tags.includes('UNCOMMON_PORT'), 'Tagged as UNCOMMON_PORT');

  // 6. Repeated Connection Patterns (Beaconing)
  const baseTime = Date.now();
  let beaconResult: any;
  for (let i = 0; i < 4; i++) {
    beaconResult = networkCollector.ingestConnection({
      pid: 7720,
      process_name: 'rundll32.exe',
      source_ip: '192.168.1.105',
      source_port: 50550 + i,
      destination_ip: '203.0.113.88',
      destination_port: 8443,
      protocol: 'TCP',
      connection_state: 'ESTABLISHED',
      timestamp: new Date(baseTime + (i * 10000)).toISOString() // exactly 10s intervals
    });
  }
  assert(beaconResult.is_suspicious, 'Detected repeated low-jitter beaconing pattern');
  assert(beaconResult.detection_tags.includes('BEACONING_PATTERN'), 'Tagged as BEACONING_PATTERN');

  // Test Suite 5: Safe Simulation Scenarios Runner
  console.log('\n\x1b[36m[Test Suite 5: Safe Simulation Scenarios Runner]\x1b[0m');
  const allSims = networkManager.getSimulations();
  assert(allSims.length >= 8, `Available simulation scenarios: ${allSims.length}`);

  for (const sim of allSims) {
    const res = networkManager.runSimulation(sim.id);
    assert(res.success, `Simulation '${sim.name}' completed with expected outcome (${sim.expectedAlert ? 'Alert' : 'Clean'})`);
  }

  // Test Suite 6: Configuration Management & Filters
  console.log('\n\x1b[36m[Test Suite 6: Configuration & Query Filtering]\x1b[0m');
  const initialCfg = networkManager.getConfig();
  assert(initialCfg.enabled === true, 'Network detector is enabled by default');

  networkManager.updateConfig({ uncommonPorts: [...initialCfg.uncommonPorts, 12345] });
  const updatedCfg = networkManager.getConfig();
  assert(updatedCfg.uncommonPorts.includes(12345), 'Successfully updated uncommon ports config');

  // Restore config
  networkManager.updateConfig({ uncommonPorts: initialCfg.uncommonPorts });

  const filtered = networkManager.getNetworkEvents({ is_suspicious: true });
  assert(filtered.events.every(e => e.is_suspicious), 'Filter is_suspicious=true returns only suspicious events');

  console.log(`\n\x1b[1m=== Network Telemetry Test Results: ${passed} passed, ${failed} failed ===\x1b[0m\n`);
  return { passed, failed };
}

if (process.argv[1]?.includes('network-telemetry')) {
  runNetworkTelemetryTests().then(res => {
    if (res.failed > 0) process.exit(1);
  }).catch(err => {
    console.error('Network telemetry test failed:', err);
    process.exit(1);
  });
}
