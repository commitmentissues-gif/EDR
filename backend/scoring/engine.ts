import fs from 'node:fs';
import path from 'node:path';
import { 
  RiskLevel, 
  ScoreFactorKey, 
  RiskScoringConfig, 
  UpdateRiskScoringConfigInput,
  ScoreFactorContribution, 
  RiskScoreCalculation,
  ScoreFactorDefinition 
} from './types.js';
import { TelemetryEvent, DetectionRule, ConditionEvaluationResult } from '../detection/types.js';
import { logger } from '../logger/index.js';

const log = logger.forComponent('RiskScoringEngine');

/**
 * Standard Default Scoring Factors Specification:
 * Suspicious parent-child relationship: +15
 * Suspicious command line: +20
 * Unsigned executable: +10
 * Known malicious hash: +50
 * Suspicious temporary execution: +15
 * Persistence activity: +30
 * Threat intelligence match: +40
 * MITRE technique detection: +15
 */
export const FACTOR_DEFINITIONS: Record<ScoreFactorKey, ScoreFactorDefinition> = {
  suspicious_parent_child: {
    key: 'suspicious_parent_child',
    name: 'Suspicious parent-child relationship',
    defaultPoints: 15,
    description: 'Anomalous or unauthorized process lineage (e.g., Office spawning PowerShell, Browser spawning cmd)'
  },
  suspicious_command_line: {
    key: 'suspicious_command_line',
    name: 'Suspicious command line',
    defaultPoints: 20,
    description: 'Obfuscated, encoded (-enc), download cradle, or LOLBin execution syntax'
  },
  unsigned_executable: {
    key: 'unsigned_executable',
    name: 'Unsigned executable',
    defaultPoints: 10,
    description: 'Binary lacks valid Authenticode digital signature or signature is invalid/untrusted'
  },
  known_malicious_hash: {
    key: 'known_malicious_hash',
    name: 'Known malicious hash',
    defaultPoints: 50,
    description: 'Cryptographic hash matches verified malware sample or Threat Intelligence IoC'
  },
  suspicious_temporary_execution: {
    key: 'suspicious_temporary_execution',
    name: 'Suspicious temporary execution',
    defaultPoints: 15,
    description: 'Executable launching from temporary or world-writable staging directory (Temp, Public)'
  },
  persistence_activity: {
    key: 'persistence_activity',
    name: 'Persistence activity',
    defaultPoints: 30,
    description: 'Autostart modification (Registry Run keys, startup folders, or scheduled tasks)'
  },
  threat_intel_match: {
    key: 'threat_intel_match',
    name: 'Threat intelligence match',
    defaultPoints: 40,
    description: 'Network IP, domain, or artifact matches active Threat Intelligence feeds'
  },
  mitre_technique_detection: {
    key: 'mitre_technique_detection',
    name: 'MITRE technique detection',
    defaultPoints: 15,
    description: 'Event maps directly to an active MITRE ATT&CK enterprise adversary technique'
  }
};

export const DEFAULT_RISK_SCORING_CONFIG: RiskScoringConfig = {
  base_score: 0,
  factors: {
    suspicious_parent_child: 15,
    suspicious_command_line: 20,
    unsigned_executable: 10,
    known_malicious_hash: 50,
    suspicious_temporary_execution: 15,
    persistence_activity: 30,
    threat_intel_match: 40,
    mitre_technique_detection: 15
  },
  risk_levels: [
    { min: 0, max: 19, level: 'Informational' },
    { min: 20, max: 39, level: 'Low' },
    { min: 40, max: 59, level: 'Medium' },
    { min: 60, max: 79, level: 'High' },
    { min: 80, max: 100, level: 'Critical' }
  ]
};

let activeScoringConfig: RiskScoringConfig = { ...DEFAULT_RISK_SCORING_CONFIG };
const configFilePath = path.resolve(process.cwd(), 'config', 'risk-scoring.json');

// Attempt to load persisted scoring config
try {
  if (fs.existsSync(configFilePath)) {
    const raw = fs.readFileSync(configFilePath, 'utf-8');
    const parsed = JSON.parse(raw);
    activeScoringConfig = {
      base_score: parsed.base_score ?? DEFAULT_RISK_SCORING_CONFIG.base_score,
      factors: { ...DEFAULT_RISK_SCORING_CONFIG.factors, ...(parsed.factors || {}) },
      risk_levels: parsed.risk_levels || DEFAULT_RISK_SCORING_CONFIG.risk_levels
    };
    log.info('Loaded customized risk scoring configuration');
  }
} catch (err) {
  log.warn('Using default risk scoring configuration:', err);
}

/**
 * Returns current risk scoring configuration
 */
export function getScoringConfig(): RiskScoringConfig {
  return JSON.parse(JSON.stringify(activeScoringConfig));
}

/**
 * Updates risk scoring factor weights and configuration
 */
export function updateScoringConfig(newConfig: UpdateRiskScoringConfigInput): RiskScoringConfig {
  if (newConfig.base_score !== undefined) {
    activeScoringConfig.base_score = Math.max(0, Math.min(100, Math.round(newConfig.base_score)));
  }

  if (newConfig.factors) {
    for (const [key, val] of Object.entries(newConfig.factors)) {
      if (key in activeScoringConfig.factors && typeof val === 'number') {
        activeScoringConfig.factors[key as ScoreFactorKey] = Math.max(0, Math.min(100, Math.round(val)));
      }
    }
  }

  if (newConfig.risk_levels && Array.isArray(newConfig.risk_levels)) {
    activeScoringConfig.risk_levels = newConfig.risk_levels;
  }

  // Persist to disk
  try {
    const configDir = path.dirname(configFilePath);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    fs.writeFileSync(configFilePath, JSON.stringify(activeScoringConfig, null, 2), 'utf-8');
    log.info('Updated and persisted risk scoring configuration');
  } catch (err) {
    log.error('Failed to save risk scoring configuration to disk:', err);
  }

  return getScoringConfig();
}

/**
 * Resets risk scoring configuration to factory defaults
 */
export function resetScoringConfig(): RiskScoringConfig {
  activeScoringConfig = JSON.parse(JSON.stringify(DEFAULT_RISK_SCORING_CONFIG));
  try {
    if (fs.existsSync(configFilePath)) {
      fs.unlinkSync(configFilePath);
    }
    log.info('Reset risk scoring configuration to factory defaults');
  } catch {
    // Non-fatal
  }
  return getScoringConfig();
}

/**
 * Maps a numeric score (0-100) to its designated risk level:
 * 0–19 Informational
 * 20–39 Low
 * 40–59 Medium
 * 60–79 High
 * 80–100 Critical
 */
export function getRiskLevel(score: number): RiskLevel {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));

  // Check configured risk levels first
  for (const threshold of activeScoringConfig.risk_levels) {
    if (clamped >= threshold.min && clamped <= threshold.max) {
      return threshold.level;
    }
  }

  // Fallback to strict standard
  if (clamped >= 80) return 'Critical';
  if (clamped >= 60) return 'High';
  if (clamped >= 40) return 'Medium';
  if (clamped >= 20) return 'Low';
  return 'Informational';
}

export interface CalculateScoreOptions {
  event: TelemetryEvent;
  rule?: DetectionRule | null;
  evalResult?: ConditionEvaluationResult | null;
  baseScore?: number;
  explicitFactors?: ScoreFactorContribution[];
  threatIntelMatched?: boolean;
}

/**
 * Transparent Risk-Scoring Engine:
 * Evaluates individual contributing factors, applies configurable weights,
 * prevents score from exceeding 100, and returns an unhidden, fully auditable calculation.
 * 
 * Every alert shows:
 * - Base score
 * - Individual score factors
 * - Final score
 * - Risk level
 */
export function calculateTransparentRiskScore(options: CalculateScoreOptions): RiskScoreCalculation {
  const { event, rule, evalResult, threatIntelMatched } = options;
  const config = getScoringConfig();

  const base_score = options.baseScore !== undefined 
    ? Math.max(0, Math.min(100, options.baseScore))
    : config.base_score;

  const factors: ScoreFactorContribution[] = [];

  // If explicit factors were provided (e.g. for custom evaluation or unit testing)
  if (options.explicitFactors && options.explicitFactors.length > 0) {
    for (const factor of options.explicitFactors) {
      factors.push(factor);
    }
  } else {
    // 1. Factor: Suspicious parent-child relationship (+15)
    const hasParentCondition = rule?.conditions?.parent_process || rule?.conditions?.process_relationships?.parent_in || rule?.conditions?.process_relationships?.parent_not_in;
    const parentMatchesSuspicious = (
      (evalResult?.evidence?.parent_process && hasParentCondition) ||
      (rule?.id && ['EDR-001-OFFICE-POWERSHELL', 'EDR-002-CMD-UNUSUAL-PARENT', 'EDR-005-UNSIGNED-EXE-SUSPICIOUS-PARENT'].includes(rule.id)) ||
      (event.parent_process_name && ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe'].includes(event.parent_process_name.toLowerCase()))
    );

    if (parentMatchesSuspicious) {
      factors.push({
        factor: 'suspicious_parent_child',
        name: FACTOR_DEFINITIONS.suspicious_parent_child.name,
        points: config.factors.suspicious_parent_child,
        reason: `Parent process '${event.parent_process_name || 'parent'}' exhibits anomalous or unauthorized relationship with '${event.process_name || 'child'}'`,
        evidence: evalResult?.evidence?.parent_process || event.parent_process_name
      });
    }

    // 2. Factor: Suspicious command line (+20)
    const hasCmdCondition = rule?.conditions?.command_line || rule?.conditions?.command_line_match;
    const hasSuspiciousArgs = event.command_line && (
      /-enc|-encodedcommand|-e\s|-urlcache|-split|whoami\s*\/priv|delete\s*shadows|sekurlsa|mimikatz|downloadstring/i.test(event.command_line)
    );
    if ((evalResult?.evidence?.command_line && hasCmdCondition) || hasSuspiciousArgs || rule?.id === 'EDR-004-SUSPICIOUS-LOLBIN-EXEC' || rule?.id === 'EDR-007-POWERSHELL-ENCODED') {
      factors.push({
        factor: 'suspicious_command_line',
        name: FACTOR_DEFINITIONS.suspicious_command_line.name,
        points: config.factors.suspicious_command_line,
        reason: 'Command line contains obfuscated arguments, encoded payloads, or suspicious download parameters',
        evidence: event.command_line || evalResult?.evidence?.command_line
      });
    }

    // 3. Factor: Unsigned executable (+10)
    const sigStatus = (event.signature_status || '').toLowerCase();
    const isUnsigned = sigStatus === 'unsigned' || sigStatus === 'invalid' || sigStatus === 'untrusted' || rule?.conditions?.process_relationships?.is_unsigned === true;
    if (isUnsigned) {
      factors.push({
        factor: 'unsigned_executable',
        name: FACTOR_DEFINITIONS.unsigned_executable.name,
        points: config.factors.unsigned_executable,
        reason: `Executable binary is not digitally verified by a trusted certificate authority (Authenticode: ${event.signature_status || 'Unsigned'})`,
        evidence: event.signature_status || 'Unsigned'
      });
    }

    // 4. Factor: Known malicious hash (+50)
    const isMaliciousHash = rule?.id === 'EDR-006-KNOWN-MALICIOUS-HASH' || rule?.conditions?.hash === 'threat_intel_match' || (evalResult?.evidence?.hash && evalResult.evidence.hash.includes('Threat Intel'));
    if (isMaliciousHash) {
      factors.push({
        factor: 'known_malicious_hash',
        name: FACTOR_DEFINITIONS.known_malicious_hash.name,
        points: config.factors.known_malicious_hash,
        reason: 'Binary cryptographic hash matches verified malware indicator of compromise (IoC)',
        evidence: event.file_hash || evalResult?.evidence?.hash
      });
    }

    // 5. Factor: Suspicious temporary execution (+15)
    const imagePath = (event.image_path || '').toLowerCase();
    const isTempExecution = imagePath.includes('\\appdata\\local\\temp\\') || imagePath.includes('\\windows\\temp\\') || imagePath.includes('\\users\\public\\') || imagePath.includes('/tmp/') || rule?.id === 'EDR-003-EXE-FROM-TEMP-DIR';
    if (isTempExecution) {
      factors.push({
        factor: 'suspicious_temporary_execution',
        name: FACTOR_DEFINITIONS.suspicious_temporary_execution.name,
        points: config.factors.suspicious_temporary_execution,
        reason: `Process binary executed from temporary or world-writable directory '${event.image_path}'`,
        evidence: event.image_path
      });
    }

    // 6. Factor: Persistence activity (+30)
    const isPersistence = (rule?.mitre?.tactic?.toLowerCase() === 'persistence') || (event.registry_key && /run|runonce/i.test(event.registry_key)) || rule?.id === 'EDR-008-REGISTRY-RUN-PERSISTENCE';
    if (isPersistence) {
      factors.push({
        factor: 'persistence_activity',
        name: FACTOR_DEFINITIONS.persistence_activity.name,
        points: config.factors.persistence_activity,
        reason: 'Action establishes persistent autostart survival across system reboot cycles',
        evidence: event.registry_key || rule?.mitre?.technique_id
      });
    }

    // 7. Factor: Threat intelligence match (+40)
    const isThreatIntel = threatIntelMatched || (rule?.id === 'EDR-006-KNOWN-MALICIOUS-HASH') || (event.destination_ip && (evalResult?.reason?.includes('C2') || rule?.mitre?.tactic === 'Command and Control'));
    if (isThreatIntel) {
      factors.push({
        factor: 'threat_intel_match',
        name: FACTOR_DEFINITIONS.threat_intel_match.name,
        points: config.factors.threat_intel_match,
        reason: 'Telemetry correlates directly with threat actor infrastructure or published threat intelligence feed',
        evidence: event.destination_ip || event.file_hash
      });
    }

    // 8. Factor: MITRE technique detection (+15)
    if (rule?.mitre?.technique_id) {
      factors.push({
        factor: 'mitre_technique_detection',
        name: FACTOR_DEFINITIONS.mitre_technique_detection.name,
        points: config.factors.mitre_technique_detection,
        reason: `Corresponds to MITRE ATT&CK technique ${rule.mitre.technique_id} (${rule.mitre.technique_name})`,
        evidence: `${rule.mitre.technique_id} - ${rule.mitre.technique_name}`
      });
    }
  }

  // Calculation Math: Prevent score from exceeding 100!
  const factorsSum = factors.reduce((sum, f) => sum + f.points, 0);
  const raw_score = base_score + factorsSum;
  const final_score = Math.max(0, Math.min(100, raw_score));
  const is_clamped = raw_score > 100;
  const risk_level = getRiskLevel(final_score);

  // Transparent Breakdown String
  const parts = [`Base: ${base_score}`];
  for (const f of factors) {
    parts.push(`${f.name} (+${f.points})`);
  }
  const breakdownFormula = parts.join(' + ');
  const breakdown = is_clamped
    ? `${breakdownFormula} = ${raw_score} (Clamped to 100) -> [${risk_level}]`
    : `${breakdownFormula} = ${final_score} -> [${risk_level}]`;

  // Transparent Narrative Explanation
  const factorDescriptions = factors.map(f => `• ${f.name} (+${f.points}): ${f.reason}`).join('\n');
  const explanation = `[Risk Calculation: ${final_score}/100 - ${risk_level.toUpperCase()}]
Base Score: ${base_score}
Contributing Factors:
${factorDescriptions || '• None (Baseline Execution)'}
Total Computed Score: ${raw_score}${is_clamped ? ' (Clamped at maximum 100)' : ''}
Final Risk Rating: ${risk_level}`;

  return {
    base_score,
    factors,
    raw_score,
    final_score,
    risk_level,
    is_clamped,
    breakdown,
    explanation
  };
}
