import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import yaml from 'yaml';
import { query, run, scheduleSave } from '../db/index.js';
import { logger } from '../logger/index.js';
import { recordProcessEvent } from '../process/index.js';
import { 
  DetectionRule, 
  TelemetryEvent, 
  AlertRecord 
} from './types.js';
import { evaluateRuleConditions } from './evaluator.js';
import { calculateTransparentRiskScore, getRiskLevel } from '../scoring/index.js';
import { eventCollector } from '../events/index.js';

const log = logger.forComponent('DetectionEngine');

/**
 * Loads rules from a specific JSON or YAML file
 */
export function loadRulesFromFile(filePath: string): DetectionRule[] {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const ext = path.extname(filePath).toLowerCase();

    let rawRules: any[] = [];
    if (ext === '.yaml' || ext === '.yml') {
      const parsed = yaml.parse(content);
      rawRules = Array.isArray(parsed) ? parsed : (parsed.rules || []);
    } else if (ext === '.json') {
      const parsed = JSON.parse(content);
      rawRules = Array.isArray(parsed) ? parsed : (parsed.rules || []);
    }

    return rawRules.map(r => ({
      id: r.id,
      name: r.name,
      description: r.description || '',
      enabled: r.enabled !== false,
      severity: r.severity || 'HIGH',
      score: r.score ?? 70,
      mitre: {
        tactic: r.mitre?.tactic || 'Execution',
        technique_id: r.mitre?.technique_id || 'T1059',
        technique_name: r.mitre?.technique_name || 'Command and Scripting Interpreter',
        subtechnique_id: r.mitre?.subtechnique_id || undefined,
        subtechnique_name: r.mitre?.subtechnique_name || undefined
      },
      conditions: r.conditions || {},
      recommended_action: r.recommended_action || 'Inspect process execution tree and quarantine binary if unverified.',
      why_explanation: r.why_explanation || r.description || r.name
    }));
  } catch (err) {
    log.error(`Failed to parse rule file ${filePath}:`, err);
    return [];
  }
}

/**
 * Loads and syncs default rules from both YAML and JSON rule files into SQLite
 */
export function syncDefaultRules(rulesDir?: string): void {
  const targetDir = rulesDir || path.resolve(process.cwd(), 'rules');
  if (!fs.existsSync(targetDir)) {
    log.warn(`Rules directory not found at ${targetDir}`);
    return;
  }

  try {
    const ruleFiles = fs.readdirSync(targetDir)
      .filter(f => f.endsWith('.json') || f.endsWith('.yaml') || f.endsWith('.yml'))
      .filter(f => f !== 'schema.json');

    const existingRules = query<{ id: string }>('SELECT id FROM rules');
    const existingIds = new Set(existingRules.map(r => r.id));

    let importedCount = 0;
    let updatedCount = 0;

    for (const file of ruleFiles) {
      const fullPath = path.join(targetDir, file);
      const rules = loadRulesFromFile(fullPath);

      for (const rule of rules) {
        const conditionsJson = typeof rule.conditions === 'string'
          ? rule.conditions
          : JSON.stringify(rule.conditions);

        if (!existingIds.has(rule.id)) {
          run(
            `INSERT INTO rules (
              id, name, description, severity, score,
              mitre_tactic, mitre_technique_id, mitre_technique_name, mitre_subtechnique_id,
              enabled, conditions_json, recommended_action, why_explanation, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              rule.id,
              rule.name,
              rule.description || '',
              rule.severity || 'HIGH',
              rule.score ?? 70,
              rule.mitre?.tactic || 'Execution',
              rule.mitre?.technique_id || 'T1059',
              rule.mitre?.technique_name || 'Command and Scripting Interpreter',
              rule.mitre?.subtechnique_id || null,
              rule.enabled === false ? 0 : 1,
              conditionsJson,
              rule.recommended_action || 'Inspect process execution tree and quarantine binary.',
              rule.why_explanation || rule.description || rule.name,
              new Date().toISOString()
            ]
          );
          existingIds.add(rule.id);
          importedCount++;
          log.info(`Imported detection rule: ${rule.id} (${rule.name}) from ${file}`);
        } else {
          // Sync updated fields (score, recommended_action, description, conditions)
          run(
            `UPDATE rules SET 
              name = ?, description = ?, severity = ?, score = ?,
              mitre_tactic = ?, mitre_technique_id = ?, mitre_technique_name = ?, mitre_subtechnique_id = ?,
              conditions_json = ?, recommended_action = ?, why_explanation = ?
            WHERE id = ?`,
            [
              rule.name,
              rule.description || '',
              rule.severity || 'HIGH',
              rule.score ?? 70,
              rule.mitre?.tactic || 'Execution',
              rule.mitre?.technique_id || 'T1059',
              rule.mitre?.technique_name || 'Command and Scripting Interpreter',
              rule.mitre?.subtechnique_id || null,
              conditionsJson,
              rule.recommended_action,
              rule.why_explanation || rule.description,
              rule.id
            ]
          );
          updatedCount++;
        }
      }
    }

    log.info(`Detection rules sync complete: ${importedCount} imported, ${updatedCount} updated`);
    scheduleSave();
  } catch (err) {
    log.error('Failed to sync rules from catalog files:', err);
  }
}

/**
 * Retrieves all detection rules from SQLite
 */
export function getRules(filter?: { enabled?: boolean }): DetectionRule[] {
  let sql = 'SELECT * FROM rules';
  const params: any[] = [];
  if (filter?.enabled !== undefined) {
    sql += ' WHERE enabled = ?';
    params.push(filter.enabled ? 1 : 0);
  }
  sql += ' ORDER BY id ASC';

  const rows = query<any>(sql, params);
  return rows.map(r => {
    let parsedConditions = {};
    try {
      parsedConditions = JSON.parse(r.conditions_json);
    } catch {
      parsedConditions = {};
    }

    return {
      id: r.id,
      name: r.name,
      description: r.description,
      enabled: r.enabled === 1,
      severity: r.severity,
      score: r.score ?? 50,
      mitre: {
        tactic: r.mitre_tactic,
        technique_id: r.mitre_technique_id,
        technique_name: r.mitre_technique_name,
        subtechnique_id: r.mitre_subtechnique_id || undefined
      },
      conditions: parsedConditions,
      recommended_action: r.recommended_action || 'Inspect process tree and quarantine if unverified.',
      why_explanation: r.why_explanation,
      created_at: r.created_at
    };
  });
}

/**
 * Retrieves a single detection rule by ID
 */
export function getRuleById(id: string): DetectionRule | null {
  const rows = query<any>('SELECT * FROM rules WHERE id = ?', [id]);
  if (rows.length === 0) return null;
  const r = rows[0];
  let parsedConditions = {};
  try {
    parsedConditions = JSON.parse(r.conditions_json);
  } catch {
    parsedConditions = {};
  }
  return {
    id: r.id,
    name: r.name,
    description: r.description,
    enabled: r.enabled === 1,
    severity: r.severity,
    score: r.score ?? 50,
    mitre: {
      tactic: r.mitre_tactic,
      technique_id: r.mitre_technique_id,
      technique_name: r.mitre_technique_name,
      subtechnique_id: r.mitre_subtechnique_id || undefined
    },
    conditions: parsedConditions,
    recommended_action: r.recommended_action,
    why_explanation: r.why_explanation,
    created_at: r.created_at
  };
}

/**
 * Core Detection Evaluation Pipeline:
 * Evaluates a telemetry event against all enabled rules.
 * Generates an alert ONLY when a rule actually matches!
 * Does not classify every event as malicious.
 * Every alert explains:
 * - WHY it triggered
 * - WHICH rule triggered
 * - WHICH evidence was used
 * - MITRE mapping
 * - Risk score
 */
export function evaluateTelemetryEvent(
  event: TelemetryEvent,
  insertedDbEventId: number
): AlertRecord[] {
  const activeRules = getRules({ enabled: true });
  const alertsGenerated: AlertRecord[] = [];

  for (const rule of activeRules) {
    try {
      const evalResult = evaluateRuleConditions(event, rule.conditions);

      // Alert generated ONLY when the rule actually matches!
      if (evalResult.matched) {
        const alertId = `ALT-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
        const timestamp = event.timestamp || new Date().toISOString();

        // 1. Process Lineage Representation
        const lineage = [
          {
            role: 'parent',
            process_id: event.parent_process_id || 0,
            process_name: event.parent_process_name || 'parent.exe',
            command_line: event.parent_command_line || ''
          },
          {
            role: 'target',
            process_id: event.process_id || 0,
            process_name: event.process_name || (event.image_path ? event.image_path.split('\\').pop() : 'process.exe'),
            command_line: event.command_line || '',
            user: event.user || 'WIN-LAPTOP\\User',
            image_path: event.image_path || '',
            file_hash: event.file_hash || ''
          }
        ];

        // 2. Transparent Risk Scoring Calculation (Do not hide calculation!)
        const scoreCalc = calculateTransparentRiskScore({
          event,
          rule,
          evalResult
        });

        const finalScore = scoreCalc.final_score; // Clamped at 100
        const riskLevel = scoreCalc.risk_level;
        const baseScore = scoreCalc.base_score;
        const scoreFactorsJson = JSON.stringify(scoreCalc.factors);
        const scoreCalcJson = JSON.stringify(scoreCalc);

        // 3. Explicit Explanation: WHY it triggered, WHICH rule triggered, WHICH evidence was used, MITRE mapping, Risk score
        const whyTriggered = `Rule '${rule.name}' (${rule.id}) triggered because: ${evalResult.reason}. Risk Score: ${finalScore}/100 [${riskLevel}]. Score Breakdown: ${scoreCalc.breakdown}. Evidence: ${evalResult.evidence.matched_criteria.join('; ')}. Context: ${rule.description}`;

        // 4. Recommended Remediation Action
        const recommendedAction = rule.recommended_action || 'Inspect process execution tree and quarantine binary if unverified.';

        const alert: AlertRecord = {
          id: alertId,
          rule_id: rule.id,
          rule_name: rule.name,
          severity: rule.severity,
          score: finalScore,
          base_score: baseScore,
          risk_level: riskLevel,
          score_factors_json: scoreFactorsJson,
          score_calculation_json: scoreCalcJson,
          mitre_tactic: rule.mitre.tactic,
          mitre_technique_id: rule.mitre.technique_id,
          mitre_technique_name: rule.mitre.technique_name,
          mitre_subtechnique_id: rule.mitre.subtechnique_id,
          mitre_subtechnique_name: rule.mitre.subtechnique_name,
          event_id: insertedDbEventId,
          timestamp,
          title: `${rule.name} on ${event.process_name || event.event_type}`,
          why_triggered: whyTriggered,
          evidence_json: JSON.stringify(evalResult.evidence),
          recommended_action: recommendedAction,
          process_lineage_json: JSON.stringify(lineage),
          details_json: JSON.stringify({
            rule_id: rule.id,
            rule_name: rule.name,
            base_score: baseScore,
            score_factors: scoreCalc.factors,
            final_score: finalScore,
            risk_level: riskLevel,
            score_calculation: scoreCalc,
            mitre_mapping: rule.mitre,
            matched_evidence: evalResult.evidence,
            rule_criteria: rule.conditions,
            event_snapshot: event
          }),
          status: 'NEW'
        };

        // 5. Persist Alert to SQLite
        run(
          `INSERT INTO alerts (
            id, rule_id, rule_name, severity, score, base_score, risk_level,
            score_factors_json, score_calculation_json, mitre_tactic, mitre_technique_id,
            mitre_technique_name, mitre_subtechnique_id, mitre_subtechnique_name,
            event_id, timestamp, title, why_triggered,
            evidence_json, recommended_action, process_lineage_json, details_json, status
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            alert.id,
            alert.rule_id,
            alert.rule_name,
            alert.severity,
            alert.score,
            alert.base_score,
            alert.risk_level,
            alert.score_factors_json,
            alert.score_calculation_json,
            alert.mitre_tactic,
            alert.mitre_technique_id,
            alert.mitre_technique_name,
            alert.mitre_subtechnique_id || null,
            alert.mitre_subtechnique_name || null,
            alert.event_id,
            alert.timestamp,
            alert.title,
            alert.why_triggered,
            alert.evidence_json,
            alert.recommended_action,
            alert.process_lineage_json,
            alert.details_json,
            alert.status
          ]
        );

        alertsGenerated.push(alert);
        log.info(`[ALERT GENERATED] ${alert.id} - ${alert.rule_name} (Rule: ${rule.id}, Score: ${alert.score} [${alert.risk_level}], Severity: ${alert.severity})`);
      }
    } catch (err) {
      log.error(`Error evaluating rule ${rule.id} against telemetry event:`, err);
    }
  }

  // Check C2 network connections against Threat Intel IoCs
  if (event.event_type === 'network_connection' && event.destination_ip) {
    checkThreatIntelNetwork(event, insertedDbEventId, alertsGenerated);
  }

  scheduleSave();
  return alertsGenerated;
}

/**
 * Checks outbound network destination IP against threat intelligence table
 */
function checkThreatIntelNetwork(
  event: TelemetryEvent,
  eventDbId: number,
  alerts: AlertRecord[]
): void {
  try {
    const ipMatches = query<{ type: string; value: string; description: string; threat_actor: string; severity: string }>(
      'SELECT * FROM threat_intel WHERE value = ? AND type = "ip"',
      [event.destination_ip]
    );

    if (ipMatches.length > 0) {
      const match = ipMatches[0];
      const alertId = `ALT-IOC-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
      
      const scoreCalc = calculateTransparentRiskScore({
        event,
        threatIntelMatched: true,
        rule: {
          id: 'EDR-006-KNOWN-MALICIOUS-HASH',
          name: 'Threat Intelligence Malicious C2 IP Match',
          severity: (match.severity as any) || 'CRITICAL',
          score: 100,
          mitre: {
            tactic: 'Command and Control',
            technique_id: 'T1071',
            technique_name: 'Application Layer Protocol'
          },
          conditions: {},
          description: match.description,
          enabled: true,
          recommended_action: 'Immediately isolate host from network and block destination IP at perimeter firewall.'
        }
      });

      const finalScore = scoreCalc.final_score;
      const riskLevel = scoreCalc.risk_level;
      const baseScore = scoreCalc.base_score;
      const scoreFactorsJson = JSON.stringify(scoreCalc.factors);
      const scoreCalcJson = JSON.stringify(scoreCalc);

      const why = `Threat Intel Match: Outbound network connection to destination IP '${event.destination_ip}:${event.destination_port || 'any'}' matches known C2 Threat Infrastructure IoC (${match.threat_actor}): "${match.description}". Risk Score: ${finalScore}/100 [${riskLevel}]. Score Breakdown: ${scoreCalc.breakdown}. MITRE: [Command and Control -> T1071 Application Layer Protocol].`;

      const evidence = {
        destination_ip: event.destination_ip,
        destination_port: event.destination_port,
        threat_actor: match.threat_actor,
        matched_criteria: [`Outbound connection to verified C2 IP ${event.destination_ip}`]
      };

      const alert: AlertRecord = {
        id: alertId,
        rule_id: 'EDR-006-KNOWN-MALICIOUS-HASH',
        rule_name: 'Threat Intelligence Malicious C2 IP Match',
        severity: (match.severity as any) || 'CRITICAL',
        score: finalScore,
        base_score: baseScore,
        risk_level: riskLevel,
        score_factors_json: scoreFactorsJson,
        score_calculation_json: scoreCalcJson,
        mitre_tactic: 'Command and Control',
        mitre_technique_id: 'T1071',
        mitre_technique_name: 'Application Layer Protocol',
        event_id: eventDbId,
        timestamp: event.timestamp || new Date().toISOString(),
        title: `Outbound Connection to Malicious C2 IP: ${event.destination_ip}`,
        why_triggered: why,
        evidence_json: JSON.stringify(evidence),
        recommended_action: 'Immediately isolate host from network and block destination IP at perimeter firewall.',
        process_lineage_json: JSON.stringify([
          {
            role: 'target',
            process_id: event.process_id || 0,
            process_name: event.process_name || 'process.exe',
            command_line: event.command_line || ''
          }
        ]),
        details_json: JSON.stringify({ match, event, score_calculation: scoreCalc }),
        status: 'NEW'
      };

      run(
        `INSERT INTO alerts (
          id, rule_id, rule_name, severity, score, base_score, risk_level,
          score_factors_json, score_calculation_json, mitre_tactic, mitre_technique_id,
          mitre_technique_name, event_id, timestamp, title, why_triggered,
          evidence_json, recommended_action, process_lineage_json, details_json, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          alert.id, alert.rule_id, alert.rule_name, alert.severity, alert.score,
          alert.base_score, alert.risk_level, alert.score_factors_json, alert.score_calculation_json,
          alert.mitre_tactic, alert.mitre_technique_id, alert.mitre_technique_name, alert.event_id,
          alert.timestamp, alert.title, alert.why_triggered, alert.evidence_json,
          alert.recommended_action, alert.process_lineage_json, alert.details_json, alert.status
        ]
      );

      alerts.push(alert);
    }
  } catch (err) {
    log.error('Error checking network threat intel:', err);
  }
}

/**
 * Ingests an event (Windows Event Log or general telemetry), filters noise,
 * deduplicates for low resource usage, normalizes into the Common Event Schema,
 * stores into SQLite, records process lineage, and evaluates detections.
 */
export function ingestAndDetect(event: TelemetryEvent): { eventId: number; alertsGenerated: AlertRecord[] } {
  // 1. Process through Windows Event Collector & Normalizer
  const collectorResult = eventCollector.ingest(event);

  if (collectorResult.isNoise) {
    log.debug(`Event filtered as system noise by channel policy: ${event.channel || 'System'} ID ${event.windows_event_id}`);
    return { eventId: 0, alertsGenerated: [] };
  }

  if (collectorResult.isDuplicate) {
    log.debug(`Event deduplicated by low-resource cache: ${event.channel} ID ${event.windows_event_id}`);
    return { eventId: 0, alertsGenerated: [] };
  }

  const normalized = collectorResult.normalized;
  const insertedDbId = collectorResult.storedId || 1;

  // 2. If process creation, also record into process_events
  if (normalized.event_category === 'process' || normalized.event_type === 'process_creation') {
    try {
      recordProcessEvent({
        pid: normalized.process_id || 0,
        parent_pid: normalized.parent_process_id || 0,
        process_name: normalized.process_name || (normalized.process_path ? normalized.process_path.split('\\').pop() : 'unknown.exe'),
        executable_path: normalized.process_path || `C:\\Windows\\System32\\${normalized.process_name || 'process.exe'}`,
        command_line: normalized.command_line || '',
        username: normalized.user_name || normalized.user || 'WIN-LAPTOP\\User',
        sha256: normalized.file_hash || '',
        creation_timestamp: normalized.timestamp,
        signature_status: normalized.signature_status || 'Unknown',
        publisher: (event as any).publisher || '',
        source: normalized.channel || normalized.source || 'sysmon'
      });
    } catch {
      // Non-fatal
    }
  }

  // 3. Evaluate against detection engine rules across common schema
  const alertsGenerated = evaluateTelemetryEvent(normalized, insertedDbId);

  // 4. If alert was generated, flag normalized event in SQLite
  if (alertsGenerated.length > 0 && insertedDbId > 0) {
    try {
      run('UPDATE normalized_events SET is_alerted = 1 WHERE id = ?', [insertedDbId]);
    } catch {
      // Ignore
    }
  }

  return {
    eventId: insertedDbId,
    alertsGenerated
  };
}

/**
 * Retrieves alerts from SQLite with filtering options
 */
export function getAlerts(filter: {
  severity?: string;
  status?: string;
  rule_id?: string;
  min_score?: number;
  search?: string;
  limit?: number;
  offset?: number;
} = {}): AlertRecord[] {
  let sql = 'SELECT * FROM alerts WHERE 1=1';
  const params: any[] = [];

  if (filter.severity && filter.severity !== 'all') {
    sql += ' AND severity = ?';
    params.push(filter.severity);
  }

  if (filter.status && filter.status !== 'all') {
    sql += ' AND status = ?';
    params.push(filter.status);
  }

  if (filter.rule_id) {
    sql += ' AND rule_id = ?';
    params.push(filter.rule_id);
  }

  if (filter.min_score !== undefined && !isNaN(filter.min_score)) {
    sql += ' AND score >= ?';
    params.push(filter.min_score);
  }

  if (filter.search) {
    sql += ' AND (title LIKE ? OR why_triggered LIKE ? OR rule_name LIKE ? OR mitre_technique_name LIKE ? OR recommended_action LIKE ?)';
    const term = `%${filter.search}%`;
    params.push(term, term, term, term, term);
  }

  sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(filter.limit || 200, filter.offset || 0);

  return query<AlertRecord>(sql, params);
}

/**
 * Retrieves a single alert with correlated event and rule details
 */
export function getAlertById(id: string): { alert: AlertRecord; correlatedEvent: any; rule: any } | null {
  const alerts = query<AlertRecord>('SELECT * FROM alerts WHERE id = ?', [id]);
  if (alerts.length === 0) return null;
  const alert = alerts[0];

  let correlatedEvent = null;
  if (alert.event_id) {
    const events = query('SELECT * FROM events WHERE id = ?', [alert.event_id]);
    correlatedEvent = events[0] || null;
  }

  const rule = query('SELECT * FROM rules WHERE id = ?', [alert.rule_id])[0] || null;

  return { alert, correlatedEvent, rule };
}
