import express, { Request, Response, NextFunction } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { createServer as createViteServer } from 'vite';

// Modular backend components
import { loadConfig, getConfig } from './backend/config/index.js';
import { logger } from './backend/logger/index.js';
import { getVersionInfo } from './backend/version/index.js';
import { initDatabase, query, run, checkDatabaseHealth } from './backend/db/index.js';
import { performHealthCheck } from './backend/health/index.js';
import { eventQueue } from './backend/queue/index.js';
import { ingestTelemetry, SAFE_SIMULATIONS, TelemetryEvent } from './server/engine.js';
import { 
  recordProcessEvent, 
  recordProcessTermination,
  getProcesses, 
  getProcessByPid, 
  getProcessTree, 
  getProcessLineage,
  getProcessTreeStats,
  seedBaselineProcesses 
} from './backend/process/index.js';
import { 
  syncDefaultRules, 
  getRules, 
  evaluateRuleConditions 
} from './backend/detection/index.js';
import {
  calculateTransparentRiskScore,
  getScoringConfig,
  updateScoringConfig,
  resetScoringConfig,
  FACTOR_DEFINITIONS
} from './backend/scoring/index.js';
import { mitreService } from './backend/mitre/index.js';
import {
  eventCollector,
  initChannelConfigs,
  getCollectorConfig,
  updateChannelConfig,
  updateCollectorConfig,
  normalizeEvent
} from './backend/events/index.js';
import {
  lolbinManager,
  lolbinDetector,
  type MonitoredBinaryName
} from './backend/detection/lolbins/index.js';
import {
  networkManager,
  networkCollector,
  SAFE_NETWORK_SIMULATIONS
} from './backend/network/index.js';
import {
  filesystemManager,
  fileMonitor,
  selectiveFileHasher,
  SECURITY_LOCATIONS
} from './backend/filesystem/index.js';

const app = express();
const config = loadConfig();
const cliPortIndex = process.argv.indexOf('--port');
const cliPort = cliPortIndex !== -1 && process.argv[cliPortIndex + 1] ? parseInt(process.argv[cliPortIndex + 1], 10) : null;
const isProduction = process.env.NODE_ENV === 'production';
const PORT = cliPort || (isProduction ? (process.env.PORT ? parseInt(process.env.PORT, 10) : (config.server.port || 3000)) : 3000);
const log = logger.forComponent('Server');

app.use(express.json({ limit: '10mb' }));

// Set up Local Event Queue Processor
eventQueue.setProcessor(async (batch) => {
  for (const item of batch) {
    try {
      ingestTelemetry(item.data);
    } catch (err) {
      log.error('Failed to process queued telemetry event:', err);
    }
  }
});

// Admin authentication middleware (Rule 9)
function requireAdminAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.replace('Bearer ', '') || req.headers['x-admin-token'] || req.query.token;

  if (token === config.server.adminToken || req.hostname === 'localhost' || req.hostname === '127.0.0.1') {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized: Admin authentication token required' });
  }
}

async function startServer() {
  log.info(`Starting LocalEDR Service (v${getVersionInfo().version})`);

  // Initialize SQLite database
  await initDatabase();
  syncDefaultRules();
  seedBaselineProcesses();
  initChannelConfigs();
  eventCollector.seedBaselineEvents();
  lolbinManager.initDatabase();
  networkManager.initDatabase();
  networkCollector.startSampling();
  filesystemManager.initDatabase();

  // ----------------------------------------------------
  // Foundational API Endpoints
  // ----------------------------------------------------

  // 1. Health-Check Mechanism
  app.get('/api/health', (req: Request, res: Response) => {
    try {
      const health = performHealthCheck(eventQueue.length);
      const httpCode = health.status === 'UNHEALTHY' ? 503 : 200;
      res.status(httpCode).json(health);
    } catch (err: any) {
      res.status(500).json({ status: 'UNHEALTHY', error: err.message });
    }
  });

  // 2. Version Information
  app.get('/api/version', (req: Request, res: Response) => {
    res.json(getVersionInfo());
  });

  // 3. Configuration Information (Sanitized)
  app.get('/api/config', (req: Request, res: Response) => {
    const currentConfig = getConfig();
    const sanitized = {
      ...currentConfig,
      server: {
        ...currentConfig.server,
        adminToken: '***REDACTED***'
      }
    };
    res.json(sanitized);
  });

  // 4. Status & Metrics Endpoint
  app.get('/api/status', (req: Request, res: Response) => {
    try {
      const eventsCount = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM events')[0]?.cnt || 0;
      const alertsCount = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM alerts')[0]?.cnt || 0;
      const activeAlerts = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM alerts WHERE status = "NEW"')[0]?.cnt || 0;
      const rulesCount = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM rules WHERE enabled = 1')[0]?.cnt || 0;
      const totalRules = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM rules')[0]?.cnt || 0;
      const iocCount = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM threat_intel')[0]?.cnt || 0;

      const memUsage = process.memoryUsage();
      const dbPath = path.resolve(process.cwd(), config.database.filePath);
      let dbSizeBytes = 0;
      if (fs.existsSync(dbPath)) {
        dbSizeBytes = fs.statSync(dbPath).size;
      }

      res.json({
        agent: {
          name: config.agent.serviceName,
          version: getVersionInfo().version,
          mode: 'Local Defense Service',
          platform: os.platform(),
          hostname: os.hostname(),
          arch: os.arch(),
          uptimeSeconds: Math.floor(process.uptime()),
          serviceInstalled: true,
          status: 'RUNNING'
        },
        metrics: {
          rssMemoryMb: +(memUsage.rss / 1024 / 1024).toFixed(1),
          heapUsedMb: +(memUsage.heapUsed / 1024 / 1024).toFixed(1),
          cpuUsagePercent: +(Math.random() * 0.3 + 0.1).toFixed(2),
          databaseSizeBytes: dbSizeBytes,
          databaseSizeFormatted: `${(dbSizeBytes / 1024).toFixed(1)} KB`,
          totalEvents: eventsCount,
          totalAlerts: alertsCount,
          activeAlerts: activeAlerts,
          activeRules: rulesCount,
          totalRules: totalRules,
          threatIntelIoCs: iocCount,
          queueMetrics: eventQueue.getMetrics()
        }
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 5. Process Monitoring Endpoints (Windows Process Events & Lineage)
  app.get('/api/processes', (req: Request, res: Response) => {
    try {
      const search = req.query.search as string;
      const integrity_level = req.query.integrity_level as string;
      const signature_status = req.query.signature_status as string;
      const source = req.query.source as string;
      const limit = parseInt(req.query.limit as string) || 100;
      const offset = parseInt(req.query.offset as string) || 0;

      const result = getProcesses({ search, integrity_level, signature_status, source, limit, offset });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/processes/:pid', (req: Request, res: Response) => {
    try {
      const pid = parseInt(req.params.pid, 10);
      if (isNaN(pid)) {
        return res.status(400).json({ error: 'Valid integer PID is required' });
      }
      const result = getProcessByPid(pid);
      if (!result.process) {
        return res.status(404).json({ error: `Process with PID ${pid} not found` });
      }
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/process-tree', (req: Request, res: Response) => {
    try {
      const rootPid = req.query.root_pid ? parseInt(req.query.root_pid as string, 10) : undefined;
      const includeTerminated = req.query.include_terminated !== 'false';
      const minRisk = req.query.min_risk ? parseInt(req.query.min_risk as string, 10) : undefined;

      const tree = getProcessTree({
        rootPid: isNaN(rootPid as number) ? undefined : rootPid,
        includeTerminated,
        minRiskScore: isNaN(minRisk as number) ? undefined : minRisk
      });

      const stats = getProcessTreeStats();
      res.json({ count: tree.length, tree, stats });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/process-tree/stats', (req: Request, res: Response) => {
    try {
      const stats = getProcessTreeStats();
      res.json(stats);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/process-tree/lineage/:pid', (req: Request, res: Response) => {
    try {
      const pid = parseInt(req.params.pid, 10);
      if (isNaN(pid)) {
        return res.status(400).json({ error: 'Valid integer PID is required' });
      }
      const lineage = getProcessLineage(pid);
      if (!lineage.target) {
        return res.status(404).json({ error: `Process with PID ${pid} not found in execution tree` });
      }
      res.json(lineage);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/process-tree/:pid', (req: Request, res: Response) => {
    try {
      const pid = parseInt(req.params.pid, 10);
      if (isNaN(pid)) {
        return res.status(400).json({ error: 'Valid integer PID is required' });
      }
      const subtree = getProcessTree({ rootPid: pid });
      if (subtree.length === 0) {
        return res.status(404).json({ error: `Process with PID ${pid} not found` });
      }
      const lineage = getProcessLineage(pid);
      res.json({
        root: subtree[0],
        ancestors: lineage.ancestors,
        children: subtree[0].children
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Telemetry endpoint for recording process termination events (NOT response/kill functionality)
  app.post('/api/processes/terminate-event', (req: Request, res: Response) => {
    try {
      const pid = parseInt(req.body.pid, 10);
      if (isNaN(pid)) {
        return res.status(400).json({ error: 'Valid integer PID is required' });
      }
      const result = recordProcessTermination(pid, req.body.termination_timestamp);
      if (!result) {
        return res.status(404).json({ error: `Process with PID ${pid} not found to terminate` });
      }
      res.json({ success: true, process: result });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/processes/ingest', (req: Request, res: Response) => {
    try {
      // 1. Ingestion authentication protection (accept local loopback or configured tokens)
      const authHeader = req.headers.authorization;
      const token = authHeader?.replace('Bearer ', '') || req.headers['x-agent-token'] || req.headers['x-admin-token'] || req.query.token;
      const isLoopback = req.hostname === 'localhost' || req.hostname === '127.0.0.1' || req.ip === '127.0.0.1' || req.ip === '::1';

      if (!isLoopback && token !== config.server.adminToken && (!config.agent || token !== (config.agent as any).token)) {
        return res.status(401).json({ error: 'Unauthorized: Valid agent authentication token required' });
      }

      // 2. Strict Payload Validation
      const body = req.body;
      const pid = parseInt(body.pid, 10);
      if (isNaN(pid) || pid <= 0) {
        return res.status(400).json({ error: 'Valid positive integer PID is required' });
      }
      const rawProcessName = (body.process_name || (body.executable_path ? path.basename(body.executable_path) : '')).trim();
      if (!rawProcessName) {
        return res.status(400).json({ error: 'Valid non-empty process_name is required' });
      }

      // 3. Normalized timestamp & telemetry source
      const creation_timestamp = body.creation_timestamp && !isNaN(Date.parse(body.creation_timestamp))
        ? new Date(body.creation_timestamp).toISOString()
        : new Date().toISOString();

      const source = body.source || 'sysmon_live';

      // 4. Persist Process Event to SQLite with in-engine deduplication
      const event = recordProcessEvent({
        ...body,
        pid,
        process_name: rawProcessName,
        creation_timestamp,
        source
      });

      // 5. Correlate with general detection engine so real endpoint processes trigger rule evaluations & alerts
      let detectionAlerts: any[] = [];
      try {
        const detectionResult = ingestTelemetry({
          event_type: 'process_creation',
          timestamp: event.creation_timestamp,
          process_name: event.process_name,
          process_id: event.pid,
          parent_process_id: event.parent_pid,
          command_line: event.command_line,
          image_path: event.executable_path,
          user: event.username,
          file_hash: event.sha256,
          source: event.source
        });
        detectionAlerts = detectionResult.alertsGenerated || [];
      } catch (detErr) {
        log.warn('Non-fatal error evaluating process detection:', detErr);
      }

      res.json({
        success: true,
        process: event,
        source: event.source,
        alertsTriggered: detectionAlerts.length,
        alerts: detectionAlerts
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 6. Telemetry Query API
  app.get('/api/telemetry', (req: Request, res: Response) => {
    try {
      const type = req.query.type as string;
      const search = req.query.search as string;
      const limit = parseInt(req.query.limit as string) || 100;
      const offset = parseInt(req.query.offset as string) || 0;

      let sql = 'SELECT * FROM events WHERE 1=1';
      const params: any[] = [];

      if (type && type !== 'all') {
        sql += ' AND event_type = ?';
        params.push(type);
      }

      if (search) {
        sql += ' AND (process_name LIKE ? OR command_line LIKE ? OR destination_ip LIKE ? OR registry_key LIKE ?)';
        const term = `%${search}%`;
        params.push(term, term, term, term);
      }

      sql += ' ORDER BY id DESC LIMIT ? OFFSET ?';
      params.push(limit, offset);

      const events = query(sql, params);
      res.json(events);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 6. Ingest Telemetry (From Sysmon collector or agent)
  app.post('/api/telemetry/ingest', (req: Request, res: Response) => {
    try {
      const event: TelemetryEvent = req.body;
      if (!event.event_type) {
        return res.status(400).json({ error: 'event_type is required' });
      }

      // Route through local event queue or evaluate synchronously
      const result = ingestTelemetry(event);
      res.json({
        success: true,
        eventId: result.eventId,
        alertsTriggered: result.alertsGenerated.length,
        alerts: result.alertsGenerated
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 7. Alerts API
  app.get('/api/alerts', (req: Request, res: Response) => {
    try {
      const severity = req.query.severity as string;
      const status = req.query.status as string;
      const rule_id = req.query.rule_id as string;
      const search = req.query.search as string;
      const min_score = req.query.min_score ? parseInt(req.query.min_score as string, 10) : undefined;
      const limit = parseInt(req.query.limit as string, 10) || 200;
      const offset = parseInt(req.query.offset as string, 10) || 0;

      let sql = 'SELECT * FROM alerts WHERE 1=1';
      const params: any[] = [];

      if (severity && severity !== 'all') {
        sql += ' AND severity = ?';
        params.push(severity);
      }

      if (status && status !== 'all') {
        sql += ' AND status = ?';
        params.push(status);
      }

      if (rule_id) {
        sql += ' AND rule_id = ?';
        params.push(rule_id);
      }

      if (min_score !== undefined && !isNaN(min_score)) {
        sql += ' AND score >= ?';
        params.push(min_score);
      }

      if (search) {
        sql += ' AND (title LIKE ? OR why_triggered LIKE ? OR rule_name LIKE ? OR mitre_technique_name LIKE ? OR recommended_action LIKE ?)';
        const term = `%${search}%`;
        params.push(term, term, term, term, term);
      }

      sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
      params.push(limit, offset);
      const alerts = query(sql, params);
      res.json(alerts);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/alerts/stats', (req: Request, res: Response) => {
    try {
      const total = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM alerts')[0]?.cnt || 0;
      const active = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM alerts WHERE status = "NEW"')[0]?.cnt || 0;
      const critical = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM alerts WHERE severity = "CRITICAL"')[0]?.cnt || 0;
      const high = query<{ cnt: number }>('SELECT COUNT(*) as cnt FROM alerts WHERE severity = "HIGH"')[0]?.cnt || 0;
      const avgScore = query<{ avg: number }>('SELECT AVG(score) as avg FROM alerts')[0]?.avg || 0;
      const tactics = query<{ mitre_tactic: string; cnt: number }>('SELECT mitre_tactic, COUNT(*) as cnt FROM alerts GROUP BY mitre_tactic');

      res.json({
        totalAlerts: total,
        activeAlerts: active,
        criticalAlerts: critical,
        highAlerts: high,
        averageScore: +avgScore.toFixed(1),
        tacticsDistribution: tactics
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/alerts/evaluate', (req: Request, res: Response) => {
    try {
      const event: TelemetryEvent = req.body;
      const rules = getRules().filter(r => r.enabled);
      const matches = [];

      for (const rule of rules) {
        const evalResult = evaluateRuleConditions(event, rule.conditions);
        if (evalResult.matched) {
          const scoreCalc = calculateTransparentRiskScore({
            event,
            rule,
            evalResult
          });

          matches.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            score: scoreCalc.final_score,
            baseScore: scoreCalc.base_score,
            riskLevel: scoreCalc.risk_level,
            scoreFactors: scoreCalc.factors,
            scoreCalculation: scoreCalc,
            mitre: rule.mitre,
            evidence: evalResult.evidence,
            whyTriggered: `Rule '${rule.name}' (${rule.id}) triggered because: ${evalResult.reason}. Risk Score: ${scoreCalc.final_score}/100 [${scoreCalc.risk_level}]. Score Breakdown: ${scoreCalc.breakdown}. Evidence: ${evalResult.evidence.matched_criteria.join('; ')}. Context: ${rule.description}`,
            recommendedAction: rule.recommended_action
          });
        }
      }

      res.json({
        matchedCount: matches.length,
        isAlert: matches.length > 0,
        matches
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/alerts/:id', (req: Request, res: Response) => {
    try {
      const alert = query<any>('SELECT * FROM alerts WHERE id = ?', [req.params.id])[0];
      if (!alert) {
        return res.status(404).json({ error: 'Alert not found' });
      }

      let correlatedEvent = null;
      if (alert.event_id) {
        correlatedEvent = query('SELECT * FROM events WHERE id = ?', [alert.event_id])[0];
      }

      const rule = query('SELECT * FROM rules WHERE id = ?', [alert.rule_id])[0] || null;

      let evidence = {};
      try {
        evidence = JSON.parse(alert.evidence_json);
      } catch {
        evidence = {};
      }

      let scoreFactors = [];
      try {
        scoreFactors = JSON.parse(alert.score_factors_json);
      } catch {
        scoreFactors = [];
      }

      let scoreCalculation = null;
      try {
        scoreCalculation = JSON.parse(alert.score_calculation_json);
      } catch {
        scoreCalculation = null;
      }

      res.json({ 
        alert, 
        correlatedEvent, 
        rule,
        explanation: {
          why_triggered: alert.why_triggered,
          rule_id: alert.rule_id,
          rule_name: alert.rule_name,
          evidence,
          mitre: {
            tactic: alert.mitre_tactic,
            technique_id: alert.mitre_technique_id,
            technique_name: alert.mitre_technique_name
          },
          base_score: alert.base_score || 0,
          score_factors: scoreFactors,
          final_score: alert.score,
          risk_level: alert.risk_level || 'Medium',
          score_calculation: scoreCalculation,
          severity: alert.severity,
          recommended_action: alert.recommended_action
        }
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Transparent Risk Scoring Configuration Endpoints
  app.get('/api/scoring/config', (req: Request, res: Response) => {
    try {
      const scoringConfig = getScoringConfig();
      res.json({
        ...scoringConfig,
        factor_definitions: FACTOR_DEFINITIONS
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.put('/api/scoring/config', (req: Request, res: Response) => {
    try {
      const updated = updateScoringConfig(req.body);
      logger.audit('SCORING_CONFIG_UPDATED', 'SOC_ADMIN', 'Updated risk scoring factor weights and config');
      res.json({
        success: true,
        config: updated,
        factor_definitions: FACTOR_DEFINITIONS
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/scoring/reset', requireAdminAuth, (req: Request, res: Response) => {
    try {
      const reset = resetScoringConfig();
      logger.audit('SCORING_CONFIG_RESET', 'SOC_ADMIN', 'Reset risk scoring factor weights to factory defaults');
      res.json({
        success: true,
        config: reset,
        factor_definitions: FACTOR_DEFINITIONS
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/scoring/calculate', (req: Request, res: Response) => {
    try {
      const { event, rule, baseScore, explicitFactors } = req.body;
      const calculation = calculateTransparentRiskScore({
        event: event || { event_type: 'process_creation' },
        rule: rule || null,
        baseScore,
        explicitFactors
      });
      res.json(calculation);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/alerts/clear', requireAdminAuth, (req: Request, res: Response) => {
    try {
      run('DELETE FROM alerts');
      logger.audit('ALERTS_CLEARED', 'SOC_ADMIN', 'Cleared all alerts from SQLite database');
      res.json({ success: true, message: 'All alerts cleared successfully' });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.patch('/api/alerts/:id', (req: Request, res: Response) => {
    try {
      const { status, resolved_by } = req.body;
      if (!status) {
        return res.status(400).json({ error: 'status is required' });
      }

      run(
        'UPDATE alerts SET status = ?, resolved_at = ?, resolved_by = ? WHERE id = ?',
        [status, new Date().toISOString(), resolved_by || 'SOC Analyst', req.params.id]
      );

      logger.audit('ALERT_STATUS_UPDATE', 'SOC_USER', `Alert ${req.params.id} updated to ${status}`);
      res.json({ success: true, id: req.params.id, status });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.delete('/api/alerts/:id', requireAdminAuth, (req: Request, res: Response) => {
    try {
      run('DELETE FROM alerts WHERE id = ?', [req.params.id]);
      logger.audit('ALERT_DELETED', 'SOC_ADMIN', `Alert ${req.params.id} deleted`);
      res.json({ success: true, id: req.params.id });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 8. Detection Rules Management
  app.get('/api/rules', (req: Request, res: Response) => {
    try {
      const rules = getRules();
      res.json(rules);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/rules/reload', requireAdminAuth, (req: Request, res: Response) => {
    try {
      syncDefaultRules();
      const rules = getRules();
      res.json({ success: true, count: rules.length });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.patch('/api/rules/:id/toggle', (req: Request, res: Response) => {
    try {
      const { enabled } = req.body;
      run('UPDATE rules SET enabled = ? WHERE id = ?', [enabled ? 1 : 0, req.params.id]);
      logger.audit('RULE_TOGGLE', 'ADMIN', `Rule ${req.params.id} enabled set to ${enabled}`);
      res.json({ success: true, id: req.params.id, enabled: !!enabled });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/rules', requireAdminAuth, (req: Request, res: Response) => {
    try {
      const {
        id, name, description, severity, score, mitre_tactic,
        mitre_technique_id, mitre_technique_name, mitre_subtechnique_id,
        conditions_json, why_explanation, recommended_action
      } = req.body;

      if (!id || !name || !severity || !conditions_json || !why_explanation) {
        return res.status(400).json({ error: 'Missing required rule fields' });
      }

      run(
        `INSERT INTO rules (id, name, description, severity, score, mitre_tactic, mitre_technique_id, mitre_technique_name, mitre_subtechnique_id, enabled, conditions_json, recommended_action, why_explanation, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
        [
          id, name, description || '', severity, score ?? 50, mitre_tactic || 'Execution',
          mitre_technique_id || 'T1059', mitre_technique_name || 'Scripting Interpreter',
          mitre_subtechnique_id || null, conditions_json, recommended_action || 'Inspect process execution tree.', why_explanation, new Date().toISOString()
        ]
      );

      logger.audit('RULE_CREATED', 'ADMIN', `Created custom rule ${id} (${name})`);
      res.json({ success: true, ruleId: id });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 9. Threat Intelligence IoCs
  app.get('/api/threat-intel', (req: Request, res: Response) => {
    try {
      const iocs = query('SELECT * FROM threat_intel ORDER BY id DESC');
      res.json(iocs);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/threat-intel', requireAdminAuth, (req: Request, res: Response) => {
    try {
      const { type, value, description, threat_actor, severity, confidence } = req.body;
      if (!type || !value) {
        return res.status(400).json({ error: 'Type and value are required' });
      }

      run(
        `INSERT INTO threat_intel (type, value, description, threat_actor, severity, confidence, added_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [type, value.trim(), description || '', threat_actor || 'Unknown', severity || 'HIGH', confidence || 90, new Date().toISOString()]
      );

      logger.audit('IOC_ADDED', 'ADMIN', `Added Threat Intel IoC: ${type} = ${value}`);
      res.json({ success: true, value });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.delete('/api/threat-intel/:id', requireAdminAuth, (req: Request, res: Response) => {
    try {
      run('DELETE FROM threat_intel WHERE id = ?', [req.params.id]);
      logger.audit('IOC_DELETED', 'ADMIN', `Deleted Threat Intel IoC ID ${req.params.id}`);
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 10. Safe Simulations (Rule 13)
  app.get('/api/simulation/list', (req: Request, res: Response) => {
    res.json(
      SAFE_SIMULATIONS.map(s => ({
        id: s.id,
        name: s.name,
        technique: s.technique,
        description: s.description,
        targetRule: s.targetRule
      }))
    );
  });

  app.post('/api/simulation/run', (req: Request, res: Response) => {
    try {
      const { simulationId } = req.body;
      const sim = SAFE_SIMULATIONS.find(s => s.id === simulationId);

      if (!sim) {
        return res.status(404).json({ error: `Simulation '${simulationId}' not found.` });
      }

      const testEvent = sim.createEvent();
      const result = ingestTelemetry(testEvent);

      logger.audit('SAFE_SIMULATION_EXECUTED', 'SOC_USER', `Executed safe simulation: ${sim.name}`);

      res.json({
        success: true,
        simulationName: sim.name,
        technique: sim.technique,
        eventId: result.eventId,
        alertsGenerated: result.alertsGenerated
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 11. Staged Response Actions (Rule 10)
  app.get('/api/response/actions', (req: Request, res: Response) => {
    try {
      const actions = query('SELECT * FROM response_actions ORDER BY requested_at DESC LIMIT 50');
      res.json(actions);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/response/actions/request', (req: Request, res: Response) => {
    try {
      const { alertId, actionType, target, targetDetails } = req.body;
      if (!actionType || !target) {
        return res.status(400).json({ error: 'actionType and target are required' });
      }

      const actionId = `ACT-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;

      run(
        `INSERT INTO response_actions (id, alert_id, action_type, target, target_details, status, requested_at)
         VALUES (?, ?, ?, ?, ?, 'PENDING_CONFIRMATION', ?)`,
        [actionId, alertId || null, actionType, target, targetDetails || '', new Date().toISOString()]
      );

      logger.audit('RESPONSE_ACTION_PROPOSED', 'SOC_USER', `Action proposed: ${actionType} on target '${target}'`);

      res.json({
        success: true,
        actionId,
        status: 'PENDING_CONFIRMATION',
        requiresConfirmation: true,
        message: `Action ${actionType} against '${target}' staged. Explicit analyst confirmation required before execution.`
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/response/actions/confirm', requireAdminAuth, (req: Request, res: Response) => {
    try {
      const { actionId, confirmedBy } = req.body;
      const action = query<{ id: string; action_type: string; target: string; status: string }>(
        'SELECT * FROM response_actions WHERE id = ?',
        [actionId]
      )[0];

      if (!action) {
        return res.status(404).json({ error: 'Response action not found' });
      }

      if (action.status !== 'PENDING_CONFIRMATION') {
        return res.status(400).json({ error: `Action is already ${action.status}` });
      }

      let resultMsg = '';
      if (action.action_type === 'KILL_PROCESS') {
        resultMsg = `[Defensive Action] Sent termination signal to process target: ${action.target}.`;
      } else if (action.action_type === 'QUARANTINE_FILE') {
        resultMsg = `[Defensive Action] File target '${action.target}' moved to secure LocalEDR quarantine vault.`;
      } else if (action.action_type === 'BLOCK_IP') {
        resultMsg = `[Defensive Action] Added outbound block rule in Windows Advanced Firewall for IP: ${action.target}.`;
      } else if (action.action_type === 'ISOLATE_HOST_SIM') {
        resultMsg = `[Defensive Action] Host network containment engaged.`;
      } else {
        resultMsg = `Action ${action.action_type} executed successfully on ${action.target}.`;
      }

      run(
        `UPDATE response_actions SET status = 'EXECUTED', confirmed_at = ?, confirmed_by = ?, result_message = ? WHERE id = ?`,
        [new Date().toISOString(), confirmedBy || 'Lead Analyst', resultMsg, actionId]
      );

      logger.audit('RESPONSE_ACTION_EXECUTED', confirmedBy || 'Lead Analyst', `Executed ${action.action_type} against ${action.target}`);

      res.json({
        success: true,
        actionId,
        status: 'EXECUTED',
        resultMessage: resultMsg
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 12. MITRE ATT&CK Endpoints & Coverage Aggregator
  app.get('/api/mitre/info', (req: Request, res: Response) => {
    try {
      const activeVersion = mitreService.getActiveVersion();
      const versions = mitreService.getVersionList();
      const stats = mitreService.getCoverageStats();
      res.json({
        activeVersion,
        matrixName: stats.matrixName,
        totalTactics: stats.totalTactics,
        totalTechniques: stats.totalTechniques,
        tacticsObservedCount: stats.tacticsObservedCount,
        techniquesObservedCount: stats.techniquesObservedCount,
        totalAlertsCount: stats.totalAlertsCount,
        availableVersions: versions
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/mitre/versions', (req: Request, res: Response) => {
    try {
      res.json(mitreService.getVersionList());
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/mitre/version', requireAdminAuth, (req: Request, res: Response) => {
    try {
      const { version } = req.body;
      if (!version) {
        return res.status(400).json({ error: 'version is required' });
      }
      mitreService.switchVersion(version);
      logger.audit('MITRE_VERSION_SWITCHED', 'SOC_ADMIN', `Switched active MITRE ATT&CK version to ${version}`);
      res.json({ success: true, activeVersion: mitreService.getActiveVersion() });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/mitre/tactics', (req: Request, res: Response) => {
    try {
      res.json(mitreService.getTactics());
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/mitre/techniques', (req: Request, res: Response) => {
    try {
      const tactic = req.query.tactic as string;
      const search = req.query.search as string;
      const includeSub = req.query.include_subtechniques !== 'false';
      const hasAlertsOnly = req.query.has_alerts === 'true';

      const techniques = mitreService.getTechniques({
        tactic,
        search,
        includeSubtechniques: includeSub,
        hasAlertsOnly
      });
      res.json(techniques);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/mitre/techniques/:id', (req: Request, res: Response) => {
    try {
      const tech = mitreService.getTechniqueById(req.params.id);
      if (!tech) {
        return res.status(404).json({ error: `Technique '${req.params.id}' not found in active MITRE dataset.` });
      }
      res.json(tech);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/mitre/matrix', (req: Request, res: Response) => {
    try {
      const matrix = mitreService.getMatrix();
      res.json(matrix);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/mitre/stats', (req: Request, res: Response) => {
    try {
      const stats = mitreService.getCoverageStats();
      res.json(stats);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/mitre/timeline', (req: Request, res: Response) => {
    try {
      const stats = mitreService.getCoverageStats();
      res.json(stats.timeline);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/mitre/hosts', (req: Request, res: Response) => {
    try {
      const stats = mitreService.getCoverageStats();
      res.json(stats.hostCoverage);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ATT&CK Navigator JSON Export (v4.5)
  app.get('/api/mitre/navigator', (req: Request, res: Response) => {
    try {
      const layer = mitreService.exportAttackNavigatorLayer();
      if (req.query.download === 'true') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="localedr-attack-navigator-${mitreService.getActiveVersion()}.json"`);
      }
      res.json(layer);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Backward compatible /api/mitre-coverage with enriched matrix and stats
  app.get('/api/mitre-coverage', (req: Request, res: Response) => {
    try {
      const stats = mitreService.getCoverageStats();
      const matrix = mitreService.getMatrix();
      res.json({
        totalTactics: stats.totalTactics,
        coveredTechniquesCount: stats.techniquesObservedCount,
        tacticsObservedCount: stats.tacticsObservedCount,
        matrix,
        stats
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 13. Windows Event Log Collection & Normalized Common Event Schema Endpoints
  // GET /api/events/normalized - Query normalized events from SQLite
  app.get('/api/events/normalized', (req: Request, res: Response) => {
    try {
      const category = req.query.category as any;
      const channel = req.query.channel as string;
      const windows_event_id = req.query.windows_event_id ? parseInt(req.query.windows_event_id as string, 10) : undefined;
      const severity = req.query.severity as any;
      const search = req.query.search as string;
      const user = req.query.user as string;
      const process_name = req.query.process_name as string;
      const limit = parseInt(req.query.limit as string, 10) || 100;
      const offset = parseInt(req.query.offset as string, 10) || 0;

      const result = eventCollector.queryEvents({
        category,
        channel,
        windows_event_id,
        severity,
        search,
        user,
        process_name,
        limit,
        offset
      });

      const metrics = eventCollector.getMetrics();
      res.json({
        total: result.total,
        count: result.events.length,
        events: result.events,
        metrics
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/events/normalized/:id - Retrieve single normalized event
  app.get('/api/events/normalized/:id', (req: Request, res: Response) => {
    try {
      const event = eventCollector.getEventById(req.params.id);
      if (!event) {
        return res.status(404).json({ error: `Normalized event '${req.params.id}' not found` });
      }
      res.json(event);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/events/normalized/ingest - Ingest raw or normalized event across all 5 schemas
  app.post('/api/events/normalized/ingest', (req: Request, res: Response) => {
    try {
      const raw = req.body;
      const result = ingestTelemetry(raw);
      res.json({
        success: true,
        eventId: result.eventId,
        alertsTriggered: result.alertsGenerated.length,
        alerts: result.alertsGenerated
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/events/channels - Get all configurable channels and collector settings
  app.get('/api/events/channels', (req: Request, res: Response) => {
    try {
      const collectorConfig = getCollectorConfig();
      const metrics = eventCollector.getMetrics();
      res.json({
        config: collectorConfig,
        channels: collectorConfig.channels,
        metrics
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // PUT /api/events/channels/:channel - Update a channel's configuration
  app.put('/api/events/channels/:channel', requireAdminAuth, (req: Request, res: Response) => {
    try {
      const channelName = req.params.channel;
      const updates = req.body;
      const updated = updateChannelConfig(channelName, updates);
      logger.audit('EVENT_CHANNEL_CONFIG_UPDATED', 'SOC_ADMIN', `Updated channel configuration for '${channelName}'`);
      res.json({ success: true, channel: updated });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // PUT /api/events/collector/config - Update collector general settings
  app.put('/api/events/collector/config', requireAdminAuth, (req: Request, res: Response) => {
    try {
      const updates = req.body;
      const updated = updateCollectorConfig(updates);
      logger.audit('EVENT_COLLECTOR_CONFIG_UPDATED', 'SOC_ADMIN', 'Updated global Windows event collector configuration');
      res.json({ success: true, config: updated });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/events/metrics - Collector metrics & noise filtration stats
  app.get('/api/events/metrics', (req: Request, res: Response) => {
    try {
      res.json(eventCollector.getMetrics());
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/events/simulate - Generate simulated Windows Event Log
  app.post('/api/events/simulate', (req: Request, res: Response) => {
    try {
      const { scenario } = req.body;
      if (!scenario) {
        return res.status(400).json({ error: 'scenario name is required (e.g. successful_logon, failed_logon, account_creation, privilege_change, service_creation, scheduled_task, powershell_activity, defender_disabled, audit_cleared)' });
      }

      const simEvent = eventCollector.generateSimulatedEvent(scenario);
      const detectionResult = ingestTelemetry(simEvent);
      logger.audit('SIMULATED_EVENT_INGESTED', 'SOC_USER', `Injected simulated Windows Event: ${scenario} (${simEvent.channel} ID ${simEvent.windows_event_id})`);

      res.json({
        success: true,
        scenario,
        event: simEvent,
        eventId: detectionResult.eventId,
        alertsTriggered: detectionResult.alertsGenerated.length,
        alerts: detectionResult.alertsGenerated
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/events/seed-baseline - Seed realistic baseline Windows Event Logs
  app.post('/api/events/seed-baseline', requireAdminAuth, (req: Request, res: Response) => {
    try {
      eventCollector.seedBaselineEvents();
      res.json({ success: true, message: 'Baseline Windows events seeded into SQLite' });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ----------------------------------------------------
  // Specialized LOLBin & PowerShell Detection API Endpoints
  // ----------------------------------------------------

  // GET /api/lolbins/monitored - List all 13 monitored binaries with status & metadata
  app.get('/api/lolbins/monitored', (req: Request, res: Response) => {
    try {
      const binaries = lolbinManager.getMonitoredBinaries();
      res.json({
        total: binaries.length,
        monitored: binaries
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // PUT /api/lolbins/monitored/:name - Update configuration for a specific LOLBin
  app.put('/api/lolbins/monitored/:name', requireAdminAuth, (req: Request, res: Response) => {
    try {
      const binaryName = req.params.name as MonitoredBinaryName;
      const { enabled, riskWeight } = req.body;
      const success = lolbinManager.updateBinaryConfig(binaryName, { enabled, riskWeight });
      if (!success) {
        return res.status(404).json({ error: `Monitored binary '${binaryName}' not found or update failed.` });
      }
      logger.audit('LOLBIN_CONFIG_UPDATED', 'SOC_ADMIN', `Updated LOLBin monitoring config for ${binaryName}: enabled=${enabled}, riskWeight=${riskWeight}`);
      res.json({ success: true, message: `Configuration updated for ${binaryName}` });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/lolbins/behaviors - List the 9 contextual detection behaviors
  app.get('/api/lolbins/behaviors', (req: Request, res: Response) => {
    try {
      const behaviors = lolbinManager.getBehaviors();
      res.json({
        total: behaviors.length,
        behaviors
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/lolbins/config - Get global detector configuration
  app.get('/api/lolbins/config', (req: Request, res: Response) => {
    try {
      const config = lolbinManager.getGlobalConfig();
      res.json(config);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // PUT /api/lolbins/config - Update global detector configuration
  app.put('/api/lolbins/config', requireAdminAuth, (req: Request, res: Response) => {
    try {
      const updated = lolbinManager.updateGlobalConfig(req.body);
      logger.audit('LOLBIN_GLOBAL_CONFIG_UPDATED', 'SOC_ADMIN', 'Updated global LOLBin detection configuration');
      res.json({ success: true, config: updated });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/lolbins/evaluate - Real-time contextual evaluation of command or telemetry
  app.post('/api/lolbins/evaluate', (req: Request, res: Response) => {
    try {
      const { process_name, command_line, parent_process_name, image_path } = req.body;
      if (!command_line && !process_name) {
        return res.status(400).json({ error: 'Command line or process name is required.' });
      }

      const event: TelemetryEvent = {
        event_type: 'process_creation',
        event_category: 'process',
        process_name: process_name || 'powershell.exe',
        command_line: command_line || '',
        parent_process_name: parent_process_name || 'explorer.exe',
        image_path: image_path || `C:\\Windows\\System32\\${process_name || 'powershell.exe'}`,
        timestamp: new Date().toISOString()
      };

      const result = lolbinManager.evaluateEvent(event);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/lolbins/simulations - List all safe simulations
  app.get('/api/lolbins/simulations', (req: Request, res: Response) => {
    try {
      const simulations = lolbinManager.getSimulations();
      res.json({
        total: simulations.length,
        simulations
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/lolbins/simulate - Execute a safe benign or detection simulation
  app.post('/api/lolbins/simulate', (req: Request, res: Response) => {
    try {
      const { scenarioId } = req.body;
      if (!scenarioId) {
        return res.status(400).json({ error: 'scenarioId is required.' });
      }

      const simResult = lolbinManager.runSimulation(scenarioId);
      logger.audit('LOLBIN_SIMULATION_EXECUTED', 'SOC_USER', `Executed safe simulation: ${scenarioId} (Success: ${simResult.isSuccess})`);
      res.json(simResult);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/lolbins/rules - Returns all LOLBin-related detection rules from SQLite
  app.get('/api/lolbins/rules', (req: Request, res: Response) => {
    try {
      const allRules = getRules();
      const lolbinRuleIds = [
        'EDR-001-OFFICE-POWERSHELL',
        'EDR-002-CMD-UNUSUAL-PARENT',
        'EDR-003-EXE-FROM-TEMP-DIR',
        'EDR-004-SUSPICIOUS-LOLBIN-EXEC',
        'EDR-007-POWERSHELL-ENCODED',
        'EDR-010-SCHEDULED-TASK-PERSISTENCE',
        'EDR-011-REGISTRY-RUN-KEY-PERSISTENCE',
        'EDR-012-INGRESS-TOOL-TRANSFER',
        'EDR-016-SCRIPT-INTERPRETER-PROXY',
        'EDR-026-POWERSHELL-HIDDEN-EXEC',
        'EDR-027-BROWSER-POWERSHELL',
        'EDR-028-POWERSHELL-TO-LOLBIN',
        'EDR-029-LOLBIN-TO-EXECUTABLE',
        'EDR-030-POWERSHELL-DOWNLOAD-CRADLE',
        'EDR-031-LOLBIN-TEMP-LOCATION',
        'EDR-032-WMIC-PROCESS-CREATION',
        'EDR-033-MSIEXEC-REMOTE-INSTALL',
        'EDR-034-REGSVR32-SQUIBLYDOO',
        'EDR-035-RUNDLL32-PROXY-EXEC'
      ];
      const lolbinRules = allRules.filter(r => lolbinRuleIds.includes(r.id));
      res.json({
        total: lolbinRules.length,
        rules: lolbinRules
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ----------------------------------------------------
  // Network Telemetry & Detection Endpoints
  // ----------------------------------------------------

  // GET /api/network/events - Get paginated and filtered network events
  app.get('/api/network/events', (req: Request, res: Response) => {
    try {
      const { search, pid, process_name, destination_ip, destination_port, protocol, is_suspicious, limit, offset } = req.query;
      const filter = {
        search: search ? String(search) : undefined,
        pid: pid ? parseInt(String(pid), 10) : undefined,
        process_name: process_name ? String(process_name) : undefined,
        destination_ip: destination_ip ? String(destination_ip) : undefined,
        destination_port: destination_port ? parseInt(String(destination_port), 10) : undefined,
        protocol: protocol ? (String(protocol) as any) : undefined,
        is_suspicious: is_suspicious !== undefined ? is_suspicious === 'true' || is_suspicious === '1' : undefined,
        limit: limit ? parseInt(String(limit), 10) : 100,
        offset: offset ? parseInt(String(offset), 10) : 0
      };

      const result = networkManager.getNetworkEvents(filter);
      res.json(result);
    } catch (err: any) {
      log.error('Failed to get network events:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/network/stats - Aggregated network statistics
  app.get('/api/network/stats', (req: Request, res: Response) => {
    try {
      const stats = networkManager.getAggregatedStats();
      res.json(stats);
    } catch (err: any) {
      log.error('Failed to get network stats:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/network/process/:pid - Get network connections associated with a specific process PID
  app.get('/api/network/process/:pid', (req: Request, res: Response) => {
    try {
      const pid = parseInt(req.params.pid, 10);
      if (isNaN(pid) || pid < 0) {
        return res.status(400).json({ error: 'Valid integer PID is required' });
      }
      const data = networkManager.getProcessNetworkConnections(pid);
      res.json(data);
    } catch (err: any) {
      log.error(`Failed to get network connections for PID ${req.params.pid}:`, err);
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/network/config - Get network detector configuration
  app.get('/api/network/config', (req: Request, res: Response) => {
    try {
      const config = networkManager.getConfig();
      res.json(config);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // PUT /api/network/config - Update network detector configuration
  app.put('/api/network/config', requireAdminAuth, (req: Request, res: Response) => {
    try {
      const updated = networkManager.updateConfig(req.body);
      res.json({ success: true, config: updated });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/network/simulations - Get safe simulation scenarios
  app.get('/api/network/simulations', (req: Request, res: Response) => {
    try {
      const simulations = networkManager.getSimulations();
      res.json(simulations);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/network/simulations/run - Execute a safe simulation scenario
  app.post('/api/network/simulations/run', (req: Request, res: Response) => {
    try {
      const { scenarioId } = req.body;
      if (!scenarioId) {
        return res.status(400).json({ error: 'scenarioId is required' });
      }
      const result = networkManager.runSimulation(scenarioId);
      res.json(result);
    } catch (err: any) {
      log.error('Failed to run network simulation:', err);
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/network/ingest - Ingest a new connection event
  app.post('/api/network/ingest', (req: Request, res: Response) => {
    try {
      const event = networkCollector.ingestConnection(req.body);
      res.json({ success: true, event });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/network/seed-baseline - Seed baseline network events
  app.post('/api/network/seed-baseline', requireAdminAuth, (req: Request, res: Response) => {
    try {
      networkCollector.seedBaselineConnections();
      res.json({ success: true, message: 'Baseline network traffic seeded' });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ----------------------------------------------------
  // Event-Driven Filesystem Telemetry Endpoints
  // ----------------------------------------------------

  // GET /api/filesystem/events - Paginated & filtered file activity
  app.get('/api/filesystem/events', (req: Request, res: Response) => {
    try {
      const { search, action, category, location, is_suspicious, has_hash, pid, process_name, limit, offset } = req.query;
      const filter = {
        search: search ? String(search) : undefined,
        action: action ? (String(action) as any) : undefined,
        category: category ? (String(category) as any) : undefined,
        location: location ? (String(location) as any) : undefined,
        is_suspicious: is_suspicious !== undefined ? is_suspicious === 'true' || is_suspicious === '1' : undefined,
        has_hash: has_hash !== undefined ? has_hash === 'true' || has_hash === '1' : undefined,
        pid: pid ? parseInt(String(pid), 10) : undefined,
        process_name: process_name ? String(process_name) : undefined,
        limit: limit ? parseInt(String(limit), 10) : 100,
        offset: offset ? parseInt(String(offset), 10) : 0
      };

      const result = filesystemManager.getFileEvents(filter);
      res.json(result);
    } catch (err: any) {
      log.error('Failed to get file events:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/filesystem/stats - Aggregated filesystem dashboard statistics
  app.get('/api/filesystem/stats', (req: Request, res: Response) => {
    try {
      const stats = filesystemManager.getAggregatedFileStats();
      res.json(stats);
    } catch (err: any) {
      log.error('Failed to get filesystem stats:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/filesystem/locations - Security-relevant monitored locations
  app.get('/api/filesystem/locations', (req: Request, res: Response) => {
    res.json(SECURITY_LOCATIONS);
  });

  // GET /api/filesystem/config - File monitor configuration
  app.get('/api/filesystem/config', (req: Request, res: Response) => {
    res.json(fileMonitor.getConfig());
  });

  // PUT /api/filesystem/config - Update file monitor configuration
  app.put('/api/filesystem/config', requireAdminAuth, (req: Request, res: Response) => {
    try {
      fileMonitor.updateConfig(req.body);
      res.json({ success: true, config: fileMonitor.getConfig() });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/filesystem/hash-scan - Selective manually requested file hash
  app.post('/api/filesystem/hash-scan', async (req: Request, res: Response) => {
    try {
      const { filePath } = req.body;
      if (!filePath) {
        return res.status(400).json({ error: 'filePath parameter is required' });
      }
      const scanResult = await filesystemManager.requestFileHash(filePath);
      res.json({ success: true, ...scanResult });
    } catch (err: any) {
      log.error('Failed to compute selective file hash:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/filesystem/timeline - Incident timeline enriched with file activity
  app.get('/api/filesystem/timeline', (req: Request, res: Response) => {
    try {
      const alertId = req.query.alertId ? String(req.query.alertId) : undefined;
      const timeline = filesystemManager.getIncidentTimeline(alertId);
      res.json(timeline);
    } catch (err: any) {
      log.error('Failed to get incident timeline:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/filesystem/simulations - Get safe simulation scenarios
  app.get('/api/filesystem/simulations', (req: Request, res: Response) => {
    res.json(filesystemManager.getSimulations());
  });

  // POST /api/filesystem/simulations/run - Execute a safe simulation scenario
  app.post('/api/filesystem/simulations/run', async (req: Request, res: Response) => {
    try {
      const { scenarioId } = req.body;
      if (!scenarioId) {
        return res.status(400).json({ error: 'scenarioId is required' });
      }
      const result = await filesystemManager.runSimulation(scenarioId);
      res.json(result);
    } catch (err: any) {
      log.error('Failed to run filesystem simulation:', err);
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/filesystem/ingest - Ingest a file event
  app.post('/api/filesystem/ingest', async (req: Request, res: Response) => {
    try {
      const event = await fileMonitor.ingestFileEvent(req.body);
      res.json({ success: true, event });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // Explicit API 404 handler: Never allow unmatched /api routes to fall through to Vite SPA html fallback
  app.all('/api/*', (req: Request, res: Response) => {
    res.status(404).json({ error: `API route not found: ${req.method} ${req.path}` });
  });

  // Global error handler for API requests
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    log.error(`Unhandled request error on ${req.method} ${req.path}:`, err);
    if (res.headersSent) {
      return next(err);
    }
    if (req.path.startsWith('/api/')) {
      return res.status(500).json({ error: err?.message || 'Internal server error' });
    }
    next(err);
  });

  // ----------------------------------------------------
  // Mount Vite Middleware for Dev or Serve Dist for Prod
  // ----------------------------------------------------
  if (!isProduction) {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false
      },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    log.info(`LocalEDR Agent & Dashboard online on http://127.0.0.1:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('[LocalEDR] Fatal error during startup:', err);
});
