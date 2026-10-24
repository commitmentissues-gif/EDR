import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { query } from '../db/index.js';
import { logger } from '../logger/index.js';
import {
  MitreDataset,
  MitreTactic,
  MitreTechnique,
  MitreVersionMeta,
  MitreCoverageStats,
  MitreHostCoverage,
  MitreTimelinePoint,
  MitreNavigatorLayer
} from './types.js';

const log = logger.forComponent('MitreService');

class MitreService {
  private activeVersion: string = 'v15.1';
  private dataset: MitreDataset | null = null;
  private tacticsMap = new Map<string, MitreTactic>();
  private techniquesMap = new Map<string, MitreTechnique>();
  private techniquesByTactic = new Map<string, MitreTechnique[]>();
  private subtechniquesByParent = new Map<string, MitreTechnique[]>();
  private versionsList: MitreVersionMeta[] = [];

  constructor() {
    this.init();
  }

  public init(): void {
    try {
      this.loadVersionRegistry();
      this.loadDataset(this.activeVersion);
      log.info(`Initialized MITRE ATT&CK data layer (${this.activeVersion}, ${this.techniquesMap.size} techniques)`);
    } catch (err) {
      log.error('Failed to initialize MITRE service, attempting fallback:', err);
      this.fallbackLoad();
    }
  }

  private loadVersionRegistry(): void {
    const registryPath = path.resolve(process.cwd(), 'mitre', 'index.json');
    if (fs.existsSync(registryPath)) {
      try {
        const raw = fs.readFileSync(registryPath, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed.activeVersion) {
          this.activeVersion = parsed.activeVersion;
        }
        if (Array.isArray(parsed.versions)) {
          this.versionsList = parsed.versions;
        }
      } catch (e) {
        log.warn('Could not read mitre/index.json:', e);
      }
    }

    if (this.versionsList.length === 0) {
      this.versionsList = [
        {
          version: 'v15.1',
          name: 'MITRE ATT&CK Enterprise v15.1',
          filePath: 'mitre/v15.1/enterprise-attack.json',
          matrix: 'Enterprise ATT&CK',
          techniquesCount: 21,
          tacticsCount: 14,
          status: 'ACTIVE'
        },
        {
          version: 'v14.1',
          name: 'MITRE ATT&CK Enterprise v14.1',
          filePath: 'mitre/attack-enterprise.json',
          matrix: 'Enterprise ATT&CK',
          techniquesCount: 9,
          tacticsCount: 14,
          status: 'ARCHIVED'
        }
      ];
    }
  }

  private loadDataset(version: string): void {
    const meta = this.versionsList.find(v => v.version === version) || this.versionsList[0];
    let filePath = path.resolve(process.cwd(), meta.filePath);

    if (!fs.existsSync(filePath)) {
      const altPath = path.resolve(process.cwd(), 'mitre', 'v15.1', 'enterprise-attack.json');
      const legacyPath = path.resolve(process.cwd(), 'mitre', 'attack-enterprise.json');
      if (fs.existsSync(altPath)) {
        filePath = altPath;
      } else if (fs.existsSync(legacyPath)) {
        filePath = legacyPath;
      } else {
        throw new Error(`MITRE dataset file not found at ${filePath}`);
      }
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    const parsed: MitreDataset = JSON.parse(content);
    this.activeVersion = parsed.version || version;
    this.dataset = parsed;

    // Reset maps
    this.tacticsMap.clear();
    this.techniquesMap.clear();
    this.techniquesByTactic.clear();
    this.subtechniquesByParent.clear();

    // Index tactics
    for (const tactic of parsed.tactics) {
      this.tacticsMap.set(tactic.id.toUpperCase(), tactic);
      this.tacticsMap.set(tactic.name.toLowerCase(), tactic);
    }

    // Index techniques
    for (const tech of parsed.techniques) {
      const normalized: MitreTechnique = {
        ...tech,
        is_subtechnique: tech.is_subtechnique ?? tech.id.includes('.'),
        parent_id: tech.parent_id ?? (tech.id.includes('.') ? tech.id.split('.')[0] : null)
      };

      this.techniquesMap.set(normalized.id.toUpperCase(), normalized);

      // Group by tactic
      const tacticKey = normalized.tactic.toLowerCase();
      if (!this.techniquesByTactic.has(tacticKey)) {
        this.techniquesByTactic.set(tacticKey, []);
      }
      this.techniquesByTactic.get(tacticKey)!.push(normalized);

      // Group subtechniques
      if (normalized.is_subtechnique && normalized.parent_id) {
        const parentKey = normalized.parent_id.toUpperCase();
        if (!this.subtechniquesByParent.has(parentKey)) {
          this.subtechniquesByParent.set(parentKey, []);
        }
        this.subtechniquesByParent.get(parentKey)!.push(normalized);
      }
    }
  }

  private fallbackLoad(): void {
    const legacyPath = path.resolve(process.cwd(), 'mitre', 'attack-enterprise.json');
    if (fs.existsSync(legacyPath)) {
      try {
        const raw = fs.readFileSync(legacyPath, 'utf-8');
        const parsed = JSON.parse(raw);
        this.dataset = {
          matrix: parsed.matrix || 'Enterprise ATT&CK',
          version: parsed.version || 'v14.1',
          name: 'MITRE ATT&CK Enterprise (Fallback)',
          tactics: parsed.tactics || [],
          techniques: parsed.techniques || []
        };
        for (const t of this.dataset.tactics) {
          this.tacticsMap.set(t.name.toLowerCase(), t);
        }
        for (const te of this.dataset.techniques) {
          this.techniquesMap.set(te.id.toUpperCase(), te);
        }
      } catch (err) {
        log.error('Fallback load also failed:', err);
      }
    }
  }

  public getActiveVersion(): string {
    return this.activeVersion;
  }

  public getVersionList(): MitreVersionMeta[] {
    return this.versionsList.map(v => ({
      ...v,
      status: v.version === this.activeVersion ? 'ACTIVE' : 'AVAILABLE'
    }));
  }

  public switchVersion(version: string): boolean {
    const target = this.versionsList.find(v => v.version === version);
    if (!target) {
      throw new Error(`Version '${version}' not found in MITRE registry.`);
    }

    this.loadDataset(version);

    // Update active version in registry
    const registryPath = path.resolve(process.cwd(), 'mitre', 'index.json');
    try {
      const data = {
        activeVersion: version,
        versions: this.versionsList.map(v => ({
          ...v,
          status: v.version === version ? 'ACTIVE' : 'AVAILABLE'
        }))
      };
      fs.writeFileSync(registryPath, JSON.stringify(data, null, 2));
    } catch (e) {
      log.warn('Could not save updated version registry:', e);
    }

    return true;
  }

  public getTactics(): MitreTactic[] {
    if (!this.dataset) return [];
    
    // Enrich tactics with real alert counts from DB
    const alertStats = query<{ mitre_tactic: string; cnt: number }>(
      'SELECT mitre_tactic, COUNT(*) as cnt FROM alerts GROUP BY mitre_tactic'
    );
    const alertMap: Record<string, number> = {};
    for (const a of alertStats) {
      alertMap[a.mitre_tactic.toLowerCase()] = a.cnt;
    }

    const rulesStats = query<{ mitre_tactic: string; cnt: number }>(
      'SELECT mitre_tactic, COUNT(*) as cnt FROM rules GROUP BY mitre_tactic'
    );
    const rulesMap: Record<string, number> = {};
    for (const r of rulesStats) {
      rulesMap[r.mitre_tactic.toLowerCase()] = r.cnt;
    }

    return this.dataset.tactics.map(t => {
      const nameKey = t.name.toLowerCase();
      const techList = this.techniquesByTactic.get(nameKey) || [];
      return {
        ...t,
        techniquesCount: techList.length,
        alertsCount: alertMap[nameKey] || 0
      };
    });
  }

  public getTechniques(filters?: {
    tactic?: string;
    search?: string;
    includeSubtechniques?: boolean;
    hasAlertsOnly?: boolean;
  }): MitreTechnique[] {
    if (!this.dataset) return [];

    let list = Array.from(this.techniquesMap.values());

    if (filters?.tactic && filters.tactic !== 'all') {
      const targetTactic = filters.tactic.toLowerCase();
      list = list.filter(t => t.tactic.toLowerCase() === targetTactic);
    }

    if (filters?.search) {
      const term = filters.search.toLowerCase();
      list = list.filter(t =>
        t.id.toLowerCase().includes(term) ||
        t.name.toLowerCase().includes(term) ||
        (t.description && t.description.toLowerCase().includes(term))
      );
    }

    if (filters?.includeSubtechniques === false) {
      list = list.filter(t => !t.is_subtechnique);
    }

    // Attach rule and alert counts
    const alertCounts = query<{ mitre_technique_id: string; cnt: number }>(
      'SELECT mitre_technique_id, COUNT(*) as cnt FROM alerts GROUP BY mitre_technique_id'
    );
    const alertMap: Record<string, number> = {};
    for (const a of alertCounts) {
      alertMap[a.mitre_technique_id.toUpperCase()] = a.cnt;
    }

    const ruleCounts = query<{ mitre_technique_id: string; cnt: number }>(
      'SELECT mitre_technique_id, COUNT(*) as cnt FROM rules GROUP BY mitre_technique_id'
    );
    const ruleMap: Record<string, number> = {};
    for (const r of ruleCounts) {
      ruleMap[r.mitre_technique_id.toUpperCase()] = r.cnt;
    }

    const results = list.map(t => {
      const key = t.id.toUpperCase();
      return {
        ...t,
        alertsCount: alertMap[key] || 0,
        rulesCount: ruleMap[key] || 0,
        subtechniques: this.subtechniquesByParent.get(key) || []
      };
    });

    if (filters?.hasAlertsOnly) {
      return results.filter(t => (t.alertsCount || 0) > 0);
    }

    return results;
  }

  public getTechniqueById(id: string): (MitreTechnique & {
    rules: Array<{ id: string; name: string; severity: string; score: number; enabled: boolean }>;
    recentAlerts: Array<{ id: string; title: string; severity: string; score: number; timestamp: string }>;
  }) | null {
    const key = id.toUpperCase();
    const tech = this.techniquesMap.get(key);
    if (!tech) return null;

    const rules = query<{ id: string; name: string; severity: string; score: number; enabled: number }>(
      'SELECT id, name, severity, score, enabled FROM rules WHERE UPPER(mitre_technique_id) = ? OR UPPER(mitre_subtechnique_id) = ?',
      [key, key]
    ).map(r => ({
      ...r,
      enabled: r.enabled === 1
    }));

    const alerts = query<{ id: string; title: string; severity: string; score: number; timestamp: string }>(
      'SELECT id, title, severity, score, timestamp FROM alerts WHERE UPPER(mitre_technique_id) = ? ORDER BY timestamp DESC LIMIT 20',
      [key]
    );

    const subtechniques = this.subtechniquesByParent.get(key) || [];

    return {
      ...tech,
      rulesCount: rules.length,
      alertsCount: alerts.length,
      subtechniques,
      rules,
      recentAlerts: alerts
    };
  }

  public getMatrix(): any {
    const tactics = this.getTactics();
    const rules = query<{
      id: string;
      name: string;
      severity: string;
      mitre_tactic: string;
      mitre_technique_id: string;
      mitre_technique_name: string;
      mitre_subtechnique_id?: string;
      enabled: number;
    }>('SELECT id, name, severity, mitre_tactic, mitre_technique_id, mitre_technique_name, mitre_subtechnique_id, enabled FROM rules');

    const alertStats = query<{ mitre_technique_id: string; cnt: number }>(
      'SELECT mitre_technique_id, COUNT(*) as cnt FROM alerts GROUP BY mitre_technique_id'
    );
    const alertCountMap: Record<string, number> = {};
    for (const stat of alertStats) {
      alertCountMap[stat.mitre_technique_id.toUpperCase()] = stat.cnt;
    }

    return tactics.map(tactic => {
      const tacticKey = tactic.name.toLowerCase();
      const datasetTechniques = this.techniquesByTactic.get(tacticKey) || [];

      // Collect all techniques belonging to this tactic (from dataset and rules)
      const techniquesObj: Record<string, any> = {};

      // Seed from dataset
      for (const dt of datasetTechniques) {
        if (!dt.is_subtechnique) {
          techniquesObj[dt.id.toUpperCase()] = {
            id: dt.id,
            name: dt.name,
            description: dt.description,
            is_subtechnique: false,
            rules: [],
            alertsCount: alertCountMap[dt.id.toUpperCase()] || 0,
            subtechniques: []
          };
        }
      }

      // Add subtechniques from dataset
      for (const dt of datasetTechniques) {
        if (dt.is_subtechnique && dt.parent_id) {
          const parentKey = dt.parent_id.toUpperCase();
          if (!techniquesObj[parentKey]) {
            // Ensure parent exists even if not explicitly listed
            techniquesObj[parentKey] = {
              id: dt.parent_id,
              name: dt.parent_id,
              is_subtechnique: false,
              rules: [],
              alertsCount: 0,
              subtechniques: []
            };
          }
          techniquesObj[parentKey].subtechniques.push({
            id: dt.id,
            name: dt.name,
            alertsCount: alertCountMap[dt.id.toUpperCase()] || 0,
            rules: []
          });
        }
      }

      // Map rules
      const matchingRules = rules.filter(r => r.mitre_tactic.toLowerCase() === tacticKey);
      for (const r of matchingRules) {
        const techId = r.mitre_technique_id.toUpperCase();
        if (!techniquesObj[techId]) {
          techniquesObj[techId] = {
            id: r.mitre_technique_id,
            name: r.mitre_technique_name,
            is_subtechnique: r.mitre_technique_id.includes('.'),
            rules: [],
            alertsCount: alertCountMap[techId] || 0,
            subtechniques: []
          };
        }
        techniquesObj[techId].rules.push({
          id: r.id,
          name: r.name,
          severity: r.severity,
          enabled: r.enabled === 1
        });
      }

      return {
        tactic: tactic.name,
        tactic_id: tactic.id,
        description: tactic.description,
        order: tactic.order,
        techniques: Object.values(techniquesObj)
      };
    });
  }

  /**
   * Generates comprehensive MITRE coverage and observation stats:
   * - Tactics observed
   * - Techniques observed
   * - Number of alerts
   * - Timeline
   * - Host coverage
   */
  public getCoverageStats(): MitreCoverageStats {
    const alerts = query<any>('SELECT * FROM alerts ORDER BY timestamp DESC');
    const rules = query<any>('SELECT * FROM rules');

    // Aggregate observed tactics
    const tacticMap = new Map<string, { count: number; techniques: Set<string>; tacticId?: string }>();
    const techniqueMap = new Map<string, {
      id: string;
      name: string;
      tactic: string;
      subtechnique_id?: string;
      alertsCount: number;
      lastSeen: string;
      highestSeverity: string;
      maxScore: number;
    }>();

    const hostAlerts = new Map<string, {
      hostname: string;
      totalAlerts: number;
      activeAlerts: number;
      tactics: Set<string>;
      techniques: Set<string>;
      lastSeen: string;
      maxScore: number;
    }>();

    const defaultHost = os.hostname() || 'WIN-ENDPOINT-01';

    for (const alert of alerts) {
      const tactic = alert.mitre_tactic || 'Execution';
      const techId = alert.mitre_technique_id || 'T1059';
      const techName = alert.mitre_technique_name || 'Scripting Interpreter';

      // Parse correlated hostname if available in details_json or default
      let hostname = defaultHost;
      try {
        if (alert.details_json) {
          const parsed = JSON.parse(alert.details_json);
          if (parsed.event_snapshot?.user && parsed.event_snapshot.user.includes('\\')) {
            hostname = parsed.event_snapshot.user.split('\\')[0];
          } else if (parsed.event_snapshot?.hostname) {
            hostname = parsed.event_snapshot.hostname;
          }
        }
      } catch {
        hostname = defaultHost;
      }

      // Tactics aggregation
      if (!tacticMap.has(tactic)) {
        const tacticMeta = this.tacticsMap.get(tactic.toLowerCase());
        tacticMap.set(tactic, {
          count: 0,
          techniques: new Set<string>(),
          tacticId: tacticMeta?.id
        });
      }
      const tStat = tacticMap.get(tactic)!;
      tStat.count++;
      tStat.techniques.add(techId);

      // Techniques aggregation
      if (!techniqueMap.has(techId)) {
        techniqueMap.set(techId, {
          id: techId,
          name: techName,
          tactic,
          subtechnique_id: alert.mitre_subtechnique_id || (techId.includes('.') ? techId : undefined),
          alertsCount: 0,
          lastSeen: alert.timestamp,
          highestSeverity: alert.severity,
          maxScore: alert.score || 0
        });
      }
      const techStat = techniqueMap.get(techId)!;
      techStat.alertsCount++;
      if (alert.score > techStat.maxScore) {
        techStat.maxScore = alert.score;
        techStat.highestSeverity = alert.severity;
      }
      if (new Date(alert.timestamp) > new Date(techStat.lastSeen)) {
        techStat.lastSeen = alert.timestamp;
      }

      // Host aggregation
      if (!hostAlerts.has(hostname)) {
        hostAlerts.set(hostname, {
          hostname,
          totalAlerts: 0,
          activeAlerts: 0,
          tactics: new Set<string>(),
          techniques: new Set<string>(),
          lastSeen: alert.timestamp,
          maxScore: 0
        });
      }
      const hStat = hostAlerts.get(hostname)!;
      hStat.totalAlerts++;
      if (alert.status === 'NEW') hStat.activeAlerts++;
      hStat.tactics.add(tactic);
      hStat.techniques.add(techId);
      if (alert.score > hStat.maxScore) hStat.maxScore = alert.score;
      if (new Date(alert.timestamp) > new Date(hStat.lastSeen)) hStat.lastSeen = alert.timestamp;
    }

    // Convert host map to array with risk level
    const hostCoverage: MitreHostCoverage[] = Array.from(hostAlerts.values()).map(h => {
      let riskLevel: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
      if (h.maxScore >= 80) riskLevel = 'Critical';
      else if (h.maxScore >= 60) riskLevel = 'High';
      else if (h.maxScore >= 40) riskLevel = 'Medium';
      else if (h.maxScore >= 20) riskLevel = 'Low';
      else riskLevel = 'Informational';

      return {
        hostname: h.hostname,
        totalAlerts: h.totalAlerts,
        activeAlerts: h.activeAlerts,
        tacticsObserved: Array.from(h.tactics),
        techniquesObserved: Array.from(h.techniques),
        lastSeen: h.lastSeen,
        riskLevel,
        maxScore: h.maxScore
      };
    });

    // Ensure local host is always represented even if 0 alerts
    if (hostCoverage.length === 0) {
      hostCoverage.push({
        hostname: defaultHost,
        totalAlerts: 0,
        activeAlerts: 0,
        tacticsObserved: [],
        techniquesObserved: [],
        lastSeen: new Date().toISOString(),
        riskLevel: 'Informational',
        maxScore: 0
      });
    }

    // Build timeline points (up to 100 recent alerts)
    const timeline: MitreTimelinePoint[] = alerts.slice(0, 100).map(alert => {
      let procName = '';
      let cmdLine = '';
      let host = defaultHost;
      try {
        if (alert.details_json) {
          const p = JSON.parse(alert.details_json);
          procName = p.event_snapshot?.process_name || '';
          cmdLine = p.event_snapshot?.command_line || '';
          if (p.event_snapshot?.user && p.event_snapshot.user.includes('\\')) {
            host = p.event_snapshot.user.split('\\')[0];
          }
        }
      } catch {}

      return {
        id: alert.id,
        timestamp: alert.timestamp,
        technique_id: alert.mitre_technique_id,
        technique_name: alert.mitre_technique_name,
        tactic: alert.mitre_tactic,
        subtechnique_id: alert.mitre_subtechnique_id,
        alert_id: alert.id,
        rule_id: alert.rule_id,
        rule_name: alert.rule_name,
        severity: alert.severity,
        score: alert.score,
        hostname: host,
        process_name: procName,
        command_line: cmdLine
      };
    });

    const tacticsObservedList = Array.from(tacticMap.entries()).map(([tactic, data]) => ({
      tactic,
      tactic_id: data.tacticId,
      alertsCount: data.count,
      techniquesCount: data.techniques.size,
      techniques: Array.from(data.techniques)
    }));

    const coveredTechRules = new Set(rules.map((r: any) => r.mitre_technique_id.toUpperCase()));

    return {
      activeVersion: this.activeVersion,
      matrixName: this.dataset?.matrix || 'Enterprise ATT&CK',
      totalTactics: this.dataset?.tactics.length || 14,
      totalTechniques: this.techniquesMap.size,
      tacticsObservedCount: tacticMap.size,
      techniquesObservedCount: techniqueMap.size,
      totalAlertsCount: alerts.length,
      totalCoveredTechniquesByRules: coveredTechRules.size,
      tacticsObserved: tacticsObservedList,
      techniquesObserved: Array.from(techniqueMap.values()),
      hostCoverage,
      timeline
    };
  }

  /**
   * Generates a valid MITRE ATT&CK Navigator v4.5 JSON layer export
   */
  public exportAttackNavigatorLayer(): MitreNavigatorLayer {
    const coverage = this.getCoverageStats();
    const rules = query<{ mitre_technique_id: string; mitre_tactic: string; name: string }>(
      'SELECT mitre_technique_id, mitre_tactic, name FROM rules WHERE enabled = 1'
    );

    const rulesByTech: Record<string, string[]> = {};
    for (const r of rules) {
      const key = r.mitre_technique_id.toUpperCase();
      if (!rulesByTech[key]) rulesByTech[key] = [];
      rulesByTech[key].push(r.name);
    }

    const techniques: any[] = [];
    const processedKeys = new Set<string>();

    // 1. Add observed techniques with alert scores and comments
    for (const observed of coverage.techniquesObserved) {
      const techKey = `${observed.id.toUpperCase()}__${observed.tactic.toLowerCase()}`;
      processedKeys.add(techKey);

      let color = '#3b82f6'; // blue default
      if (observed.alertsCount >= 4) {
        color = '#ef4444'; // Red
      } else if (observed.alertsCount >= 2) {
        color = '#f97316'; // Orange
      } else if (observed.alertsCount === 1) {
        color = '#f59e0b'; // Amber
      }

      const ruleNames = rulesByTech[observed.id.toUpperCase()] || [];

      techniques.push({
        techniqueID: observed.id,
        tactic: observed.tactic.toLowerCase().replace(/ /g, '-'),
        score: observed.alertsCount,
        color,
        comment: `LocalEDR: ${observed.alertsCount} alert(s) observed. Max Score: ${observed.maxScore}/100. Severity: ${observed.highestSeverity}. Active Rules: ${ruleNames.join(', ') || 'N/A'}`,
        enabled: true,
        metadata: [
          { name: 'Alerts', value: String(observed.alertsCount) },
          { name: 'Max Risk Score', value: String(observed.maxScore) },
          { name: 'Last Seen', value: observed.lastSeen }
        ]
      });
    }

    // 2. Add rule-covered techniques that have 0 alerts so far
    for (const r of rules) {
      const techKey = `${r.mitre_technique_id.toUpperCase()}__${r.mitre_tactic.toLowerCase()}`;
      if (!processedKeys.has(techKey)) {
        processedKeys.add(techKey);
        techniques.push({
          techniqueID: r.mitre_technique_id,
          tactic: r.mitre_tactic.toLowerCase().replace(/ /g, '-'),
          score: 0,
          color: '#10b981', // Emerald for active detection coverage
          comment: `LocalEDR: Active detection rule installed (${r.name}). 0 alerts observed.`,
          enabled: true,
          metadata: [
            { name: 'Coverage', value: 'Active Rule Deployed' },
            { name: 'Alerts', value: '0' }
          ]
        });
      }
    }

    return {
      name: `LocalEDR ATT&CK Matrix (${this.activeVersion})`,
      versions: {
        attack: '15',
        navigator: '4.9.1',
        layer: '4.5'
      },
      domain: 'enterprise-attack',
      description: `Exported from LocalEDR Autonomous Agent. Observed tactics: ${coverage.tacticsObservedCount}, Observed techniques: ${coverage.techniquesObservedCount}, Total alerts: ${coverage.totalAlertsCount}. Host: ${os.hostname()}.`,
      filters: {
        platforms: ['Windows']
      },
      sorting: 3, // Score descending
      layout: {
        layout: 'side',
        aggregateFunction: 'max',
        showID: true,
        showName: true,
        showAggregateScores: true,
        countUnscored: false
      },
      hideDisabled: false,
      techniques,
      gradient: {
        colors: ['#0f172a', '#10b981', '#f59e0b', '#ef4444'],
        minValue: 0,
        maxValue: 10
      },
      legendItems: [
        { label: 'Active Detection Rule (0 Alerts)', color: '#10b981' },
        { label: 'Observed Alert (Low Frequency)', color: '#f59e0b' },
        { label: 'Observed Alerts (High Frequency)', color: '#ef4444' }
      ]
    };
  }
}

export const mitreService = new MitreService();
