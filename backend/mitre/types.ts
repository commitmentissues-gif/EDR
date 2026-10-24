export interface MitreTactic {
  id: string;
  name: string;
  order: number;
  description: string;
  techniquesCount?: number;
  alertsCount?: number;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  tactic_id?: string;
  is_subtechnique: boolean;
  parent_id?: string | null;
  platforms?: string[];
  description: string;
  detection_guidance?: string;
  data_sources?: string[];
  windows_relevance?: string;
  rulesCount?: number;
  alertsCount?: number;
  subtechniques?: MitreTechnique[];
}

export interface MitreDataset {
  matrix: string;
  version: string;
  name: string;
  releaseDate?: string;
  description?: string;
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
}

export interface MitreVersionMeta {
  version: string;
  name: string;
  filePath: string;
  releaseDate?: string;
  matrix: string;
  techniquesCount: number;
  tacticsCount: number;
  status: 'ACTIVE' | 'AVAILABLE' | 'ARCHIVED';
}

export interface MitreHostCoverage {
  hostname: string;
  totalAlerts: number;
  tacticsObserved: string[];
  techniquesObserved: string[];
  lastSeen: string;
  riskLevel: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  maxScore: number;
  activeAlerts: number;
}

export interface MitreTimelinePoint {
  id: string;
  timestamp: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  subtechnique_id?: string;
  alert_id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  score: number;
  hostname: string;
  process_name?: string;
  command_line?: string;
}

export interface MitreCoverageStats {
  activeVersion: string;
  matrixName: string;
  totalTactics: number;
  totalTechniques: number;
  tacticsObservedCount: number;
  techniquesObservedCount: number;
  totalAlertsCount: number;
  totalCoveredTechniquesByRules: number;
  tacticsObserved: Array<{
    tactic: string;
    tactic_id?: string;
    alertsCount: number;
    techniquesCount: number;
    techniques: string[];
  }>;
  techniquesObserved: Array<{
    id: string;
    name: string;
    tactic: string;
    subtechnique_id?: string;
    alertsCount: number;
    lastSeen: string;
    highestSeverity: string;
    maxScore: number;
  }>;
  hostCoverage: MitreHostCoverage[];
  timeline: MitreTimelinePoint[];
}

export interface MitreNavigatorTechnique {
  techniqueID: string;
  tactic: string;
  score: number;
  color?: string;
  comment?: string;
  enabled: boolean;
  metadata?: Array<{ name: string; value: string }>;
}

export interface MitreNavigatorLayer {
  name: string;
  versions: {
    attack: string;
    navigator: string;
    layer: string;
  };
  domain: string;
  description: string;
  filters: {
    platforms: string[];
  };
  sorting: number;
  layout: {
    layout: string;
    aggregateFunction: string;
    showID: boolean;
    showName: boolean;
    showAggregateScores: boolean;
    countUnscored: boolean;
  };
  hideDisabled: boolean;
  techniques: MitreNavigatorTechnique[];
  gradient: {
    colors: string[];
    minValue: number;
    maxValue: number;
  };
  legendItems: Array<{
    label: string;
    color: string;
  }>;
}
