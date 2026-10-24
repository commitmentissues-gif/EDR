export interface AgentStatus {
  agent: {
    name: string;
    version: string;
    mode: string;
    platform: string;
    hostname: string;
    arch: string;
    uptimeSeconds: number;
    serviceInstalled: boolean;
    status: string;
  };
  metrics: {
    rssMemoryMb: number;
    heapUsedMb: number;
    cpuUsagePercent: number;
    databaseSizeBytes: number;
    databaseSizeFormatted: string;
    totalEvents: number;
    totalAlerts: number;
    activeAlerts: number;
    activeRules: number;
    totalRules: number;
    threatIntelIoCs: number;
  };
}

export interface TelemetryEvent {
  id: number;
  event_id: string;
  event_type: 'process_creation' | 'network_connection' | 'file_modification' | 'registry_event' | 'authentication';
  timestamp: string;
  process_name: string | null;
  process_id: number | null;
  parent_process_id: number | null;
  parent_process_name: string | null;
  parent_command_line: string | null;
  command_line: string | null;
  user: string | null;
  image_path: string | null;
  file_hash: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  registry_key: string | null;
  source: string;
  raw_json: string | null;
}

export interface ProcessNode {
  role: 'parent' | 'target' | 'child';
  process_id: number;
  process_name: string;
  command_line?: string;
  user?: string;
  image_path?: string;
  file_hash?: string;
}

export interface ProcessEvent {
  id: number;
  guid: string;
  pid: number;
  parent_pid: number;
  process_name: string;
  executable_path: string;
  command_line: string;
  username: string;
  hostname?: string;
  integrity_level: string;
  creation_timestamp: string;
  sha256: string;
  signature_status: string;
  publisher: string;
  source: string;
  terminal_session_id?: number;
  status: 'running' | 'terminated';
  is_terminated?: boolean | number;
  termination_timestamp?: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_factors?: string[] | string;
  created_at: string;
}

export interface ProcessTreeNode {
  id: number;
  pid: number;
  parent_pid: number;
  process_name: string;
  executable_path: string;
  command_line: string;
  username: string;
  hostname?: string;
  integrity_level: string;
  creation_timestamp: string;
  sha256: string;
  signature_status: string;
  publisher: string;
  status: 'running' | 'terminated';
  is_terminated?: boolean | number;
  is_synthetic?: boolean;
  source?: string;
  termination_timestamp?: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_factors?: string[];
  depth?: number;
  children: ProcessTreeNode[];
}

export type RiskLevel = 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';

export type ScoreFactorKey = 
  | 'suspicious_parent_child'
  | 'suspicious_command_line'
  | 'unsigned_executable'
  | 'known_malicious_hash'
  | 'suspicious_temporary_execution'
  | 'persistence_activity'
  | 'threat_intel_match'
  | 'mitre_technique_detection';

export interface ScoreFactorContribution {
  factor: string;
  name: string;
  points: number;
  reason: string;
  evidence?: string;
}

export interface RiskScoreCalculation {
  base_score: number;
  factors: ScoreFactorContribution[];
  raw_score: number;
  final_score: number;
  risk_level: RiskLevel;
  is_clamped: boolean;
  breakdown: string;
  explanation: string;
}

export interface RiskScoringConfig {
  base_score: number;
  factors: Record<ScoreFactorKey, number>;
  risk_levels: Array<{
    min: number;
    max: number;
    level: RiskLevel;
  }>;
  factor_definitions?: Record<ScoreFactorKey, {
    key: ScoreFactorKey;
    name: string;
    defaultPoints: number;
    description: string;
  }>;
}

export interface Alert {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  score?: number;
  base_score?: number;
  risk_level?: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  score_factors_json?: string;
  score_calculation_json?: string;
  mitre_tactic: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  mitre_subtechnique_id?: string;
  mitre_subtechnique_name?: string;
  event_id: number;
  timestamp: string;
  title: string;
  why_triggered: string;
  evidence_json?: string;
  recommended_action?: string;
  process_lineage_json: string;
  details_json: string;
  status: 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  resolved_at?: string;
  resolved_by?: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  score?: number;
  mitre_tactic: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  mitre_subtechnique_id?: string;
  enabled: number | boolean;
  conditions_json: string;
  recommended_action?: string;
  why_explanation?: string;
  created_at: string;
}

export interface ThreatIndicator {
  id: number;
  type: 'sha256' | 'md5' | 'ip' | 'domain';
  value: string;
  description: string;
  threat_actor: string;
  severity: string;
  confidence: number;
  added_at: string;
}

export interface SimulationItem {
  id: string;
  name: string;
  technique: string;
  description: string;
  targetRule: string;
}

export interface ResponseAction {
  id: string;
  alert_id?: string;
  action_type: 'KILL_PROCESS' | 'QUARANTINE_FILE' | 'BLOCK_IP' | 'ISOLATE_HOST_SIM';
  target: string;
  target_details?: string;
  status: 'PENDING_CONFIRMATION' | 'EXECUTED' | 'CANCELLED' | 'FAILED';
  requested_at: string;
  confirmed_at?: string;
  confirmed_by?: string;
  result_message?: string;
}

export interface MitreMatrixTactic {
  tactic: string;
  tactic_id?: string;
  description?: string;
  order?: number;
  techniques: {
    id: string;
    name: string;
    alertsCount: number;
    description?: string;
    is_subtechnique?: boolean;
    subtechniques?: Array<{
      id: string;
      name: string;
      alertsCount: number;
    }>;
    rules: {
      id: string;
      name: string;
      severity: string;
      enabled: boolean;
    }[];
  }[];
}

export interface MitreHostCoverage {
  hostname: string;
  totalAlerts: number;
  activeAlerts: number;
  tacticsObserved: string[];
  techniquesObserved: string[];
  lastSeen: string;
  riskLevel: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  maxScore: number;
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

export interface MitreObservedTactic {
  tactic: string;
  tactic_id?: string;
  alertsCount: number;
  techniquesCount: number;
  techniques: string[];
}

export interface MitreObservedTechnique {
  id: string;
  name: string;
  tactic: string;
  subtechnique_id?: string;
  alertsCount: number;
  lastSeen: string;
  highestSeverity: string;
  maxScore: number;
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
  tacticsObserved: MitreObservedTactic[];
  techniquesObserved: MitreObservedTechnique[];
  hostCoverage: MitreHostCoverage[];
  timeline: MitreTimelinePoint[];
}

export interface MitreTechniqueDetail {
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
  subtechniques?: Array<{
    id: string;
    name: string;
    alertsCount?: number;
  }>;
  rules?: Array<{
    id: string;
    name: string;
    severity: string;
    score: number;
    enabled: boolean;
  }>;
  recentAlerts?: Array<{
    id: string;
    title: string;
    severity: string;
    score: number;
    timestamp: string;
  }>;
}

export interface MitreVersionMeta {
  version: string;
  name: string;
  filePath?: string;
  releaseDate?: string;
  matrix: string;
  techniquesCount: number;
  tacticsCount: number;
  status: 'ACTIVE' | 'AVAILABLE' | 'ARCHIVED';
}

export type EventCategory = 'process' | 'network' | 'file' | 'registry' | 'windows_event';

export type WindowsEventChannel = 
  | 'Security' 
  | 'System' 
  | 'PowerShell' 
  | 'Windows Defender' 
  | 'Task Scheduler' 
  | 'Service Control Manager'
  | 'Sysmon';

export interface NormalizedEvent {
  id?: number;
  event_uuid: string;
  event_category: EventCategory;
  event_type: string;
  timestamp: string;
  hostname: string;
  provider?: string;
  channel?: WindowsEventChannel | string;
  windows_event_id?: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  action: string;
  
  // User & Identity Context
  user_name?: string;
  user_domain?: string;
  user_sid?: string;
  logon_id?: string;
  logon_type?: number;
  privilege_list?: string[];

  // Process & Execution Context
  process_id?: number;
  process_name?: string;
  process_path?: string;
  command_line?: string;
  parent_process_id?: number;
  parent_process_name?: string;
  parent_command_line?: string;
  file_hash?: string;
  signature_status?: string;
  integrity_level?: string;

  // Network Context
  source_ip?: string;
  source_port?: number;
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;

  // Target & Resource Context
  target_user?: string;
  target_domain?: string;
  target_resource?: string;
  file_path?: string;
  registry_key?: string;
  service_name?: string;
  service_file_name?: string;
  task_name?: string;
  script_text?: string;

  // Human Explanation & Telemetry Data
  message: string;
  data_json?: string;
  is_alerted?: boolean | number;
  created_at?: string;

  // Backwards compatibility
  event_id?: string;
  user?: string;
  image_path?: string;
  source?: string;
  raw_json?: string;
}

export interface ChannelConfig {
  channel: WindowsEventChannel;
  enabled: boolean;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
  allowed_event_ids: number[];
  excluded_event_ids: number[];
  filter_system_noise: boolean;
  max_batch_size: number;
  min_severity_level: 'All' | 'Warning' | 'Error' | 'Critical';
}

export interface WindowsEventCollectorConfig {
  enabled: boolean;
  polling_interval_ms: number;
  batch_flush_size: number;
  max_dedup_cache_size: number;
  max_retention_days: number;
  noise_filter_enabled: boolean;
  channels: Record<string, ChannelConfig>;
}

export interface CollectorMetrics {
  totalCollected: number;
  totalNormalized: number;
  totalFilteredNoise: number;
  totalIngestedToDb: number;
  activeChannelsCount: number;
  lastCollectionTimestamp?: string;
  eventsPerChannel: Record<string, number>;
  eventsPerCategory: Record<EventCategory, number>;
}

export type MonitoredBinaryName = 
  | 'powershell.exe'
  | 'cmd.exe'
  | 'rundll32.exe'
  | 'regsvr32.exe'
  | 'mshta.exe'
  | 'certutil.exe'
  | 'bitsadmin.exe'
  | 'wmic.exe'
  | 'cscript.exe'
  | 'wscript.exe'
  | 'msiexec.exe'
  | 'schtasks.exe'
  | 'reg.exe';

export type ContextualBehaviorType =
  | 'encoded_powershell'
  | 'suspicious_download'
  | 'hidden_execution'
  | 'unusual_parent'
  | 'office_to_powershell'
  | 'browser_to_powershell'
  | 'powershell_to_lolbin'
  | 'lolbin_to_executable'
  | 'temp_location_execution';

export interface MonitoredBinaryMeta {
  name: MonitoredBinaryName;
  displayName: string;
  category: 'Script Host' | 'Command Interpreter' | 'System Utility' | 'Installer' | 'Task Manager';
  description: string;
  defaultEnabled: boolean;
  mitreTechniques: string[];
  legitimateUse: string;
  commonAbuse: string;
  suspiciousKeywords: string[];
  benignExamples: string[];
  riskWeight: number;
  enabled: boolean;
  totalDetections: number;
}

export interface ContextualBehaviorDefinition {
  id: ContextualBehaviorType;
  name: string;
  description: string;
  primaryMitre: {
    tactic: string;
    technique_id: string;
    technique_name: string;
    subtechnique_id?: string;
    subtechnique_name?: string;
  };
  secondaryMitre?: {
    tactic: string;
    technique_id: string;
    technique_name: string;
  };
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  baseScore: number;
  indicators: string[];
  benignExclusions: string[];
  enabled: boolean;
}

export interface LolbinGlobalConfig {
  contextualDetectionEnabled: boolean;
  suppressBenignAdministrativeCommands: boolean;
  strictLineageVerification: boolean;
  monitoredTempDirectories: string[];
  monitoredOfficeParents: string[];
  monitoredBrowserParents: string[];
  anomalousSystemServices: string[];
  minimumDetectionScore: number;
  lastUpdated: string;
}

export interface LolbinDetectionResult {
  isLolbinEvent: boolean;
  monitoredBinary?: MonitoredBinaryName;
  isSuspicious: boolean;
  isBenignMatch: boolean;
  behaviorsDetected: ContextualBehaviorType[];
  behaviorDetails: Array<{
    type: ContextualBehaviorType;
    name: string;
    description: string;
    evidence: string;
    score: number;
    mitre: {
      tactic: string;
      technique_id: string;
      technique_name: string;
    };
  }>;
  totalScore: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  summary: string;
  recommendation: string;
  processLineage: Array<{
    role: 'parent' | 'target' | 'child';
    name: string;
    pid: number;
    commandLine?: string;
  }>;
}

export interface SafeSimulationScenario {
  id: string;
  name: string;
  category: 'benign_safe' | 'contextual_detection';
  targetBinary: MonitoredBinaryName;
  expectedAlert: boolean;
  behavior?: ContextualBehaviorType;
  mitre?: string;
  description: string;
  commandLine: string;
  parentProcess: string;
  imagePath: string;
  explanation: string;
}



