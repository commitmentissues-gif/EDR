export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface RuleMitreMapping {
  tactic: string;
  technique_id: string;
  technique_name: string;
  subtechnique_id?: string;
  subtechnique_name?: string;
}

export interface RuleProcessRelationships {
  is_unsigned?: boolean;
  parent_in?: string[];
  parent_not_in?: string[];
  disallowed_parents?: string[];
  integrity_escalation?: boolean;
  spawned_by_service?: boolean;
  parent_is_lolbin?: boolean;
  target_is_executable?: boolean;
  is_temp_location?: boolean;
  is_hidden?: boolean;
  is_encoded?: boolean;
  is_download?: boolean;
}

export interface RuleConditions {
  event_category?: string | string[];
  event_type?: string | string[];
  channel?: string | string[];
  windows_event_id?: number | number[];
  logon_type?: number | number[];
  process_name?: string | string[];
  parent_process?: string | string[];
  command_line?: string | string[];
  command_line_match?: string | string[];
  command_line_not_match?: string | string[];
  allowlist_command_line?: string | string[];
  allowlist_parent?: string | string[];
  executable_path?: string | string[];
  hash?: string | string[] | 'threat_intel_match';
  username?: string | string[];
  target_user?: string | string[];
  service_name?: string | string[];
  task_name?: string | string[];
  script_text?: string | string[];
  destination_ip?: string | string[];
  destination_port?: number | number[];
  registry_key?: string | string[];
  file_path?: string | string[];
  process_relationships?: RuleProcessRelationships;
  [key: string]: any;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean | number;
  severity: SeverityLevel;
  score: number;
  mitre: RuleMitreMapping;
  conditions: RuleConditions;
  recommended_action: string;
  why_explanation?: string;
  created_at?: string;
}

export interface EvaluationEvidence {
  process_name?: string;
  parent_process?: string;
  command_line?: string;
  executable_path?: string;
  hash?: string;
  username?: string;
  target_user?: string;
  channel?: string;
  windows_event_id?: number;
  service_name?: string;
  task_name?: string;
  script_text?: string;
  destination_ip?: string;
  process_relationships?: string;
  matched_criteria: string[];
}

export interface ConditionEvaluationResult {
  matched: boolean;
  reason: string;
  evidence: EvaluationEvidence;
}

export interface TelemetryEvent {
  event_id?: string;
  event_uuid?: string;
  event_category?: 'process' | 'network' | 'file' | 'registry' | 'windows_event' | string;
  event_type: string;
  timestamp?: string;
  hostname?: string;
  provider?: string;
  channel?: string;
  windows_event_id?: number;
  action?: string;
  process_name?: string;
  process_id?: number;
  process_path?: string;
  executable_path?: string;
  parent_process_id?: number;
  parent_process_name?: string;
  parent_command_line?: string;
  command_line?: string;
  user?: string;
  user_name?: string;
  user_domain?: string;
  user_sid?: string;
  logon_id?: string;
  logon_type?: number;
  privilege_list?: string[];
  image_path?: string;
  file_hash?: string;
  signature_status?: string;
  publisher?: string;
  integrity_level?: string;
  source_ip?: string;
  source_port?: number;
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;
  target_user?: string;
  target_domain?: string;
  target_resource?: string;
  file_path?: string;
  registry_key?: string;
  service_name?: string;
  service_file_name?: string;
  task_name?: string;
  script_text?: string;
  message?: string;
  source?: string;
  raw_json?: string;
  data_json?: string;
}

export interface AlertRecord {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: SeverityLevel;
  score: number;
  base_score: number;
  risk_level: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
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
  evidence_json: string;
  recommended_action: string;
  process_lineage_json: string;
  details_json: string;
  status: 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  resolved_at?: string;
  resolved_by?: string;
}
