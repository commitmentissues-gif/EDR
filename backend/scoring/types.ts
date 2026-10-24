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

export interface ScoreFactorDefinition {
  key: ScoreFactorKey;
  name: string;
  defaultPoints: number;
  description: string;
}

export interface ScoreFactorContribution {
  factor: ScoreFactorKey;
  name: string;
  points: number;
  reason: string;
  evidence?: string;
}

export interface RiskScoringConfig {
  base_score: number;
  factors: Record<ScoreFactorKey, number>;
  risk_levels: Array<{
    min: number;
    max: number;
    level: RiskLevel;
  }>;
}

export interface UpdateRiskScoringConfigInput {
  base_score?: number;
  factors?: Partial<Record<ScoreFactorKey, number>>;
  risk_levels?: Array<{
    min: number;
    max: number;
    level: RiskLevel;
  }>;
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
