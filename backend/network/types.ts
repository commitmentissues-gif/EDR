export type ConnectionState = 
  | 'ESTABLISHED' 
  | 'SYN_SENT' 
  | 'LISTENING' 
  | 'CLOSE_WAIT' 
  | 'TIME_WAIT' 
  | 'CLOSED';

export type NetworkProtocol = 'TCP' | 'UDP';

export type NetworkDirection = 'outbound' | 'inbound';

export interface NetworkEvent {
  id?: number;
  event_uuid: string;
  timestamp: string;
  pid: number;
  process_name: string;
  process_path?: string;
  parent_pid?: number;
  parent_process_name?: string;
  username?: string;
  signature_status?: string;
  source_ip: string;
  source_port: number;
  destination_ip: string;
  destination_port: number;
  protocol: NetworkProtocol;
  connection_state: ConnectionState;
  domain?: string;
  direction: NetworkDirection;
  bytes_sent: number;
  bytes_received: number;
  is_suspicious: boolean;
  detection_tags: string[]; // e.g. ['MALICIOUS_IP', 'UNCOMMON_PORT', 'BEACONING_PATTERN', 'SUSPICIOUS_PROCESS_NETWORK']
  risk_score: number; // 0-100
  detection_reasons?: string[];
  created_at: string;
}

export interface NetworkFilterOptions {
  search?: string;
  pid?: number;
  process_name?: string;
  destination_ip?: string;
  destination_port?: number;
  protocol?: NetworkProtocol | 'all';
  is_suspicious?: boolean;
  limit?: number;
  offset?: number;
}

export interface NetworkAggregatedStats {
  totalEvents: number;
  activeConnectionsCount: number;
  outboundCount: number;
  inboundCount: number;
  suspiciousCount: number;
  uniqueProcessesCount: number;
  uniqueDestinationsCount: number;
  topDestinations: Array<{ ip: string; domain?: string; count: number; isSuspicious: boolean }>;
  topPorts: Array<{ port: number; count: number; serviceName: string; isCommon: boolean }>;
  topProcesses: Array<{ process_name: string; pid: number; connectionCount: number; isSuspicious: boolean }>;
}

export interface NetworkDetectorConfig {
  enabled: boolean;
  uncommonPorts: number[];
  commonAllowedPorts: number[];
  suspiciousTlds: string[];
  suspiciousDomains: string[];
  unusualOutboundProcesses: string[];
  beaconingDetection: {
    enabled: boolean;
    minConnections: number;
    timeWindowSeconds: number;
    maxJitterPercent: number;
  };
  threatIntelCheckEnabled: boolean;
  alertOnUnusualProcess: boolean;
}

export interface NetworkDetectionAnalysis {
  isSuspicious: boolean;
  riskScore: number;
  tags: string[];
  reasons: string[];
  mitreTechniques: Array<{
    tactic: string;
    technique_id: string;
    technique_name: string;
  }>;
}

export interface SafeNetworkSimulationScenario {
  id: string;
  name: string;
  category: 'benign_traffic' | 'malicious_detection';
  description: string;
  expectedAlert: boolean;
  process_name: string;
  pid: number;
  source_ip: string;
  source_port: number;
  destination_ip: string;
  destination_port: number;
  protocol: NetworkProtocol;
  connection_state: ConnectionState;
  domain?: string;
  direction: NetworkDirection;
  explanation: string;
}
