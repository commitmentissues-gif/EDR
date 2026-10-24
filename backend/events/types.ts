export type EventCategory = 'process' | 'network' | 'file' | 'registry' | 'windows_event';

export type WindowsEventChannel = 
  | 'Security' 
  | 'System' 
  | 'PowerShell' 
  | 'Windows Defender' 
  | 'Task Scheduler' 
  | 'Service Control Manager'
  | 'Sysmon';

export type EventSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

/**
 * Universal Common Event Schema for LocalEDR
 * Seamlessly models process events, network events, file events, registry events, and Windows Event Logs.
 */
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
  severity: EventSeverity;
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

  // Compatibility aliases for legacy TelemetryEvent
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

export interface NormalizedEventQueryParams {
  category?: EventCategory | 'all';
  channel?: string | 'all';
  windows_event_id?: number;
  severity?: EventSeverity | 'all';
  search?: string;
  user?: string;
  process_name?: string;
  start_time?: string;
  end_time?: string;
  limit?: number;
  offset?: number;
}
