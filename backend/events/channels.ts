import { ChannelConfig, WindowsEventCollectorConfig, WindowsEventChannel } from './types.js';
import { query, run } from '../db/index.js';
import { logger } from '../logger/index.js';

const log = logger.forComponent('EventChannels');

export const DEFAULT_CHANNELS: Record<string, ChannelConfig> = {
  'Security': {
    channel: 'Security',
    enabled: true,
    priority: 'CRITICAL',
    description: 'Windows Security Event Log: Authentication, privilege rights, account provisioning, audit policies.',
    allowed_event_ids: [
      4624, // Successful logon
      4625, // Failed logon attempt
      4720, // User account created
      4726, // User account deleted
      4728, // Member added to security group
      4732, // Member added to local Administrators group
      4672, // Special privileges assigned to new logon (SeDebugPrivilege)
      4697, // Service installation attempted
      4698, // Scheduled task created
      1102  // Security audit log cleared
    ],
    excluded_event_ids: [],
    filter_system_noise: true,
    max_batch_size: 100,
    min_severity_level: 'All'
  },
  'System': {
    channel: 'System',
    enabled: true,
    priority: 'HIGH',
    description: 'Windows System Log: Kernel drivers, unexpected shutdowns, time modifications, service lifecycle.',
    allowed_event_ids: [
      7045, // Service installed in the system (SCM)
      7036, // Service started or stopped
      7040  // Service start type changed
    ],
    excluded_event_ids: [],
    filter_system_noise: true,
    max_batch_size: 100,
    min_severity_level: 'All'
  },
  'PowerShell': {
    channel: 'PowerShell',
    enabled: true,
    priority: 'CRITICAL',
    description: 'Microsoft-Windows-PowerShell & Operational logs: ScriptBlock logging (4104), Module logging (4103).',
    allowed_event_ids: [
      4104, // Script Block Logging (high-fidelity payload detection)
      4103, // Module Logging
      400   // PowerShell engine state lifecycle
    ],
    excluded_event_ids: [],
    filter_system_noise: true,
    max_batch_size: 150,
    min_severity_level: 'All'
  },
  'Windows Defender': {
    channel: 'Windows Defender',
    enabled: true,
    priority: 'CRITICAL',
    description: 'Microsoft-Windows-Windows Defender/Operational: Malware detections, real-time protection state, exclusions.',
    allowed_event_ids: [
      1116, // Malicious or unwanted software detected
      1117, // Action taken on malicious software
      5001, // Real-time protection was disabled (defense impairment)
      5007  // Antivirus configuration changed (exclusion added)
    ],
    excluded_event_ids: [],
    filter_system_noise: false,
    max_batch_size: 50,
    min_severity_level: 'All'
  },
  'Task Scheduler': {
    channel: 'Task Scheduler',
    enabled: true,
    priority: 'HIGH',
    description: 'Microsoft-Windows-TaskScheduler/Operational: Task registration, updates, and execution actions.',
    allowed_event_ids: [
      106, // Scheduled task registered
      140, // Scheduled task updated
      200  // Scheduled task action started (launch binary)
    ],
    excluded_event_ids: [],
    filter_system_noise: true,
    max_batch_size: 80,
    min_severity_level: 'All'
  },
  'Service Control Manager': {
    channel: 'Service Control Manager',
    enabled: true,
    priority: 'HIGH',
    description: 'Service Control Manager (SCM) event stream: New service binaries, persistence mechanisms.',
    allowed_event_ids: [
      7045, // Service installation
      7036, // State change
      7040  // Start type change
    ],
    excluded_event_ids: [],
    filter_system_noise: true,
    max_batch_size: 80,
    min_severity_level: 'All'
  }
};

export const DEFAULT_COLLECTOR_CONFIG: WindowsEventCollectorConfig = {
  enabled: true,
  polling_interval_ms: 3000,
  batch_flush_size: 100,
  max_dedup_cache_size: 5000,
  max_retention_days: 30,
  noise_filter_enabled: true,
  channels: DEFAULT_CHANNELS
};

let activeCollectorConfig: WindowsEventCollectorConfig = { ...DEFAULT_COLLECTOR_CONFIG };

/**
 * Initializes and loads channel configurations from SQLite
 */
export function initChannelConfigs(): void {
  try {
    const rows = query<{ key: string; value: string }>('SELECT key, value FROM system_metadata WHERE key LIKE "event_channel_%"');
    if (rows.length > 0) {
      for (const row of rows) {
        const channelKey = row.key.replace('event_channel_', '');
        if (activeCollectorConfig.channels[channelKey]) {
          try {
            const parsed = JSON.parse(row.value);
            activeCollectorConfig.channels[channelKey] = {
              ...activeCollectorConfig.channels[channelKey],
              ...parsed
            };
          } catch (e) {
            log.warn(`Failed to parse channel config for ${channelKey}:`, e);
          }
        }
      }
    }
  } catch (err) {
    log.debug('Channel config initialization completed with defaults');
  }
}

export function getCollectorConfig(): WindowsEventCollectorConfig {
  return activeCollectorConfig;
}

export function updateChannelConfig(channelName: string, updates: Partial<ChannelConfig>): ChannelConfig {
  const channel = activeCollectorConfig.channels[channelName];
  if (!channel) {
    throw new Error(`Channel '${channelName}' not found in collector configuration.`);
  }

  const updated: ChannelConfig = {
    ...channel,
    ...updates
  };

  activeCollectorConfig.channels[channelName] = updated;

  // Persist to system_metadata
  try {
    run(
      'INSERT OR REPLACE INTO system_metadata (key, value, updated_at) VALUES (?, ?, ?)',
      [`event_channel_${channelName}`, JSON.stringify(updated), new Date().toISOString()]
    );
  } catch (err) {
    log.warn(`Could not persist channel config for ${channelName} to database:`, err);
  }

  log.info(`Updated channel config for ${channelName}: enabled=${updated.enabled}, allowed_event_ids=[${updated.allowed_event_ids.join(', ')}]`);
  return updated;
}

export function updateCollectorConfig(updates: Partial<WindowsEventCollectorConfig>): WindowsEventCollectorConfig {
  activeCollectorConfig = {
    ...activeCollectorConfig,
    ...updates,
    channels: updates.channels ? { ...activeCollectorConfig.channels, ...updates.channels } : activeCollectorConfig.channels
  };

  try {
    run(
      'INSERT OR REPLACE INTO system_metadata (key, value, updated_at) VALUES (?, ?, ?)',
      ['event_collector_config', JSON.stringify({
        enabled: activeCollectorConfig.enabled,
        polling_interval_ms: activeCollectorConfig.polling_interval_ms,
        batch_flush_size: activeCollectorConfig.batch_flush_size,
        noise_filter_enabled: activeCollectorConfig.noise_filter_enabled
      }), new Date().toISOString()]
    );
  } catch (err) {
    log.warn('Could not persist collector config:', err);
  }

  return activeCollectorConfig;
}

/**
 * Checks if a Windows Event should be collected based on channel config and noise filters
 */
export function shouldCollectEvent(channelName: string, eventId: number, userContext?: string): boolean {
  if (!activeCollectorConfig.enabled) return false;

  const channel = activeCollectorConfig.channels[channelName];
  if (!channel || !channel.enabled) return false;

  // If allowed_event_ids is configured, event must be in it
  if (channel.allowed_event_ids.length > 0 && !channel.allowed_event_ids.includes(eventId)) {
    return false;
  }

  // If excluded_event_ids is configured, event must not be in it
  if (channel.excluded_event_ids.includes(eventId)) {
    return false;
  }

  // Noise Reduction: Low resource filter
  if (channel.filter_system_noise || activeCollectorConfig.noise_filter_enabled) {
    // Filter out common high-volume benign Windows background service logons
    if (eventId === 4624 && userContext) {
      const u = userContext.toUpperCase();
      if (
        u.includes('DWM-') || 
        u.includes('LOCAL SERVICE') || 
        u.includes('NETWORK SERVICE') || 
        u.includes('UMFD-') ||
        u.includes('ANONYMOUS LOGON')
      ) {
        return false;
      }
    }
  }

  return true;
}
