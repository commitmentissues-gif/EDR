import crypto from 'node:crypto';
import os from 'node:os';
import { NormalizedEvent, EventCategory, EventSeverity } from './types.js';

/**
 * Normalizes any incoming event (raw telemetry, Windows Event Log record, process event, etc.)
 * into the unified Common Event Schema.
 */
export function normalizeEvent(input: any): NormalizedEvent {
  const timestamp = input.timestamp || new Date().toISOString();
  const hostname = input.hostname || os.hostname() || 'WIN-ENDPOINT-01';
  const eventUuid = input.event_uuid || input.event_id || `evt-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;

  // 1. Determine Category
  let category: EventCategory = 'process';
  if (input.event_category) {
    category = input.event_category;
  } else if (input.channel || input.windows_event_id || input.provider) {
    category = 'windows_event';
  } else if (input.destination_ip || input.event_type === 'network_connection') {
    category = 'network';
  } else if (input.file_path || input.event_type === 'file_modification') {
    category = 'file';
  } else if (input.registry_key || input.event_type === 'registry_event') {
    category = 'registry';
  } else {
    category = 'process';
  }

  // 2. Determine Action & Event Type
  let eventType = input.event_type || 'process_creation';
  let action = input.action || 'Process Activity';
  let severity: EventSeverity = input.severity || 'INFORMATIONAL';

  // Windows Event Log Specific Normalization
  if (input.windows_event_id) {
    const eid = Number(input.windows_event_id);
    switch (eid) {
      case 4624:
        eventType = 'logon_success';
        action = `Successful Logon (Type ${input.logon_type || 2})`;
        severity = 'INFORMATIONAL';
        break;
      case 4625:
        eventType = 'logon_failure';
        action = 'Failed Logon Attempt';
        severity = 'MEDIUM';
        break;
      case 4720:
        eventType = 'account_created';
        action = `User Account Created: ${input.target_user || 'NewUser'}`;
        severity = 'HIGH';
        break;
      case 4726:
        eventType = 'account_deleted';
        action = `User Account Deleted: ${input.target_user || 'TargetUser'}`;
        severity = 'MEDIUM';
        break;
      case 4672:
        eventType = 'privilege_assigned';
        action = 'Special Administrative Privileges Assigned';
        severity = 'MEDIUM';
        break;
      case 7045:
      case 4697:
        eventType = 'service_created';
        action = `New Service Installed: ${input.service_name || 'Service'}`;
        severity = 'HIGH';
        break;
      case 106:
      case 4698:
        eventType = 'scheduled_task_created';
        action = `Scheduled Task Registered: ${input.task_name || 'Task'}`;
        severity = 'MEDIUM';
        break;
      case 4104:
        eventType = 'powershell_script_block';
        action = 'PowerShell ScriptBlock Executed';
        severity = input.script_text && (input.script_text.includes('-enc') || input.script_text.includes('downloadstring') || input.script_text.includes('bypass')) ? 'HIGH' : 'INFORMATIONAL';
        break;
      case 1116:
        eventType = 'defender_detection';
        action = 'Windows Defender Malware Detected';
        severity = 'CRITICAL';
        break;
      case 5001:
        eventType = 'defender_protection_disabled';
        action = 'Windows Defender Real-time Protection Disabled';
        severity = 'CRITICAL';
        break;
      case 1102:
        eventType = 'audit_log_cleared';
        action = 'Security Audit Log Cleared';
        severity = 'CRITICAL';
        break;
      default:
        eventType = input.event_type || `windows_event_${eid}`;
        action = input.action || `Windows Event ID ${eid}`;
        break;
    }
  }

  // 3. User normalization
  let userName = input.user_name || input.user || null;
  let userDomain = input.user_domain || null;
  if (userName && userName.includes('\\')) {
    const parts = userName.split('\\');
    userDomain = parts[0];
    userName = parts[1];
  }

  // 4. Clean process name
  let procName = input.process_name || null;
  let procPath = input.process_path || input.image_path || null;
  if (!procName && procPath) {
    procName = procPath.split('\\').pop() || null;
  }

  // 5. Message formulation
  let message = input.message;
  if (!message) {
    if (category === 'windows_event') {
      message = `[${input.channel || 'Security'}] Event ID ${input.windows_event_id || 'N/A'}: ${action} for ${userName || 'SYSTEM'}`;
    } else if (category === 'process') {
      message = `Process created: ${procName || 'unknown.exe'} by PID ${input.process_id || 0}`;
    } else if (category === 'network') {
      message = `Network connection to ${input.destination_ip || 'unknown'}:${input.destination_port || 0}`;
    } else if (category === 'file') {
      message = `File modified: ${input.file_path || 'unknown file'}`;
    } else if (category === 'registry') {
      message = `Registry key modified: ${input.registry_key || 'unknown key'}`;
    } else {
      message = `Activity recorded on ${hostname}`;
    }
  }

  // 6. Safe payload string length bounding for low resource usage
  let scriptText = input.script_text || null;
  if (scriptText && scriptText.length > 4096) {
    scriptText = scriptText.substring(0, 4096) + '... [TRUNCATED]';
  }

  return {
    id: input.id,
    event_uuid: eventUuid,
    event_category: category,
    event_type: eventType,
    timestamp,
    hostname,
    provider: input.provider || (input.channel ? `Microsoft-Windows-${input.channel}` : 'Sysmon'),
    channel: input.channel || (category === 'windows_event' ? 'Security' : 'Sysmon'),
    windows_event_id: input.windows_event_id ? Number(input.windows_event_id) : undefined,
    severity,
    action,

    // Identity
    user_name: userName || undefined,
    user_domain: userDomain || undefined,
    user_sid: input.user_sid || undefined,
    logon_id: input.logon_id || undefined,
    logon_type: input.logon_type ? Number(input.logon_type) : undefined,
    privilege_list: Array.isArray(input.privilege_list) ? input.privilege_list : undefined,

    // Process
    process_id: input.process_id ? Number(input.process_id) : undefined,
    process_name: procName || undefined,
    process_path: procPath || undefined,
    command_line: input.command_line || undefined,
    parent_process_id: input.parent_process_id ? Number(input.parent_process_id) : undefined,
    parent_process_name: input.parent_process_name || undefined,
    parent_command_line: input.parent_command_line || undefined,
    file_hash: input.file_hash || undefined,
    signature_status: input.signature_status || undefined,
    integrity_level: input.integrity_level || undefined,

    // Network
    source_ip: input.source_ip || undefined,
    source_port: input.source_port ? Number(input.source_port) : undefined,
    destination_ip: input.destination_ip || undefined,
    destination_port: input.destination_port ? Number(input.destination_port) : undefined,
    protocol: input.protocol || (input.destination_port ? 'TCP' : undefined),

    // Targets
    target_user: input.target_user || undefined,
    target_domain: input.target_domain || undefined,
    target_resource: input.target_resource || undefined,
    file_path: input.file_path || undefined,
    registry_key: input.registry_key || undefined,
    service_name: input.service_name || undefined,
    service_file_name: input.service_file_name || undefined,
    task_name: input.task_name || undefined,
    script_text: scriptText || undefined,

    // Extra
    message,
    data_json: typeof input.data_json === 'string' ? input.data_json : (input.data_json ? JSON.stringify(input.data_json) : undefined),
    is_alerted: input.is_alerted ? 1 : 0,
    created_at: input.created_at || new Date().toISOString(),

    // Backwards compatibility mappings for TelemetryEvent consumers
    event_id: eventUuid,
    user: (userDomain ? `${userDomain}\\` : '') + (userName || 'SYSTEM'),
    image_path: procPath || undefined,
    source: input.source || input.channel || 'windows_events',
    raw_json: input.raw_json || JSON.stringify(input)
  };
}
