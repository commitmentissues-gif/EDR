import { 
  NetworkEvent, 
  NetworkDetectorConfig, 
  NetworkDetectionAnalysis,
  NetworkProtocol
} from './types.js';
import { query } from '../db/index.js';

export const DEFAULT_NETWORK_CONFIG: NetworkDetectorConfig = {
  enabled: true,
  // Standard common ports that are generally expected for enterprise workstation traffic
  commonAllowedPorts: [80, 443, 53, 123, 389, 636, 88, 445, 22, 587, 993, 995, 3389, 8080],
  // Known dangerous or uncommon ports often leveraged by C2, reverse shells, or backdoor listeners
  uncommonPorts: [
    4444, // Metasploit default payload listener
    1337, // Elite / hacker C2
    31337, // Back Orifice
    6667, // IRC Botnet C2
    5555, // Freeciv / Android ADB backdoor
    9001, // Tor default directory / relay
    9050, // Tor SOCKS proxy
    4443, // Alternate TLS C2 / Pharos
    8888, // Alternate HTTP proxy
    7777, // Terraria / backdoor port
    9999, // Urchin / backdoor
    1080, // SOCKS proxy
    2222, // Alternate SSH
    8000, // Python SimpleHTTPServer staging
    8008, // Alternate HTTP
    8443, // Alternate HTTPS C2
    23,   // Telnet (unencrypted, legacy)
    21    // FTP (unencrypted)
  ],
  // TLDs with disproportionate abuse for phishing, malware hosting, or C2
  suspiciousTlds: [
    '.xyz', '.top', '.ru', '.su', '.tk', '.cc', '.buzz', '.onion', '.click', 
    '.download', '.work', '.gq', '.ml', '.cf', '.ga', '.rest', '.bar', '.live'
  ],
  // Dynamic DNS and tunneling domains commonly abused for C2 callback infrastructure
  suspiciousDomains: [
    'duckdns.org', 'ngrok.io', 'ngrok-free.app', 'localtunnel.me', 'portmap.io', 
    'serveo.net', 'pagekite.me', 'no-ip.org', 'no-ip.com', 'hopto.org', 'zapto.org',
    'pastebin.com', 'hastebin.com', 'raw.githubusercontent.com', 'discordapp.com/api/webhooks'
  ],
  // Processes that should rarely or NEVER establish outbound network sockets to external hosts
  unusualOutboundProcesses: [
    'cmd.exe',
    'powershell.exe',
    'powershell_ise.exe',
    'pwsh.exe',
    'rundll32.exe',
    'regsvr32.exe',
    'mshta.exe',
    'certutil.exe',
    'bitsadmin.exe',
    'wmic.exe',
    'cscript.exe',
    'wscript.exe',
    'msiexec.exe',
    'schtasks.exe',
    'reg.exe',
    'notepad.exe',
    'calc.exe',
    'calculator.exe',
    'spoolsv.exe',
    'lsass.exe',
    'smss.exe',
    'winlogon.exe',
    'csrss.exe',
    'services.exe',
    'taskhostw.exe',
    'winword.exe',
    'excel.exe',
    'powerpnt.exe',
    'outlook.exe',
    'mspaint.exe'
  ],
  beaconingDetection: {
    enabled: true,
    minConnections: 4,
    timeWindowSeconds: 120,
    maxJitterPercent: 20
  },
  threatIntelCheckEnabled: true,
  alertOnUnusualProcess: true
};

// Curated list of known malicious C2 IP indicators (in addition to the SQLite threat_intel table)
const EMBEDDED_MALICIOUS_IPS = new Set<string>([
  '198.51.100.45',   // Simulated Cobalt Strike Team Server
  '203.0.113.195',   // Simulated Emotet C2 Node
  '198.51.100.89',   // Simulated Qakbot Infrastructure
  '185.220.101.5',   // Known Tor Exit / Bulletproof C2
  '194.26.29.114',   // RedLine Stealer Gateway
  '91.240.118.172',  // LockBit C2 Server
  '45.142.214.123',  // DarkGate C2 Server
  '193.106.191.162'  // LummaC2 Relay
]);

interface ConnectionTimestampEntry {
  timestampMs: number;
}

// Lightweight bounded connection history for beaconing detection
// Key: `${process_name.toLowerCase()}|${destination_ip}|${destination_port}`
class ConnectionTracker {
  private history = new Map<string, ConnectionTimestampEntry[]>();
  private readonly maxTrackedKeys = 500;
  private readonly maxEntriesPerKey = 20;

  record(key: string, timestampMs: number): void {
    if (this.history.size > this.maxTrackedKeys) {
      const firstKey = this.history.keys().next().value;
      if (firstKey) this.history.delete(firstKey);
    }

    let entries = this.history.get(key);
    if (!entries) {
      entries = [];
      this.history.set(key, entries);
    }

    entries.push({ timestampMs });
    if (entries.length > this.maxEntriesPerKey) {
      entries.shift();
    }
  }

  getEntries(key: string): ConnectionTimestampEntry[] {
    return this.history.get(key) || [];
  }

  clear(): void {
    this.history.clear();
  }
}

export const connectionTracker = new ConnectionTracker();

/**
 * Checks if an IP is private/loopback RFC1918/RFC4193
 */
export function isPrivateOrLocalIp(ip: string): boolean {
  if (!ip) return true;
  const clean = ip.trim().toLowerCase();
  if (clean === '127.0.0.1' || clean === 'localhost' || clean === '::1' || clean === '0.0.0.0') {
    return true;
  }
  if (clean.startsWith('10.') || clean.startsWith('192.168.')) {
    return true;
  }
  if (clean.startsWith('172.')) {
    const parts = clean.split('.');
    if (parts.length >= 2) {
      const secondOctet = parseInt(parts[1], 10);
      if (secondOctet >= 16 && secondOctet <= 31) {
        return true;
      }
    }
  }
  if (clean.startsWith('169.254.')) {
    return true; // Link-local
  }
  if (clean.startsWith('fc') || clean.startsWith('fd') || clean.startsWith('fe80')) {
    return true; // IPv6 local
  }
  return false;
}

/**
 * Network Telemetry Detection Engine
 * Evaluates connection metadata against detection heuristics:
 * 1. Known malicious IP / Threat Intel
 * 2. Suspicious destination / domain / TLD
 * 3. Unusual outbound connection (system binary to internet)
 * 4. Suspicious process network connection (Office / LOLBin sockets)
 * 5. Repeated connection patterns (beaconing / regular C2 intervals)
 * 6. Uncommon / suspicious ports
 */
export class NetworkDetector {
  private config: NetworkDetectorConfig;

  constructor(config: NetworkDetectorConfig = DEFAULT_NETWORK_CONFIG) {
    this.config = { ...config };
  }

  updateConfig(newConfig: Partial<NetworkDetectorConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  getConfig(): NetworkDetectorConfig {
    return { ...this.config };
  }

  analyzeConnection(
    event: {
      pid: number;
      process_name: string;
      process_path?: string;
      parent_process_name?: string;
      source_ip: string;
      source_port: number;
      destination_ip: string;
      destination_port: number;
      protocol: NetworkProtocol;
      timestamp?: string;
      domain?: string;
      direction?: 'outbound' | 'inbound';
    }
  ): NetworkDetectionAnalysis {
    const tags: string[] = [];
    const reasons: string[] = [];
    const mitreTechniques: Array<{ tactic: string; technique_id: string; technique_name: string }> = [];
    let riskScore = 0;

    if (!this.config.enabled) {
      return { isSuspicious: false, riskScore: 0, tags: [], reasons: [], mitreTechniques: [] };
    }

    const procName = (event.process_name || '').toLowerCase();
    const destIp = (event.destination_ip || '').trim();
    const destPort = event.destination_port;
    const domain = (event.domain || '').toLowerCase().trim();
    const isLocal = isPrivateOrLocalIp(destIp);
    const direction = event.direction || (isLocal ? 'inbound' : 'outbound');
    const timestampMs = event.timestamp ? new Date(event.timestamp).getTime() : Date.now();

    // -------------------------------------------------------------
    // 1. Detect: Known Malicious IP / Threat Intel
    // -------------------------------------------------------------
    let threatIntelMatched = false;
    let threatActor = '';
    let threatDesc = '';

    if (this.config.threatIntelCheckEnabled && destIp && !isLocal) {
      if (EMBEDDED_MALICIOUS_IPS.has(destIp)) {
        threatIntelMatched = true;
        threatActor = 'Known C2 Infrastructure';
        threatDesc = 'Embedded high-confidence malicious C2 IP';
      } else {
        try {
          const rows = query<any>(
            'SELECT value, description, threat_actor FROM threat_intel WHERE value = ? AND type = "ip" LIMIT 1',
            [destIp]
          );
          if (rows && rows.length > 0) {
            threatIntelMatched = true;
            threatActor = rows[0].threat_actor || 'Adversary Threat Group';
            threatDesc = rows[0].description || 'Matched SQLite Threat Intelligence feed';
          }
        } catch {
          // Non-fatal if db is in startup or transition
        }
      }

      if (threatIntelMatched) {
        tags.push('KNOWN_MALICIOUS_IP');
        reasons.push(`Destination IP ${destIp} is verified malicious threat infrastructure (${threatActor}: ${threatDesc})`);
        riskScore = Math.max(riskScore, 95);
        mitreTechniques.push({
          tactic: 'Command and Control',
          technique_id: 'T1071',
          technique_name: 'Application Layer Protocol'
        });
      }
    }

    // -------------------------------------------------------------
    // 2. Detect: Suspicious Destination (Domains & TLDs)
    // -------------------------------------------------------------
    if (domain) {
      // Check suspicious TLDs
      for (const tld of this.config.suspiciousTlds) {
        if (domain.endsWith(tld)) {
          tags.push('SUSPICIOUS_DESTINATION');
          reasons.push(`Connection to high-risk top-level domain '${tld}' (${domain})`);
          riskScore = Math.max(riskScore, 75);
          mitreTechniques.push({
            tactic: 'Command and Control',
            technique_id: 'T1071.001',
            technique_name: 'Web Protocols'
          });
          break;
        }
      }

      // Check suspicious dynamic DNS or tunneling domains
      for (const suspDom of this.config.suspiciousDomains) {
        if (domain === suspDom || domain.endsWith('.' + suspDom)) {
          tags.push('SUSPICIOUS_DESTINATION');
          reasons.push(`Connection to dynamic DNS / tunneling / payload staging provider: ${domain}`);
          riskScore = Math.max(riskScore, 80);
          mitreTechniques.push({
            tactic: 'Command and Control',
            technique_id: 'T1071',
            technique_name: 'Application Layer Protocol'
          });
          break;
        }
      }
    }

    // Raw public IP connection without DNS domain for processes that should resolve hostnames
    if (!domain && !isLocal && (procName === 'powershell.exe' || procName === 'cmd.exe' || procName === 'rundll32.exe')) {
      tags.push('RAW_IP_DESTINATION');
      reasons.push(`Script/LOLBin '${procName}' connecting directly to raw public IP ${destIp} without domain resolution`);
      riskScore = Math.max(riskScore, 65);
    }

    // -------------------------------------------------------------
    // 3. Detect: Uncommon / Suspicious Ports
    // -------------------------------------------------------------
    if (destPort && this.config.uncommonPorts.includes(destPort)) {
      tags.push('UNCOMMON_PORT');
      let portNote = `Port ${destPort}`;
      if (destPort === 4444) portNote = 'Port 4444 (Metasploit default C2 listener)';
      else if (destPort === 1337) portNote = 'Port 1337 (Elite/custom hacker listener)';
      else if (destPort === 6667) portNote = 'Port 6667 (IRC botnet C2)';
      else if (destPort === 31337) portNote = 'Port 31337 (Back Orifice backdoor)';
      else if (destPort === 9001 || destPort === 9050) portNote = `Port ${destPort} (Tor Onion Routing)`;
      else if (destPort === 4443) portNote = 'Port 4443 (Alternate TLS C2 listener)';

      reasons.push(`Outbound connection to non-standard / suspicious destination port: ${portNote}`);
      riskScore = Math.max(riskScore, 70);
      mitreTechniques.push({
        tactic: 'Command and Control',
        technique_id: 'T1571',
        technique_name: 'Non-Standard Port'
      });
    }

    // -------------------------------------------------------------
    // 4. Detect: Suspicious Process Network Connection (Office / LOLBins)
    // -------------------------------------------------------------
    const isOfficeApp = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'].includes(procName);
    const isLolbin = [
      'cmd.exe', 'powershell.exe', 'powershell_ise.exe', 'pwsh.exe',
      'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe',
      'bitsadmin.exe', 'wmic.exe', 'cscript.exe', 'wscript.exe',
      'msiexec.exe', 'schtasks.exe', 'reg.exe'
    ].includes(procName);

    if (isOfficeApp && !isLocal) {
      tags.push('SUSPICIOUS_PROCESS_NETWORK');
      reasons.push(`Microsoft Office application '${procName}' established an outbound network connection to external IP ${destIp}:${destPort}`);
      riskScore = Math.max(riskScore, 85);
      mitreTechniques.push({
        tactic: 'Execution',
        technique_id: 'T1204.002',
        technique_name: 'Malicious File'
      });
      mitreTechniques.push({
        tactic: 'Command and Control',
        technique_id: 'T1071',
        technique_name: 'Application Layer Protocol'
      });
    }

    if (isLolbin && !isLocal) {
      tags.push('SUSPICIOUS_PROCESS_NETWORK');
      reasons.push(`Living-off-the-Land Binary '${procName}' initiated direct network connection to external target ${destIp}:${destPort}`);
      riskScore = Math.max(riskScore, 80);
      mitreTechniques.push({
        tactic: 'Defense Evasion',
        technique_id: 'T1218',
        technique_name: 'System Binary Proxy Execution'
      });
      if (procName === 'certutil.exe' || procName === 'bitsadmin.exe') {
        mitreTechniques.push({
          tactic: 'Command and Control',
          technique_id: 'T1105',
          technique_name: 'Ingress Tool Transfer'
        });
      }
    }

    // -------------------------------------------------------------
    // 5. Detect: Unusual Outbound Connection (System Binaries to Internet)
    // -------------------------------------------------------------
    const systemNoNetBinaries = [
      'notepad.exe', 'calc.exe', 'calculator.exe', 'spoolsv.exe', 
      'lsass.exe', 'smss.exe', 'winlogon.exe', 'csrss.exe', 'services.exe', 'mspaint.exe'
    ];

    if (systemNoNetBinaries.includes(procName) && !isLocal) {
      tags.push('UNUSUAL_OUTBOUND_CONNECTION');
      reasons.push(`Anomalous outbound connection: Core Windows process '${procName}' should never communicate with external host ${destIp}`);
      riskScore = Math.max(riskScore, 90);
      mitreTechniques.push({
        tactic: 'Command and Control',
        technique_id: 'T1071',
        technique_name: 'Application Layer Protocol'
      });
    }

    // -------------------------------------------------------------
    // 6. Detect: Repeated Connection Patterns (Beaconing / Periodic C2)
    // -------------------------------------------------------------
    if (this.config.beaconingDetection.enabled && !isLocal && destIp) {
      const trackingKey = `${procName}|${destIp}|${destPort}`;
      connectionTracker.record(trackingKey, timestampMs);

      const history = connectionTracker.getEntries(trackingKey);
      if (history.length >= this.config.beaconingDetection.minConnections) {
        // Calculate intervals between consecutive timestamps
        const intervals: number[] = [];
        for (let i = 1; i < history.length; i++) {
          const diffSec = (history[i].timestampMs - history[i - 1].timestampMs) / 1000;
          if (diffSec > 0 && diffSec < this.config.beaconingDetection.timeWindowSeconds) {
            intervals.push(diffSec);
          }
        }

        if (intervals.length >= this.config.beaconingDetection.minConnections - 1) {
          const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
          
          if (avgInterval > 0) {
            // Calculate standard deviation and jitter
            const variance = intervals.reduce((sum, val) => sum + Math.pow(val - avgInterval, 2), 0) / intervals.length;
            const stdDev = Math.sqrt(variance);
            const jitterPercent = (stdDev / avgInterval) * 100;

            if (jitterPercent <= this.config.beaconingDetection.maxJitterPercent) {
              tags.push('BEACONING_PATTERN');
              reasons.push(
                `Repeated periodic C2 beaconing detected from '${procName}' to ${destIp}:${destPort}. Mean interval: ${avgInterval.toFixed(1)}s, Jitter: ${jitterPercent.toFixed(1)}% (Low variance)`
              );
              riskScore = Math.max(riskScore, 85);
              mitreTechniques.push({
                tactic: 'Command and Control',
                technique_id: 'T1071',
                technique_name: 'Application Layer Protocol'
              });
            }
          }
        }
      }
    }

    const isSuspicious = tags.length > 0;

    return {
      isSuspicious,
      riskScore: Math.min(100, riskScore),
      tags: Array.from(new Set(tags)),
      reasons,
      mitreTechniques
    };
  }
}

export const networkDetector = new NetworkDetector();
