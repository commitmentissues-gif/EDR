import React, { useState } from 'react';
import { Layers, Copy, Check, Terminal, Shield, CheckCircle2, ListTodo, FileCode } from 'lucide-react';

export const ServiceSetupView: React.FC = () => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const steps = [
    {
      title: '1. Install Service (Auto-Start at Boot & Crash Recovery)',
      desc: 'Registers LocalEDR_Agent with SERVICE_AUTO_START and configures automatic restart after unexpected failure (reset= 86400 actions= restart/5000/restart/5000/restart/10000).',
      cmd: 'powershell -ExecutionPolicy Bypass -File scripts\\install-service.ps1'
    },
    {
      title: '2. Check Service Health & Status',
      desc: 'Inspects Service Control Manager state, auto-restart rules, working set memory, and uptime diagnostics.',
      cmd: 'powershell -ExecutionPolicy Bypass -File scripts\\status-service.ps1'
    },
    {
      title: '3. Stop Service (Graceful Shutdown)',
      desc: 'Issues a clean stop request, allowing the service to flush audit logs and update health status before halting.',
      cmd: 'powershell -ExecutionPolicy Bypass -File scripts\\stop-service.ps1'
    },
    {
      title: '4. Start Service',
      desc: 'Starts the LocalEDR_Agent background service if stopped.',
      cmd: 'powershell -ExecutionPolicy Bypass -File scripts\\start-service.ps1'
    },
    {
      title: '5. Restart Service',
      desc: 'Forces a clean restart of LocalEDR_Agent.',
      cmd: 'powershell -ExecutionPolicy Bypass -File scripts\\restart-service.ps1'
    },
    {
      title: '6. Uninstall Service',
      desc: 'Gracefully stops the service and unregisters it from Windows Service Control Manager.',
      cmd: 'powershell -ExecutionPolicy Bypass -File scripts\\uninstall-service.ps1'
    },
    {
      title: '7. Command Prompt / Batch Manager (Alternative)',
      desc: 'Execute any service lifecycle command from standard Windows cmd.exe.',
      cmd: 'scripts\\service-manager.bat status'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-2">
        <div className="flex items-center gap-2 text-emerald-400">
          <Layers className="w-5 h-5" />
          <h2 className="font-bold text-white text-base">Windows Service &amp; Sysmon Deployment Guide</h2>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">
          LocalEDR is engineered to operate autonomously as a native background Windows Service that starts automatically on boot. 
          Follow these steps to deploy the agent service and attach the event-driven Sysmon collector on a target Windows machine.
        </p>
      </div>

      {/* Step by Step Commands */}
      <div className="space-y-4">
        {steps.map((step, idx) => (
          <div
            key={idx}
            className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2"
          >
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-white text-sm">{step.title}</h3>
              <span className="text-[11px] font-mono text-slate-400">PowerShell (Admin)</span>
            </div>
            <p className="text-xs text-slate-400">{step.desc}</p>
            <div className="relative">
              <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono text-emerald-300 overflow-x-auto pr-12">
                {step.cmd}
              </pre>
              <button
                onClick={() => copyToClipboard(step.cmd, idx)}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition cursor-pointer"
                title="Copy command"
              >
                {copiedIndex === idx ? (
                  <Check className="w-4 h-4 text-emerald-400" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Incremental Roadmap & TODO List (Rule 17) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <ListTodo className="w-4 h-4 text-cyan-400" />
            <h3 className="font-bold text-white text-sm">Incremental Roadmap &amp; Feature Status (Rule 17)</h3>
          </div>
          <span className="text-xs font-mono text-slate-400">Awaiting user next chunks</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
            <div className="font-semibold text-emerald-400 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Completed in Chunk 1
            </div>
            <ul className="text-slate-300 space-y-1 pl-4 list-disc text-[11px]">
              <li>Local SQLite WAL database engine (localedr.db)</li>
              <li>Event-driven telemetry ingestion (Process, Net, File, Reg)</li>
              <li>Forensic detection engine with "Why It Triggered" logic</li>
              <li>MITRE ATT&amp;CK matrix correlation &amp; coverage</li>
              <li>Threat Intelligence IoC lookup (SHA256 &amp; C2 IP)</li>
              <li>Safe attack simulations suite (Rule 13)</li>
              <li>Staged response action safety gates (Rule 10)</li>
              <li>Windows Service installer script (SERVICE_AUTO_START)</li>
              <li>Sysmon XML configuration profile</li>
            </ul>
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
            <div className="font-semibold text-amber-400 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" />
              Upcoming in Subsequent Chunks
            </div>
            <ul className="text-slate-400 space-y-1 pl-4 list-disc text-[11px]">
              <li>Native C++ / Rust ETW kernel driver or minifilter bridge</li>
              <li>Behavioral anomaly &amp; burst rate ransomware detection</li>
              <li>Sigma rule import / export compiler</li>
              <li>SIEM Syslog / CEF exporter (Splunk, Wazuh, Elastic)</li>
              <li>Host isolation adapter (WFP / Netsh firewall lock)</li>
              <li>Encrypted file quarantine vault with SHA256 integrity</li>
              <li>On-demand process memory minidump forensics</li>
              <li>Lightweight in-memory YARA scanner</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
