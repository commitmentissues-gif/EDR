# LocalEDR SOC Web Dashboard

The LocalEDR Dashboard is a high-density, real-time Security Operations Center (SOC) web application built using **React 19 + TypeScript + Vite + Tailwind CSS**.

## Structure
- `src/components/Header.tsx`: System telemetry badges (CPU, RSS RAM, DB size, agent mode).
- `src/components/OverviewView.tsx`: Real-time incident counts, MITRE coverage summary, quick safe simulations.
- `src/components/AlertsView.tsx`: Forensic alert investigation studio with **Why It Triggered** cards, interactive **Process Lineage Tree** visualizer, and staged defensive action confirmation dialogs.
- `src/components/TelemetryView.tsx`: Real-time streaming table for Process, Network, File, and Registry events.
- `src/components/MitreMatrixView.tsx`: Interactive MITRE ATT&CK Enterprise matrix showing active coverage.
- `src/components/RulesView.tsx`: Detection rules manager with enable/disable toggles and custom rule builder.
- `src/components/ThreatIntelView.tsx`: Fast O(1) IoC hash and C2 IP indicator management.
- `src/components/SimulationsView.tsx`: Atomic Red Team style safe non-destructive test suite.
- `src/components/ServiceSetupView.tsx`: Copyable PowerShell commands to deploy the agent as an automatic Windows Service.

## Communication
The dashboard runs locally and communicates strictly with `http://127.0.0.1:3000/api` via REST endpoints.
- `/api/health`: Subsystem health status and latencies.
- `/api/status`: Real-time performance metrics and event counts.
- `/api/telemetry`: Telemetry event queries.
- `/api/alerts`: Alert investigation and response action staging.
