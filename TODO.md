# LocalEDR - Project Roadmap & TODO List

This document tracks completed modules and upcoming milestones as LocalEDR is developed incrementally.

---

## [x] Completed in Chunk 1: Foundation & Modular Architecture
- [x] **Modular Directory Layout**:
  - `agent/`: Windows Service agent project (.NET 8 NativeAOT + SysmonWatcher).
  - `backend/`: Configuration loader, structured logger, versioning, health checker, SQLite DB, and local event queue.
  - `dashboard/`: React SOC web console.
  - `rules/`: JSON Schema and declarative rule catalog.
  - `mitre/`: Enterprise ATT&CK matrix mappings.
  - `threat-intel/`: Curated SHA256 and IP indicators.
  - `config/`: JSON configuration profiles and schemas.
  - `tests/`: Automated unit test suite with 27/27 passing checks.
  - `scripts/`: Development and production lifecycle scripts (`dev.sh`, `build.sh`, `test.sh`, `install-service.ps1`).
- [x] **Subsystem Health-Check Endpoint (`/api/health`)**:
  - Evaluates database responsiveness, memory consumption, system load, and event queue capacity.
- [x] **Structured Logging & Audit Trails (`backend/logger`)**:
  - Leveled logging (`DEBUG`, `INFO`, `WARN`, `ERROR`, `AUDIT`) with file and console sinks.
- [x] **Local Event Queue (`backend/queue`)**:
  - Backpressure guard with batch processing and capacity tracking.
- [x] **Version Metadata System (`/api/version`)**:
  - Reports API version, build date, commit, runtime platform, and capability flags.

---

## [x] Completed: Native Windows Service Agent
- [x] **Windows Service Lifecycle Implementation (`agent/windows`)**:
  - Native integration with Windows Service Control Manager (`Microsoft.Extensions.Hosting.WindowsServices`).
  - Automatic boot startup (`start= auto` / `SERVICE_AUTO_START`).
  - Automatic failure recovery and restart on unexpected crash (`reset= 86400 actions= restart/5000/restart/5000/restart/10000`).
  - Graceful pre-shutdown signal handling (`StopAsync` / SCM PreShutdown).
  - Multi-sink service logging (Windows Event Log source `LocalEDR` + local file `data/logs/service.log`).
  - Real-time service health status output (`data/service-health.json`).
  - Low-frequency heartbeat without continuous polling (`< 0.1%` CPU, `< 20 MB` memory).
  - Scope strictly limited to: startup, config loading, logging, database check, health monitoring, graceful shutdown (no telemetry active).
- [x] **Service Management Scripts Suite (`scripts/`)**:
  - `install-service.ps1`: Registers service with auto-start and failure rules.
  - `uninstall-service.ps1`: Gracefully stops and removes service from SCM.
  - `start-service.ps1`: Starts service and verifies running state.
  - `stop-service.ps1`: Gracefully stops service with timeout and clean exit.
  - `restart-service.ps1`: Cleanly restarts service.
  - `status-service.ps1`: Displays detailed SCM status, recovery actions, memory, and uptime.
  - `service-manager.bat`: Single command-prompt CLI wrapper.
- [x] **Resilience & Lifecycle Test Suite**:
  - `tests/service-lifecycle.test.ts` (all 21 lifecycle assertions passing).

---

## [x] Completed: Real Windows Process Monitoring & Lineage
- [x] **Event-Driven Process Creation Collection**:
  - Captures PID, Parent PID (PPID), Process name, Executable path, Command line, Username, Integrity level, Creation timestamp, SHA-256, Digital signature status, and Publisher.
  - Non-polling architecture listening to Windows EventLogWatcher (`Microsoft-Windows-Sysmon/Operational` Event ID 1 & Security Audit Event 4688).
  - Selective hashing (executed binaries only, <100MB) without scanning every file on disk.
  - In-memory `HashSignatureCache` for zero CPU/disk spikes on repeated executions.
- [x] **Indexed SQLite Storage Model (`process_events`)**:
  - Dedicated relational schema with 6 B-Tree indexes on PID, PPID, process name, timestamp, SHA-256, and path.
- [x] **Process Query & Tree API Endpoints**:
  - `GET /api/processes` (with filtering and pagination).
  - `GET /api/processes/{pid}` (process details, parent, children).
  - `GET /api/process-tree` (hierarchical execution lineage tree).
  - `POST /api/processes/ingest` (real-time telemetry receiver).
- [x] **Interactive Dashboard Experience (`ProcessMonitorView`)**:
  - Full process list with real-time search, integrity level filters, Authenticode badges, and process detail drawer.
  - Hierarchical interactive process tree view.
- [x] **Tested with Normal Windows Applications**:
  - Baseline seeded and verified against `System`, `smss.exe`, `services.exe`, `svchost.exe`, `explorer.exe`, `taskhostw.exe`, `chrome.exe`, `notepad.exe`, `cmd.exe`, `powershell.exe`.
  - Full automated test suite passing (70/70 assertions).

---

## [x] Completed: Process Execution Detection Engine & Heuristics
- [x] **Process Execution Detection Rules**:
  - Suspicious parent-child anomalies (e.g., Office spawning Cmd/PowerShell, Spoolsv spawning LOLBAS, WmiPrvSE spawning script engines).
  - Unsigned binaries executing from user-writable directories (`%TEMP%`, `%APPDATA%`).
  - Command line obfuscation & base64 encoded payload detection.
- [x] **Automated Alert Correlation & MITRE ATT&CK Mapping**:
  - Automatic linking of process execution events to ATT&CK tactics (Execution, Persistence, Defense Evasion).
- [x] **Atomic Red Team Safe Simulation Injectors**:
  - Safe process creation validation tests with live rule triggering feedback.
- [x] **Transparent Mathematical Risk Scoring**:
  - Clamped (0-100) scoring model with configurable factor weights and breakdown formulas.
- [x] **Resilient Client-Server Communication**:
  - Protected API routes with explicit JSON 404 handler and safe client-side fetch abstractions.
