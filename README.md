# LocalEDR - Lightweight Local Windows Endpoint Detection & Response

**LocalEDR** is an autonomous, privacy-preserving, lightweight Windows Endpoint Detection and Response (EDR) solution designed to run continuously as a native Windows Service with zero external cloud dependencies.

---

## Windows Service Architecture

The LocalEDR endpoint agent runs as a native Windows Service (`LocalEDR_Agent`):
- **Boot Persistence**: Registered with `SERVICE_AUTO_START` to automatically launch when Windows boots without requiring user logon or manual start.
- **Continuous Background Execution**: Operates under the Windows Service Control Manager (SCM).
- **Crash Resilience & Auto-Restart**: Configured with automatic failure recovery actions (`reset= 86400 actions= restart/5000/restart/5000/restart/10000`) so it automatically restarts after any unexpected process failure.
- **Graceful Shutdown**: Intercepts SCM pre-shutdown notifications (`PreShutdown` / `StopAsync`), flushes in-memory audit trails, closes SQLite database connections, and writes clean termination state.
- **Resource Optimization**: Employs non-polling low-frequency health check-ins, keeping CPU consumption at `< 0.1%` and working set memory under `~15–40 MB`.
- **Integrated Architecture**: Hosts autonomous SQLite storage, structured logging, health checks, and event-driven process monitoring pipeline.

---

## Windows Process Monitoring Architecture

LocalEDR features real-time, event-driven Windows process monitoring designed to reconstruct complete process lineage without excessive CPU or disk usage:

### 1. Process Event Model
Every process creation event captures:
- **PID**: Process Identifier.
- **Parent PID (PPID)**: Parent Process Identifier for parent-child execution tree building.
- **Process Name**: Binary executable name (e.g., `explorer.exe`, `powershell.exe`).
- **Executable Path**: Fully-qualified filesystem path (e.g., `C:\Windows\System32\cmd.exe`).
- **Command Line**: Full command line with arguments (e.g., `cmd.exe /c whoami`).
- **Username**: Security principal context (e.g., `NT AUTHORITY\SYSTEM`, `WIN-LAPTOP\User`).
- **Integrity Level**: Windows mandatory integrity level (`System`, `High`, `Medium`, `Low`, `AppContainer`).
- **Creation Timestamp**: ISO 8601 high-resolution timestamp.
- **SHA-256 Hash**: Cryptographic hash of the executed binary.
- **Digital Signature Status**: Authenticode verification state (`Valid`, `Unsigned`, `Invalid`, `Unknown`).
- **Publisher**: Authenticode signer certificate subject (e.g., `Microsoft Windows Publisher`, `Google LLC`).
- **Source**: Telemetry source (`sysmon_event_1`, `security_audit_4688`, `live_monitor`).

### 2. High-Performance, Low-Overhead Design
- **Event-Driven Collection**: Uses Windows EventLogWatcher (`Microsoft-Windows-Sysmon/Operational` Event ID 1 and Security Audit 4688) instead of continuous process polling or enumeration loops.
- **Selective Binary Hashing**: Hashes are computed **only** for executed files (with size caps under 100MB) rather than scanning the entire disk.
- **In-Memory Hash & Signature Cache (`HashSignatureCache`)**: Caches SHA-256 and Authenticode certificate subjects in an in-memory LRU cache to eliminate duplicate disk reads for frequently executed system binaries.
- **Indexed SQLite Storage**: Stored in the `process_events` table with dedicated B-Tree indexes:
  - `idx_process_events_pid` ON `process_events(pid)`
  - `idx_process_events_ppid` ON `process_events(parent_pid)`
  - `idx_process_events_name` ON `process_events(process_name)`
  - `idx_process_events_timestamp` ON `process_events(creation_timestamp)`
  - `idx_process_events_sha256` ON `process_events(sha256)`
  - `idx_process_events_exe` ON `process_events(executable_path)`

### 3. Process-Tree Engine & Lineage Reconstruction
The process-tree engine reconstructs true parent-child execution lineages:
```text
explorer.exe
└── chrome.exe
└── powershell.exe
└── cmd.exe
      └── conhost.exe
```

Key capabilities:
- **Causality & PID Reuse Handling**: Reconstructs relationships using PID, Parent PID, Creation Timestamp (ensuring parent timestamp precedes child timestamp), and Executable Path. Windows PID collisions over time are resolved chronologically.
- **Terminated Parent Handling**:
  - Handles processes whose parent process has already terminated (e.g. `updater_setup.exe` [Terminated] ➔ `bg_sync_service.exe` [Running]).
  - Preserves historical terminated parent records in the hierarchy with `is_terminated: true` so child processes remain attached in context.
  - Accounts for processes whose parent terminated prior to telemetry collection (e.g., `explorer.exe` launched by logon-terminated `userinit.exe` PID 740).
- **Security Risk Scoring Engine**:
  - Scores every process on a scale of 0 to 100 (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - Evaluates Living-off-the-Land (LOLBIN) patterns (e.g. `powershell.exe` with `-ExecutionPolicy Bypass`, `-enc`, memory injection/download cradles), unsigned binaries, invalid digital signatures, and abnormal parent-child relations (e.g. Office or browser spawning console shells).

### 4. Process Telemetry & Tree API Endpoints

- `GET /api/process-tree`: Returns the complete hierarchical execution tree with risk scores, Authenticode details, and terminated parent preservation. Optional query filters: `root_pid`, `include_terminated`, `min_risk`.
- `GET /api/process-tree/:pid`: Retrieves subtree rooted at a specific PID along with ancestor lineage chain.
- `GET /api/process-tree/lineage/:pid`: Returns the root-to-leaf ancestor path and direct children for a specific process.
- `GET /api/process-tree/stats`: Returns tree statistics (total nodes, active, terminated, root count, max depth, high risk count).
- `POST /api/processes/terminate-event`: Ingestion endpoint for recording process termination telemetry events (verifies that child branches remain attached).
- `GET /api/processes`: Paginated process list with filtering (`search`, `integrity_level`, `signature_status`, `status`, `min_risk`, `limit`, `offset`).
- `GET /api/processes/:pid`: Retrieves single process by PID with immediate parent and children.
- `POST /api/processes/ingest`: Ingestion endpoint for new process creation events.

### 5. Visual Process-Tree Dashboard Component
- Dedicated **Processes** tab with dual **Process Tree** and **Process List** views.
- Each process node card in the visual tree clearly displays:
  - **Process Name**: Executable binary name with executable icon.
  - **PID**: Process identifier badge.
  - **Parent PID**: Parent process identifier badge (with terminated status indicator if parent is dead).
  - **User**: Security principal context (e.g. `WIN-LAPTOP\User`, `NT AUTHORITY\SYSTEM`).
  - **Command Line**: Full command line arguments preview with quick-copy button.
  - **SHA-256**: Hex cryptographic hash with one-click copy.
  - **Signature Status**: Authenticode validity badge (`Valid`, `Unsigned`, `Invalid`) alongside signer publisher.
  - **Risk Score**: Color-coded risk badge (`Risk: 0-100` with `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` levels).
- Interactive capabilities:
  - **Expand / Collapse All** buttons and per-branch chevron toggles.
  - **Real-time Filter & Search**: Instant filter by Risk Level (All, High/Critical, Medium, Low), Terminated status, and keyword search across PID, name, cmdline, and SHA-256.
  - **Process Detail Inspector**: Clicking any process opens an inspector modal displaying full metadata, risk assessment breakdown with individual risk factor bullets, copyable paths and hashes, upstream ancestor lineage breadcrumbs, and clickable child process cards.
  - Strict read-only inspection (no kill/response controls added).

### 6. Windows Applications Baseline Testing
The system is validated against normal Windows applications:
- System boot baseline: `System` (PID 4), `smss.exe` (PID 368), `services.exe` (PID 612), `svchost.exe` (PID 884, 1044).
- Interactive user baseline: `explorer.exe` (PID 1120), `taskhostw.exe` (PID 1940), `chrome.exe` (PID 2840), `notepad.exe` (PID 3420), `cmd.exe` (PID 4112), `powershell.exe` (PID 4820), `conhost.exe` (PID 4912).
- Terminated parent test scenario: `updater_setup.exe` (PID 5520, terminated) ➔ `bg_sync_service.exe` (PID 5530, running).

---

## Windows Service Management Commands

All service management scripts are located in the `scripts/` directory. Run these commands from an **Administrator PowerShell** or **Command Prompt**:

### 1. Install Service (Auto-Start at Boot & Crash Recovery)
Installs `LocalEDR_Agent`, configures automatic boot startup (`start= auto`), registers recovery restart actions, and starts the service:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-service.ps1
```
Or via Windows Command Prompt:
```cmd
scripts\service-manager.bat install
```

### 2. Inspect Service Status & Health Diagnostics
Outputs real-time SCM status, process ID, startup type, failure actions, working set memory, and uptime:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\status-service.ps1
```
Or via native Windows commands:
```cmd
sc.exe query LocalEDR_Agent
sc.exe qc LocalEDR_Agent
sc.exe qfailure LocalEDR_Agent
```

### 3. Gracefully Stop Service
Issues a graceful termination signal allowing the service to flush logs and update health status:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\stop-service.ps1
```
Or via `sc.exe`:
```cmd
net stop LocalEDR_Agent
```

### 4. Start Service
Starts the service if stopped:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-service.ps1
```
Or via `sc.exe`:
```cmd
net start LocalEDR_Agent
```

### 5. Restart Service
Performs a clean restart:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\restart-service.ps1
```

### 6. Uninstall Service
Gracefully stops the service and unregisters it from Windows Service Control Manager:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\uninstall-service.ps1
```
Or via `sc.exe`:
```cmd
sc.exe stop LocalEDR_Agent
sc.exe delete LocalEDR_Agent
```

---

## Service Log Inspection & Health Telemetry

- **Service Health Report**: `data/service-health.json` (Atomic JSON updated every 15 seconds)
- **Service Rolling Log**: `data/logs/service.log`
- **Windows Event Log**: View via Event Viewer (`eventvwr.msc`) under `Windows Logs -> Application` with Source `LocalEDR`.
- **Health-Check API Endpoint**: `GET http://127.0.0.1:3000/api/health`

---

## Testing Service Lifecycle & Reboot Resilience

To execute the automated unit and lifecycle test suite verifying configuration loading, logging, database initialization, reboot survival flags, and graceful shutdown handling:
```bash
npm run test
```
Or run the dedicated service lifecycle test:
```bash
npx tsx tests/service-lifecycle.test.ts
```

---

## Directory Structure

```
├── agent/                         # Windows Service Agent source
│   ├── windows/                   # Native C# .NET 8 Windows Service
│   │   ├── LocalEDR.Agent.csproj  # NativeAOT-ready project file
│   │   ├── Program.cs             # Windows Service lifecycle host
│   │   ├── Worker.cs              # Background supervisor & health monitor
│   │   └── SysmonWatcher.cs       # Future telemetry adapter (disabled)
├── backend/                       # Local EDR backend core
│   ├── config/                    # Configuration loader (localedr.default.json)
│   ├── db/                        # SQLite initialization & schema migrations
│   ├── health/                    # Subsystem health checker
│   ├── logger/                    # Structured leveled logger & audit trail
│   ├── queue/                     # Local event queue with backpressure
│   └── version/                   # Version metadata
├── config/                        # Configuration schemas and profiles
├── data/                          # Persistent storage & logs
│   ├── localedr.db                # Local SQLite WAL database
│   ├── service-health.json        # Service health diagnostics report
│   └── logs/service.log           # Service operational log
├── scripts/                       # Operational management scripts
│   ├── install-service.ps1        # SCM installer (start=auto + failure rules)
│   ├── uninstall-service.ps1      # SCM uninstaller
│   ├── start-service.ps1          # Service start script
│   ├── stop-service.ps1           # Graceful stop script
│   ├── restart-service.ps1        # Service restart script
│   ├── status-service.ps1         # Status & diagnostics query
│   └── service-manager.bat        # CMD wrapper
├── tests/                         # Automated test suite
│   ├── run-all.ts                 # Full test suite runner
│   └── service-lifecycle.test.ts  # Service startup & resilience tests
├── src/                           # React SOC web dashboard
└── server.ts                      # Local API service & Vite middleware
```
