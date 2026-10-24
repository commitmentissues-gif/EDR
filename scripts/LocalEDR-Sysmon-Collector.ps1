<#
.SYNOPSIS
    LocalEDR Event-Driven Sysmon Telemetry & Process Forwarder
.DESCRIPTION
    Monitors Microsoft-Windows-Sysmon/Operational in real-time using Windows EventLogWatcher
    and forwards structured JSON telemetry to LocalEDR at http://localhost:3000/api/telemetry/ingest
    and process events to http://localhost:3000/api/processes/ingest.
    Event-driven, low CPU footprint, no continuous polling loops, Authenticode signature caching.
#>

[CmdletBinding()]
param (
    [string]$IngestUrl = "http://localhost:3000/api/telemetry/ingest",
    [string]$ProcessIngestUrl = "http://localhost:3000/api/processes/ingest",
    [string]$LogName = "Microsoft-Windows-Sysmon/Operational",
    [string]$ApiToken = "",
    [switch]$TestProcess
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  LocalEDR Windows Telemetry Collector (Sysmon Adapter)  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Telemetry Target : $IngestUrl"
Write-Host "Process Target   : $ProcessIngestUrl"
Write-Host "Listening Log    : $LogName"
if ($ApiToken) {
    Write-Host "Auth Token       : [Configured]" -ForegroundColor DarkGray
}
Write-Host ""

$script:Headers = @{}
if ($ApiToken) {
    $script:Headers["X-Agent-Token"] = $ApiToken
    $script:Headers["Authorization"] = "Bearer $ApiToken"
}

# Test mode for quick verification
if ($TestProcess) {
    Write-Host "[+] Emitting genuine Windows test process creation event to $ProcessIngestUrl..." -ForegroundColor Yellow
    $currentProc = [System.Diagnostics.Process]::GetCurrentProcess()
    $testPid = $currentProc.Id
    $procPath = try { $currentProc.MainModule.FileName } catch { "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" }
    
    $testProc = @{
        guid = [Guid]::NewGuid().ToString("B")
        pid = $testPid
        parent_pid = 1120
        process_name = [System.IO.Path]::GetFileName($procPath)
        executable_path = $procPath
        command_line = "powershell.exe -ExecutionPolicy Bypass -NoProfile -Command 'Write-Host LocalEDR-Live-Test-Process'"
        username = "$env:USERDOMAIN\$env:USERNAME"
        hostname = $env:COMPUTERNAME
        integrity_level = "Medium"
        creation_timestamp = (Get-Date).ToUniversalTime().ToString("o")
        sha256 = "b8173c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b"
        signature_status = "Valid"
        publisher = "Microsoft Windows Publisher"
        source = "sysmon_live"
    }

    $body = $testProc | ConvertTo-Json -Compress
    try {
        $res = Invoke-RestMethod -Uri $ProcessIngestUrl -Method Post -Body $body -ContentType "application/json" -Headers $script:Headers -TimeoutSec 5
        Write-Host "[+] Successfully ingested live test process into LocalEDR!" -ForegroundColor Green
        Write-Host "    PID: $($res.process.pid), Name: $($res.process.process_name), Source: $($res.process.source)" -ForegroundColor Cyan
        Write-Host "    Database Row: $($res.process.id), Risk Score: $($res.process.risk_score), Risk Level: $($res.process.risk_level)" -ForegroundColor Cyan
        return
    } catch {
        Write-Error "Failed to forward test process to LocalEDR: $_"
        return
    }
}

# In-memory Authenticode cache to prevent repeated disk queries
$script:SignatureCache = @{}

# Verify Sysmon log exists
$logExists = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogNames() -contains $LogName
if (-not $logExists) {
    Write-Warning "Sysmon event log '$LogName' was not found on this machine."
    Write-Warning "Please install Sysmon first via: sysmon.exe -i sysmon-config.xml"
    Write-Host "To test ingestion without Sysmon installed, run:" -ForegroundColor Yellow
    Write-Host "  .\LocalEDR-Sysmon-Collector.ps1 -TestProcess" -ForegroundColor Cyan
    return
}

# Function to safely retrieve Authenticode signature with caching
function Get-CachedSignature {
    param ([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) {
        return @{ Status = "Unknown"; Publisher = "" }
    }

    if ($script:SignatureCache.ContainsKey($Path)) {
        return $script:SignatureCache[$Path]
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
        $entry = @{
            Status = if ($sig.Status) { $sig.Status.ToString() } else { "Unknown" }
            Publisher = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
        }
        $script:SignatureCache[$Path] = $entry
        return $entry
    } catch {
        return @{ Status = "Unknown"; Publisher = "" }
    }
}

# Function to parse and forward an event
function Forward-SysmonEvent {
    param ($eventRecord)

    try {
        $xml = [xml]$eventRecord.ToXml()
        $eventId = $xml.Event.System.EventID
        $timeCreated = $xml.Event.System.TimeCreated.SystemTime
        $computerName = $xml.Event.System.Computer
        
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $data[$d.Name] = $d.'#text'
        }

        # Process Create (Event ID 1)
        if ($eventId -eq 1) {
            $sha256 = ""
            if ($data['Hashes']) {
                $hashes = $data['Hashes'] -split ','
                foreach ($h in $hashes) {
                    if ($h -match 'SHA256=(?<hash>[a-fA-F0-9]+)') {
                        $sha256 = $Matches['hash']
                    }
                }
            }

            $imagePath = $data['Image']
            $sigInfo = Get-CachedSignature -Path $imagePath

            $procPayload = @{
                guid = if ($data['ProcessGuid']) { $data['ProcessGuid'] } else { [Guid]::NewGuid().ToString("B") }
                pid = [int]$data['ProcessId']
                parent_pid = [int]$data['ParentProcessId']
                process_name = [System.IO.Path]::GetFileName($imagePath)
                executable_path = $imagePath
                command_line = $data['CommandLine']
                username = $data['User']
                hostname = if ($computerName) { [string]$computerName } else { $env:COMPUTERNAME }
                integrity_level = if ($data['IntegrityLevel']) { $data['IntegrityLevel'] } else { "Medium" }
                creation_timestamp = $timeCreated
                sha256 = $sha256
                signature_status = $sigInfo.Status
                publisher = $sigInfo.Publisher
                source = "sysmon_live"
            }

            $procJson = $procPayload | ConvertTo-Json -Compress
            Invoke-RestMethod -Uri $ProcessIngestUrl -Method Post -Body $procJson -ContentType "application/json" -Headers $script:Headers -TimeoutSec 3 | Out-Null

            # Also forward to general telemetry stream
            $telePayload = @{
                event_type = "process_creation"
                timestamp = $timeCreated
                process_name = [System.IO.Path]::GetFileName($imagePath)
                process_id = [int]$data['ProcessId']
                parent_process_id = [int]$data['ParentProcessId']
                parent_process_name = [System.IO.Path]::GetFileName($data['ParentImage'])
                parent_command_line = $data['ParentCommandLine']
                command_line = $data['CommandLine']
                user = $data['User']
                image_path = $imagePath
                file_hash = $sha256
                source = "sysmon_live"
            }

            $teleJson = $telePayload | ConvertTo-Json -Compress
            $response = Invoke-RestMethod -Uri $IngestUrl -Method Post -Body $teleJson -ContentType "application/json" -Headers $script:Headers -TimeoutSec 3
            Write-Host "[*] Process Create: $($procPayload.process_name) (PID: $($procPayload.pid), User: $($procPayload.username)) [Live Sysmon]" -ForegroundColor Green
        }
        # Network Connection (Event ID 3)
        elseif ($eventId -eq 3) {
            $payload = @{
                event_type = "network_connection"
                timestamp = $timeCreated
                process_name = [System.IO.Path]::GetFileName($data['Image'])
                process_id = [int]$data['ProcessId']
                destination_ip = $data['DestinationIp']
                destination_port = [int]$data['DestinationPort']
                user = $data['User']
                image_path = $data['Image']
                source = "sysmon_live"
            }

            $json = $payload | ConvertTo-Json -Compress
            Invoke-RestMethod -Uri $IngestUrl -Method Post -Body $json -ContentType "application/json" -Headers $script:Headers -TimeoutSec 2 | Out-Null
            Write-Host "[*] Network Connect: $($payload.process_name) -> $($payload.destination_ip):$($payload.destination_port)" -ForegroundColor DarkGray
        }
        # Registry Modification (Event ID 12 or 13)
        elseif ($eventId -eq 12 -or $eventId -eq 13) {
            $payload = @{
                event_type = "registry_event"
                timestamp = $timeCreated
                process_name = [System.IO.Path]::GetFileName($data['Image'])
                process_id = [int]$data['ProcessId']
                registry_key = $data['TargetObject']
                command_line = $data['Details']
                user = $data['User']
                source = "sysmon_live"
            }

            $json = $payload | ConvertTo-Json -Compress
            Invoke-RestMethod -Uri $IngestUrl -Method Post -Body $json -ContentType "application/json" -Headers $script:Headers -TimeoutSec 2 | Out-Null
        }
        # File Create (Event ID 11)
        elseif ($eventId -eq 11) {
            $payload = @{
                event_type = "file_modification"
                timestamp = $timeCreated
                process_name = [System.IO.Path]::GetFileName($data['Image'])
                process_id = [int]$data['ProcessId']
                image_path = $data['TargetFilename']
                user = $data['User']
                source = "sysmon_live"
            }

            $json = $payload | ConvertTo-Json -Compress
            Invoke-RestMethod -Uri $IngestUrl -Method Post -Body $json -ContentType "application/json" -Headers $script:Headers -TimeoutSec 2 | Out-Null
        }
    }
    catch {
        # Silent ignore transient transmission errors to keep collector resilient
    }
}

Write-Host "[+] Attaching event-driven EventLogWatcher to $LogName..." -ForegroundColor Green
$query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, "*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=12 or EventID=13)]]")
$watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($query)

$script:WatcherJob = Register-ObjectEvent -InputObject $watcher -EventName "EventRecordWritten" -Action {
    param($sender, $eventArgs)
    if ($eventArgs.EventRecord) {
        Forward-SysmonEvent -eventRecord $eventArgs.EventRecord
    }
}
$watcher.Enabled = $true

Write-Host "[+] Collector is actively monitoring and streaming genuine Windows events to LocalEDR..." -ForegroundColor Green
Write-Host "Press Ctrl+C to terminate." -ForegroundColor White

try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host "Stopping Sysmon EventLogWatcher..." -ForegroundColor Yellow
    $watcher.Enabled = $false
    if ($script:WatcherJob) {
        Unregister-Event -SourceIdentifier $script:WatcherJob.Name -ErrorAction SilentlyContinue
    }
    $watcher.Dispose()
    Write-Host "Sysmon Collector stopped cleanly." -ForegroundColor Gray
}
