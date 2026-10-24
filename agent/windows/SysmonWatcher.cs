namespace LocalEDR.Agent;

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Xml;
using Microsoft.Extensions.Logging;

/// <summary>
/// Event-driven watcher that monitors Microsoft-Windows-Sysmon/Operational without polling.
/// Captures high-fidelity Process Creation (Event ID 1) with PID, PPID, Image, CommandLine,
/// IntegrityLevel, and SHA-256 hashes without scanning every file on disk.
/// </summary>
public class SysmonWatcher : IDisposable
{
    private readonly ILogger _logger;
    private readonly HttpClient _httpClient;
    private EventLogWatcher? _watcher;
    private const string LogName = "Microsoft-Windows-Sysmon/Operational";
    private const string ProcessIngestUrl = "http://127.0.0.1:3000/api/processes/ingest";
    private const string TelemetryIngestUrl = "http://127.0.0.1:3000/api/telemetry/ingest";

    private readonly string _processIngestUrl;
    private readonly string _telemetryIngestUrl;

    public SysmonWatcher(ILogger logger, string? apiToken = null, string processIngestUrl = ProcessIngestUrl, string telemetryIngestUrl = TelemetryIngestUrl)
    {
        _logger = logger;
        _processIngestUrl = processIngestUrl;
        _telemetryIngestUrl = telemetryIngestUrl;
        _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        if (!string.IsNullOrEmpty(apiToken))
        {
            _httpClient.DefaultRequestHeaders.Add("X-Agent-Token", apiToken);
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiToken);
        }
    }

    public void Start()
    {
        try
        {
            var query = new EventLogQuery(LogName, PathType.LogName, "*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=12 or EventID=13)]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEventRecordWritten;
            _watcher.Enabled = true;
            _logger.LogInformation("SysmonWatcher attached to {logName} (Event-Driven)", LogName);
        }
        catch (EventLogNotFoundException)
        {
            _logger.LogWarning("Sysmon event log not found. Local baseline and test injection active.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to initialize SysmonWatcher");
        }
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord == null) return;

        try
        {
            var xml = new XmlDocument();
            xml.LoadXml(e.EventRecord.ToXml());

            var eventId = xml.SelectSingleNode("//System/EventID")?.InnerText;
            var timeCreated = xml.SelectSingleNode("//System/TimeCreated/@SystemTime")?.Value ?? DateTime.UtcNow.ToString("o");
            var computer = xml.SelectSingleNode("//System/Computer")?.InnerText ?? Environment.MachineName;

            var dataNodes = xml.SelectNodes("//EventData/Data");
            var eventData = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (dataNodes != null)
            {
                foreach (XmlNode node in dataNodes)
                {
                    var name = node.Attributes?["Name"]?.Value;
                    if (!string.IsNullOrEmpty(name))
                    {
                        eventData[name] = node.InnerText;
                    }
                }
            }

            // Process Creation (Event ID 1)
            if (eventId == "1")
            {
                eventData.TryGetValue("ProcessId", out var pidStr);
                eventData.TryGetValue("ParentProcessId", out var ppidStr);
                eventData.TryGetValue("Image", out var imagePath);
                eventData.TryGetValue("CommandLine", out var commandLine);
                eventData.TryGetValue("User", out var username);
                eventData.TryGetValue("IntegrityLevel", out var integrityLevel);
                eventData.TryGetValue("Hashes", out var hashes);
                eventData.TryGetValue("ProcessGuid", out var processGuid);

                int.TryParse(pidStr, out var pid);
                int.TryParse(ppidStr, out var ppid);

                string sha256 = "";
                if (!string.IsNullOrEmpty(hashes))
                {
                    foreach (var part in hashes.Split(','))
                    {
                        var trimmed = part.Trim();
                        if (trimmed.StartsWith("SHA256=", StringComparison.OrdinalIgnoreCase))
                        {
                            sha256 = trimmed.Substring(7);
                            break;
                        }
                    }
                }

                var procName = !string.IsNullOrEmpty(imagePath) ? Path.GetFileName(imagePath) : "unknown.exe";

                var processPayload = new
                {
                    guid = processGuid ?? Guid.NewGuid().ToString("B"),
                    pid = pid,
                    parent_pid = ppid,
                    process_name = procName,
                    executable_path = imagePath ?? "",
                    command_line = commandLine ?? imagePath ?? "",
                    username = username ?? "WIN-HOST\\User",
                    hostname = computer,
                    integrity_level = integrityLevel ?? "Medium",
                    creation_timestamp = timeCreated,
                    sha256 = sha256,
                    signature_status = "Unknown",
                    publisher = "",
                    source = "sysmon_live"
                };

                _ = Task.Run(async () =>
                {
                    try
                    {
                        var procJson = JsonSerializer.Serialize(processPayload);
                        using var procContent = new StringContent(procJson, Encoding.UTF8, "application/json");
                        var response = await _httpClient.PostAsync(_processIngestUrl, procContent);
                        if (!response.IsSuccessStatusCode)
                        {
                            _logger.LogWarning("LocalEDR process ingest returned HTTP {code} for PID {pid}", (int)response.StatusCode, pid);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogTrace("Failed to send process creation event: {msg}", ex.Message);
                    }
                });
            }
            else
            {
                // Generic telemetry forwarding
                var payload = new
                {
                    event_type = eventId == "3" ? "network_connection" : "generic_event",
                    timestamp = timeCreated,
                    source = "sysmon_live",
                    raw_xml = xml.InnerXml
                };

                _ = Task.Run(async () =>
                {
                    try
                    {
                        var json = JsonSerializer.Serialize(payload);
                        using var content = new StringContent(json, Encoding.UTF8, "application/json");
                        await _httpClient.PostAsync(_telemetryIngestUrl, content);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogTrace("Failed to send telemetry event: {msg}", ex.Message);
                    }
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogTrace("Error forwarding event record: {msg}", ex.Message);
        }
    }

    public void Dispose()
    {
        if (_watcher != null)
        {
            _watcher.Enabled = false;
            _watcher.Dispose();
            _watcher = null;
        }
    }
}
