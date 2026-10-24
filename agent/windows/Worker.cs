namespace LocalEDR.Agent;

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly HttpClient _httpClient;
    private readonly string _baseDir;
    private readonly string _logFilePath;
    private readonly string _healthFilePath;
    private readonly string _dbFilePath;
    private JsonElement _config;
    private DateTimeOffset _startTime;
    private SysmonWatcher? _sysmonWatcher;

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
        _baseDir = AppDomain.CurrentDomain.BaseDirectory;
        _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };

        _logFilePath = Path.Combine(_baseDir, "data", "logs", "service.log");
        _healthFilePath = Path.Combine(_baseDir, "data", "service-health.json");
        _dbFilePath = Path.Combine(_baseDir, "data", "localedr.db");
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        _startTime = DateTimeOffset.UtcNow;
        LogToFile("INFO", "Service starting", $"LocalEDR Windows Service initializing. PID={Environment.ProcessId}");
        _logger.LogInformation("LocalEDR Windows Service starting. ProcessId={ProcessId}", Environment.ProcessId);

        // 1. Configuration Loading
        LoadConfiguration();

        // 2. Logging Initialization
        InitializeLogging();

        // 3. Database Initialization Verification
        InitializeDatabase();

        // 4. Initial Health State Publication
        WriteHealthStatus("STARTING", "Service successfully completed initialization sequence.");

        // 5. Initialize & Start Real-time Sysmon Telemetry Watcher
        try
        {
            string? token = null;
            if (_config.TryGetProperty("server", out var srvCfg) && srvCfg.TryGetProperty("adminToken", out var tokElem))
            {
                token = tokElem.GetString();
            }
            _sysmonWatcher = new SysmonWatcher(_logger, token);
            _sysmonWatcher.Start();
            LogToFile("INFO", "Sysmon init", "Sysmon real-time event watcher started.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start SysmonWatcher");
            LogToFile("WARN", "Sysmon init failed", ex.Message);
        }

        await base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("LocalEDR Service supervisor active. Health monitoring engaged.");
        LogToFile("INFO", "Service running", "Supervisor loop started. Real-time Sysmon process monitoring active.");

        // Read heartbeat interval from config (default 15 seconds to minimize CPU/battery impact)
        int heartbeatSeconds = 15;
        if (_config.TryGetProperty("agent", out var agentCfg) && 
            agentCfg.TryGetProperty("heartbeatIntervalSeconds", out var hbElem) &&
            hbElem.TryGetInt32(out var configuredInterval))
        {
            heartbeatSeconds = Math.Max(5, configuredInterval);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Health Monitoring: Inspect process memory and database file health
                using var currentProcess = Process.GetCurrentProcess();
                long workingSetMb = currentProcess.WorkingSet64 / 1024 / 1024;
                long privateMemoryMb = currentProcess.PrivateMemorySize64 / 1024 / 1024;

                bool dbAccessible = File.Exists(_dbFilePath);
                long dbSizeBytes = dbAccessible ? new FileInfo(_dbFilePath).Length : 0;

                var healthReport = new
                {
                    status = "HEALTHY",
                    serviceName = "LocalEDR_Agent",
                    processId = Environment.ProcessId,
                    uptimeSeconds = (long)(DateTimeOffset.UtcNow - _startTime).TotalSeconds,
                    timestamp = DateTimeOffset.UtcNow.ToString("o"),
                    memory = new
                    {
                        workingSetMb,
                        privateMemoryMb
                    },
                    database = new
                    {
                        accessible = dbAccessible,
                        path = _dbFilePath,
                        sizeBytes = dbSizeBytes
                    },
                    telemetryStatus = "SYSMON_PROCESS_WATCHER_ACTIVE"
                };

                // Write atomic health status file for local inspection and external checks
                WriteHealthReport(healthReport);

                // Check local backend health endpoint if available
                try
                {
                    var response = await _httpClient.GetAsync("http://127.0.0.1:3000/api/health", stoppingToken);
                    if (response.IsSuccessStatusCode)
                    {
                        _logger.LogDebug("Local backend health check verified HTTP 200.");
                    }
                }
                catch
                {
                    // Backend may start alongside or independently; do not mark service failed
                }
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogWarning(ex, "Health monitoring loop encountered transient issue.");
                LogToFile("WARN", "Health check warning", ex.Message);
            }

            // Sleep without continuous CPU wakeups
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(heartbeatSeconds), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("LocalEDR Windows Service received stop signal. Commencing graceful shutdown.");
        LogToFile("INFO", "Service shutdown", "Graceful shutdown initiated by Service Control Manager.");

        try
        {
            if (_sysmonWatcher != null)
            {
                _sysmonWatcher.Dispose();
                _sysmonWatcher = null;
                LogToFile("INFO", "Sysmon stop", "SysmonWatcher cleanly detached.");
            }

            // Publish clean shutdown state
            WriteHealthStatus("STOPPED", "Service shut down gracefully.");
            LogToFile("INFO", "Service stopped", "Shutdown procedures complete. Exiting cleanly.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred during graceful shutdown.");
        }

        await base.StopAsync(cancellationToken);
    }

    private void LoadConfiguration()
    {
        try
        {
            string defaultConfigPath = Path.Combine(_baseDir, "config", "localedr.default.json");
            string userConfigPath = Path.Combine(_baseDir, "config", "localedr.json");

            string configToLoad = File.Exists(userConfigPath) ? userConfigPath : defaultConfigPath;

            if (File.Exists(configToLoad))
            {
                string jsonText = File.ReadAllText(configToLoad);
                using var doc = JsonDocument.Parse(jsonText);
                _config = doc.RootElement.Clone();
                _logger.LogInformation("Configuration successfully loaded from {path}", configToLoad);
                LogToFile("INFO", "Config loaded", $"Loaded configuration from {configToLoad}");
            }
            else
            {
                _logger.LogWarning("Configuration file not found. Using internal defaults.");
                using var doc = JsonDocument.Parse("{\"agent\":{\"heartbeatIntervalSeconds\":15}}");
                _config = doc.RootElement.Clone();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load configuration. Falling back to defaults.");
            LogToFile("ERROR", "Config load failed", ex.Message);
            using var doc = JsonDocument.Parse("{\"agent\":{\"heartbeatIntervalSeconds\":15}}");
            _config = doc.RootElement.Clone();
        }
    }

    private void InitializeLogging()
    {
        try
        {
            string logDir = Path.GetDirectoryName(_logFilePath)!;
            if (!Directory.Exists(logDir))
            {
                Directory.CreateDirectory(logDir);
            }

            LogToFile("INFO", "Logging init", "Local log directory and service log stream verified.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to initialize local log file directory.");
        }
    }

    private void InitializeDatabase()
    {
        try
        {
            string dbDir = Path.GetDirectoryName(_dbFilePath)!;
            if (!Directory.Exists(dbDir))
            {
                Directory.CreateDirectory(dbDir);
            }

            if (!File.Exists(_dbFilePath))
            {
                _logger.LogInformation("Database file does not exist yet. It will be initialized on first write.");
                LogToFile("INFO", "Database init", "Database path verified: " + _dbFilePath);
            }
            else
            {
                _logger.LogInformation("Verified SQLite database file presence at {path}", _dbFilePath);
                LogToFile("INFO", "Database init", "Existing SQLite database verified: " + _dbFilePath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to verify database file access.");
            LogToFile("ERROR", "Database check failed", ex.Message);
        }
    }

    private void WriteHealthStatus(string status, string message)
    {
        var statusObj = new
        {
            status,
            serviceName = "LocalEDR_Agent",
            processId = Environment.ProcessId,
            timestamp = DateTimeOffset.UtcNow.ToString("o"),
            message
        };
        WriteHealthReport(statusObj);
    }

    private void WriteHealthReport(object report)
    {
        try
        {
            string json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
            string tempFile = _healthFilePath + ".tmp";
            File.WriteAllText(tempFile, json);
            File.Move(tempFile, _healthFilePath, true);
        }
        catch
        {
            // Suppress disk contention during health file write
        }
    }

    private void LogToFile(string level, string eventName, string message)
    {
        try
        {
            string line = $"[{DateTimeOffset.UtcNow:o}] [{level.PadRight(5)}] [{eventName}] {message}{Environment.NewLine}";
            File.AppendAllText(_logFilePath, line, Encoding.UTF8);
        }
        catch
        {
            // Do not fault service if log file is temporarily locked
        }
    }
}
