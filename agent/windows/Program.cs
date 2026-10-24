namespace LocalEDR.Agent;

using System;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

public class Program
{
    public static void Main(string[] args)
    {
        // Set current directory to base directory so relative paths (config/, data/) resolve correctly when run as a Windows Service
        Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

        var builder = Host.CreateApplicationBuilder(args);

        // Configure as a native Windows Service
        // Integrates with Service Control Manager (SCM), handling Start, Stop, and PreShutdown
        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName = "LocalEDR_Agent";
        });

        // Initialize Logging System
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();

        if (OperatingSystem.IsWindows())
        {
            builder.Logging.AddEventLog(settings =>
            {
                settings.SourceName = "LocalEDR";
                settings.LogName = "Application";
            });
        }

        // Register the Core Windows Service Worker
        builder.Services.AddHostedService<Worker>();

        var host = builder.Build();
        host.Run();
    }
}
