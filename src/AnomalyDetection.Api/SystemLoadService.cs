using System.Diagnostics;

namespace AnomalyDetection.Api;

public sealed class SystemLoadService
{
    private readonly object _gate = new();
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;
    private DateTimeOffset _lastSampledAt = DateTimeOffset.UtcNow;
    private TimeSpan _lastProcessorTime = Process.GetCurrentProcess().TotalProcessorTime;
    private double? _lastCpuPercent;

    public SystemLoadResponse GetSnapshot()
    {
        using var process = Process.GetCurrentProcess();
        var now = DateTimeOffset.UtcNow;
        var processorTime = process.TotalProcessorTime;
        double? cpuPercent;

        lock (_gate)
        {
            var elapsedSeconds = (now - _lastSampledAt).TotalSeconds;
            var cpuSeconds = (processorTime - _lastProcessorTime).TotalSeconds;
            cpuPercent = elapsedSeconds > 0
                ? Math.Clamp(cpuSeconds / elapsedSeconds / Math.Max(1, Environment.ProcessorCount) * 100, 0, 100)
                : _lastCpuPercent;

            _lastSampledAt = now;
            _lastProcessorTime = processorTime;
            _lastCpuPercent = cpuPercent;
        }

        return new SystemLoadResponse(
            now,
            cpuPercent,
            process.WorkingSet64 / 1024d / 1024d,
            GC.GetTotalMemory(forceFullCollection: false) / 1024d / 1024d,
            process.Threads.Count,
            Environment.ProcessorCount,
            (now - _startedAt).TotalSeconds);
    }
}
