using AnomalyDetection.Contracts;
using AnomalyDetection.Storage;
using System.Text.Json.Serialization;

namespace AnomalyDetection.Alerts;

public sealed class ClickHouseAlertMaterializer
{
    private readonly ClickHouseHttpClient _clickHouse;
    private readonly AlertRuleEngine _engine;

    public ClickHouseAlertMaterializer(ClickHouseHttpClient clickHouse, AlertRuleEngine engine)
    {
        _clickHouse = clickHouse;
        _engine = engine;
    }

    public async Task<AlertMaterializationResult> RunAsync(
        AlertMaterializationOptions options,
        CancellationToken cancellationToken = default)
    {
        await _clickHouse.InitializeSchemaAsync(cancellationToken);

        var detections = await ReadDetectionsAsync(options, cancellationToken);
        var candidates = _engine.Evaluate(detections);
        var existing = await ReadExistingKeysAsync(options, cancellationToken);
        var newAlerts = candidates
            .Where(alert => !existing.Contains(AlertKey.From(alert)))
            .Take(options.MaxAlertsToInsert)
            .ToArray();

        if (!options.DryRun)
        {
            await _clickHouse.InsertAlertsAsync(newAlerts, cancellationToken);
        }

        return new AlertMaterializationResult(
            DateTimeOffset.UtcNow,
            detections.Count,
            candidates.Count,
            newAlerts.Length,
            options.DryRun);
    }

    private async Task<IReadOnlyCollection<DetectionSnapshot>> ReadDetectionsAsync(
        AlertMaterializationOptions options,
        CancellationToken cancellationToken)
    {
        var where = options.LookbackHours > 0
            ? $"WHERE ts >= now() - INTERVAL {options.LookbackHours} HOUR"
            : string.Empty;

        var rows = await _clickHouse.QueryJsonEachRowAsync<DetectionRow>(
            $"""
            SELECT
                toUnixTimestamp64Milli(ts) AS timestamp_ms,
                src_ip,
                dst_ip,
                dst_port,
                proto,
                reconstruction_error,
                threshold,
                is_anomaly,
                model_version
            FROM anomaly_detections
            {where}
            ORDER BY ts DESC
            LIMIT {Math.Clamp(options.MaxDetections, 1, 1_000_000)}
            """,
            cancellationToken);

        return rows
            .Select(static row => new DetectionSnapshot(
                DateTimeOffset.FromUnixTimeMilliseconds(row.TimestampMs),
                row.SourceIp,
                row.DestinationIp,
                row.DestinationPort,
                row.Protocol,
                row.ReconstructionError,
                row.Threshold,
                row.IsAnomaly == 1,
                row.ModelVersion))
            .ToArray();
    }

    private async Task<IReadOnlySet<AlertKey>> ReadExistingKeysAsync(
        AlertMaterializationOptions options,
        CancellationToken cancellationToken)
    {
        var where = options.LookbackHours > 0
            ? $"WHERE ts >= now() - INTERVAL {options.LookbackHours} HOUR"
            : string.Empty;

        var rows = await _clickHouse.QueryJsonEachRowAsync<AlertRow>(
            $"""
            SELECT
                toUnixTimestamp64Milli(ts) AS timestamp_ms,
                severity,
                src_ip,
                dst_ip,
                dst_port,
                proto
            FROM anomaly_alerts
            {where}
            LIMIT 100000
            """,
            cancellationToken);

        return rows.Select(static row => AlertKey.From(row)).ToHashSet();
    }

    private sealed record DetectionRow(
        [property: JsonPropertyName("timestamp_ms")] long TimestampMs,
        [property: JsonPropertyName("src_ip")] string SourceIp,
        [property: JsonPropertyName("dst_ip")] string DestinationIp,
        [property: JsonPropertyName("dst_port")] int DestinationPort,
        [property: JsonPropertyName("proto")] string Protocol,
        [property: JsonPropertyName("reconstruction_error")] float ReconstructionError,
        [property: JsonPropertyName("threshold")] float Threshold,
        [property: JsonPropertyName("is_anomaly")] byte IsAnomaly,
        [property: JsonPropertyName("model_version")] string ModelVersion);

    private sealed record AlertRow(
        [property: JsonPropertyName("timestamp_ms")] long TimestampMs,
        [property: JsonPropertyName("severity")] string Severity,
        [property: JsonPropertyName("src_ip")] string SourceIp,
        [property: JsonPropertyName("dst_ip")] string DestinationIp,
        [property: JsonPropertyName("dst_port")] int DestinationPort,
        [property: JsonPropertyName("proto")] string Protocol);

    private sealed record AlertKey(
        DateTimeOffset Timestamp,
        string Severity,
        string SourceIp,
        string DestinationIp,
        int DestinationPort,
        string Protocol)
    {
        public static AlertKey From(AlertEvent alert)
        {
            return new AlertKey(
                alert.Timestamp,
                alert.Severity,
                alert.SourceIp,
                alert.DestinationIp,
                alert.DestinationPort,
                alert.Protocol);
        }

        public static AlertKey From(AlertRow row)
        {
            return new AlertKey(
                DateTimeOffset.FromUnixTimeMilliseconds(row.TimestampMs),
                row.Severity,
                row.SourceIp,
                row.DestinationIp,
                row.DestinationPort,
                row.Protocol);
        }
    }
}

public sealed record AlertMaterializationOptions(
    int LookbackHours = 0,
    int MaxDetections = 100_000,
    int MaxAlertsToInsert = 10_000,
    bool DryRun = false);

public sealed record AlertMaterializationResult(
    DateTimeOffset GeneratedAt,
    int DetectionsRead,
    int CandidateAlerts,
    int InsertedAlerts,
    bool DryRun);
