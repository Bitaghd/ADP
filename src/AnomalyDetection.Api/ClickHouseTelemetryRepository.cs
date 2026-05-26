using AnomalyDetection.Storage;
using System.Diagnostics;
using System.Text.Json.Serialization;

namespace AnomalyDetection.Api;

public sealed class ClickHouseTelemetryRepository
{
    private const string NetworkBytesExpression =
        "if(greatest(orig_ip_bytes, 0) + greatest(resp_ip_bytes, 0) > 0, greatest(orig_ip_bytes, 0) + greatest(resp_ip_bytes, 0), greatest(orig_bytes, 0) + greatest(resp_bytes, 0))";
    private const string NetworkPacketsExpression = "greatest(orig_pkts, 0) + greatest(resp_pkts, 0)";

    private readonly ClickHouseHttpClient _clickHouse;

    public ClickHouseTelemetryRepository(ClickHouseHttpClient clickHouse)
    {
        _clickHouse = clickHouse;
    }

    public async Task<OverviewResponse> GetOverviewAsync(
        OverviewQuery query,
        CancellationToken cancellationToken = default)
    {
        var lookbackHours = Math.Clamp(query.LookbackHours, 0, 24 * 365 * 20);
        var bucketMinutes = Math.Clamp(query.BucketMinutes, 1, 24 * 60);
        var where = BuildWhere(lookbackHours);

        var summaryRows = await _clickHouse.QueryJsonEachRowAsync<SummaryRow>(
            $"""
            SELECT
                count() AS total,
                countIf(is_anomaly = 1) AS anomalies,
                if(count() = 0, 0, countIf(is_anomaly = 1) / count()) AS anomaly_rate,
                uniqExact(src_ip) AS distinct_sources,
                uniqExact(dst_ip) AS distinct_destinations,
                uniqExact(model_version) AS model_versions,
                if(count() = 0, 0, avg(reconstruction_error)) AS avg_error,
                if(count() = 0, 0, avg(threshold)) AS avg_threshold,
                if(count() = 0, 0, max(reconstruction_error)) AS max_error,
                if(count() = 0, 0, argMax(threshold, ts)) AS latest_threshold,
                if(count() = 0, 0, toUnixTimestamp64Milli(min(ts))) AS earliest_ms,
                if(count() = 0, 0, toUnixTimestamp64Milli(max(ts))) AS latest_ms
            FROM anomaly_detections
            {where}
            """,
            cancellationToken);

        var summary = (summaryRows.FirstOrDefault() ?? SummaryRow.Empty).ToDto();

        var timeline = await QueryTimelineAsync(where, bucketMinutes, cancellationToken);
        var topSources = await QueryDimensionAsync("src_ip", where, 8, cancellationToken);
        var topDestinations = await QueryDimensionAsync("concat(dst_ip, ':', toString(dst_port))", where, 8, cancellationToken);
        var protocols = await QueryDimensionAsync("proto", where, 8, cancellationToken);
        var latestAnomalies = await GetDetectionsAsync(
            new DetectionsQuery(6, 0, AnomaliesOnly: true, lookbackHours, null, null, null),
            cancellationToken);

        return new OverviewResponse(
            DateTimeOffset.UtcNow,
            lookbackHours,
            bucketMinutes,
            summary,
            timeline,
            topSources,
            topDestinations,
            protocols,
            latestAnomalies.Items);
    }

    public async Task<NetworkStatsResponse> GetNetworkStatsAsync(
        NetworkStatsQuery query,
        CancellationToken cancellationToken = default)
    {
        var lookbackHours = Math.Clamp(query.LookbackHours, 0, 24 * 365 * 20);
        var bucketMinutes = Math.Clamp(query.BucketMinutes, 1, 24 * 60);
        var where = BuildNetworkWhere(lookbackHours);

        var summaryRows = await _clickHouse.QueryJsonEachRowAsync<NetworkSummaryRow>(
            $"""
            SELECT
                count() AS total_flows,
                if(count() = 0, 0, sum({NetworkBytesExpression})) AS total_bytes,
                if(count() = 0, 0, sum({NetworkPacketsExpression})) AS total_packets,
                uniqExact(src_ip) AS distinct_sources,
                uniqExact(dst_ip) AS distinct_destinations,
                if(count() = 0, 0, toUnixTimestamp64Milli(min(ts))) AS earliest_ms,
                if(count() = 0, 0, toUnixTimestamp64Milli(max(ts))) AS latest_ms
            FROM zeek_conn_events
            {where}
            """,
            cancellationToken);

        var summary = (summaryRows.FirstOrDefault() ?? NetworkSummaryRow.Empty).ToDto();
        var timeline = await QueryNetworkTimelineAsync(where, bucketMinutes, cancellationToken);
        var protocols = await QueryNetworkDimensionAsync("proto", where, 8, summary.TotalBytes, cancellationToken);
        var topSources = await QueryNetworkDimensionAsync("src_ip", where, 8, summary.TotalBytes, cancellationToken);
        var topDestinations = await QueryNetworkDimensionAsync("concat(dst_ip, ':', toString(dst_port))", where, 8, summary.TotalBytes, cancellationToken);

        return new NetworkStatsResponse(
            DateTimeOffset.UtcNow,
            lookbackHours,
            bucketMinutes,
            summary,
            timeline,
            protocols,
            topSources,
            topDestinations);
    }

    public async Task<DetectionPage> GetDetectionsAsync(
        DetectionsQuery query,
        CancellationToken cancellationToken = default)
    {
        var limit = Math.Clamp(query.Limit, 1, 500);
        var offset = Math.Clamp(query.Offset, 0, 100_000);
        var lookbackHours = Math.Clamp(query.LookbackHours, 0, 24 * 365 * 20);
        var where = BuildWhere(
            lookbackHours,
            query.AnomaliesOnly,
            query.SourceIp,
            query.DestinationIp,
            query.Protocol);

        var countRows = await _clickHouse.QueryJsonEachRowAsync<CountRow>(
            $"""
            SELECT
                count() AS total,
                countIf(is_anomaly = 1) AS anomalies
            FROM anomaly_detections
            {where}
            """,
            cancellationToken);

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
                threshold_method,
                model_version,
                window_size,
                stride
            FROM anomaly_detections
            {where}
            ORDER BY ts DESC
            LIMIT {limit}
            OFFSET {offset}
            """,
            cancellationToken);

        var totals = countRows.FirstOrDefault() ?? new CountRow(0, 0);
        return new DetectionPage(
            DateTimeOffset.UtcNow,
            limit,
            offset,
            totals.Total,
            totals.Anomalies,
            rows.Select(static row => row.ToDto()).ToArray());
    }

    public async Task<AlertPage> GetAlertsAsync(
        AlertsQuery query,
        CancellationToken cancellationToken = default)
    {
        var limit = Math.Clamp(query.Limit, 1, 5_000);
        var offset = Math.Clamp(query.Offset, 0, 100_000);
        var lookbackHours = Math.Clamp(query.LookbackHours, 0, 24 * 365 * 20);
        var where = BuildAlertWhere(
            lookbackHours,
            query.Severity,
            query.UnacknowledgedOnly);

        var summaryRows = await _clickHouse.QueryJsonEachRowAsync<AlertSummaryRow>(
            $"""
            SELECT
                count() AS total,
                countIf(acknowledged = 0) AS unacknowledged,
                countIf(severity = 'critical') AS critical,
                countIf(severity = 'high') AS high,
                countIf(severity = 'medium') AS medium
            FROM anomaly_alerts
            {where}
            """,
            cancellationToken);

        var rows = await _clickHouse.QueryJsonEachRowAsync<AlertRow>(
            $"""
            SELECT
                toUnixTimestamp64Milli(ts) AS timestamp_ms,
                severity,
                src_ip,
                dst_ip,
                dst_port,
                proto,
                reconstruction_error,
                threshold,
                message,
                acknowledged
            FROM anomaly_alerts
            {where}
            ORDER BY acknowledged ASC, ts DESC, severity ASC
            LIMIT {limit}
            OFFSET {offset}
            """,
            cancellationToken);

        return new AlertPage(
            DateTimeOffset.UtcNow,
            limit,
            offset,
            (summaryRows.FirstOrDefault() ?? AlertSummaryRow.Empty).ToDto(),
            rows.Select(static row => row.ToDto()).ToArray());
    }

    public async Task<StorageStatus> GetStorageStatusAsync(CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            var reachable = await _clickHouse.PingAsync(cancellationToken);
            if (!reachable)
            {
                return new StorageStatus(false, "offline", 0, 0, null, stopwatch.Elapsed.TotalMilliseconds, null);
            }

            var summaryRows = await _clickHouse.QueryJsonEachRowAsync<SummaryRow>(
                """
                SELECT
                    count() AS total,
                    countIf(is_anomaly = 1) AS anomalies,
                    if(count() = 0, 0, countIf(is_anomaly = 1) / count()) AS anomaly_rate,
                    uniqExact(src_ip) AS distinct_sources,
                    uniqExact(dst_ip) AS distinct_destinations,
                    uniqExact(model_version) AS model_versions,
                    if(count() = 0, 0, avg(reconstruction_error)) AS avg_error,
                    if(count() = 0, 0, avg(threshold)) AS avg_threshold,
                    if(count() = 0, 0, max(reconstruction_error)) AS max_error,
                    if(count() = 0, 0, argMax(threshold, ts)) AS latest_threshold,
                    if(count() = 0, 0, toUnixTimestamp64Milli(min(ts))) AS earliest_ms,
                    if(count() = 0, 0, toUnixTimestamp64Milli(max(ts))) AS latest_ms
                FROM anomaly_detections
                """,
                cancellationToken);

            var summary = (summaryRows.FirstOrDefault() ?? SummaryRow.Empty).ToDto();
            return new StorageStatus(
                true,
                "online",
                summary.TotalDetections,
                summary.Anomalies,
                summary.LatestTimestamp,
                stopwatch.Elapsed.TotalMilliseconds,
                null);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            return new StorageStatus(false, "offline", 0, 0, null, stopwatch.Elapsed.TotalMilliseconds, exception.Message);
        }
    }

    private async Task<IReadOnlyList<TimelineBucket>> QueryTimelineAsync(
        string where,
        int bucketMinutes,
        CancellationToken cancellationToken)
    {
        var rows = await _clickHouse.QueryJsonEachRowAsync<TimelineRow>(
            $"""
            SELECT
                toUnixTimestamp(toStartOfInterval(ts, INTERVAL {bucketMinutes} MINUTE)) * 1000 AS bucket_ms,
                count() AS total,
                countIf(is_anomaly = 1) AS anomalies,
                if(count() = 0, 0, countIf(is_anomaly = 1) / count()) AS anomaly_rate,
                if(count() = 0, 0, avg(reconstruction_error)) AS avg_error,
                if(count() = 0, 0, avg(threshold)) AS avg_threshold
            FROM anomaly_detections
            {where}
            GROUP BY bucket_ms
            ORDER BY bucket_ms ASC
            LIMIT 240
            """,
            cancellationToken);

        return rows.Select(static row => row.ToDto()).ToArray();
    }

    private async Task<IReadOnlyList<NetworkTimelineBucket>> QueryNetworkTimelineAsync(
        string where,
        int bucketMinutes,
        CancellationToken cancellationToken)
    {
        var rows = await _clickHouse.QueryJsonEachRowAsync<NetworkTimelineRow>(
            $"""
            SELECT
                toUnixTimestamp(toStartOfInterval(ts, INTERVAL {bucketMinutes} MINUTE)) * 1000 AS bucket_ms,
                count() AS flows,
                if(count() = 0, 0, sum({NetworkBytesExpression})) AS bytes,
                if(count() = 0, 0, sum({NetworkPacketsExpression})) AS packets
            FROM zeek_conn_events
            {where}
            GROUP BY bucket_ms
            ORDER BY bucket_ms ASC
            LIMIT 240
            """,
            cancellationToken);

        return rows.Select(row => row.ToDto(bucketMinutes)).ToArray();
    }

    private async Task<IReadOnlyList<DimensionBreakdown>> QueryDimensionAsync(
        string expression,
        string where,
        int limit,
        CancellationToken cancellationToken)
    {
        var rows = await _clickHouse.QueryJsonEachRowAsync<DimensionRow>(
            $"""
            SELECT
                {expression} AS name,
                count() AS total,
                countIf(is_anomaly = 1) AS anomalies,
                if(count() = 0, 0, countIf(is_anomaly = 1) / count()) AS anomaly_rate,
                if(count() = 0, 0, max(reconstruction_error)) AS max_error
            FROM anomaly_detections
            {where}
            GROUP BY name
            ORDER BY anomalies DESC, total DESC, max_error DESC
            LIMIT {Math.Clamp(limit, 1, 50)}
            """,
            cancellationToken);

        return rows.Select(static row => new DimensionBreakdown(
            string.IsNullOrWhiteSpace(row.Name) ? "(empty)" : row.Name,
            row.Total,
            row.Anomalies,
            row.AnomalyRate,
            row.MaxError)).ToArray();
    }

    private async Task<IReadOnlyList<NetworkDimensionBreakdown>> QueryNetworkDimensionAsync(
        string expression,
        string where,
        int limit,
        double totalBytes,
        CancellationToken cancellationToken)
    {
        var rows = await _clickHouse.QueryJsonEachRowAsync<NetworkDimensionRow>(
            $"""
            SELECT
                {expression} AS name,
                count() AS flows,
                if(count() = 0, 0, sum({NetworkBytesExpression})) AS bytes,
                if(count() = 0, 0, sum({NetworkPacketsExpression})) AS packets
            FROM zeek_conn_events
            {where}
            GROUP BY name
            ORDER BY bytes DESC, flows DESC
            LIMIT {Math.Clamp(limit, 1, 50)}
            """,
            cancellationToken);

        return rows.Select(row => new NetworkDimensionBreakdown(
            string.IsNullOrWhiteSpace(row.Name) ? "(empty)" : row.Name,
            row.Flows,
            row.Bytes,
            row.Packets,
            totalBytes > 0 ? row.Bytes / totalBytes : 0)).ToArray();
    }

    private static string BuildWhere(
        int lookbackHours,
        bool anomaliesOnly = false,
        string? sourceIp = null,
        string? destinationIp = null,
        string? protocol = null)
    {
        var filters = new List<string>();
        if (lookbackHours > 0)
        {
            filters.Add($"ts >= now() - INTERVAL {lookbackHours} HOUR");
        }

        if (anomaliesOnly)
        {
            filters.Add("is_anomaly = 1");
        }

        if (!string.IsNullOrWhiteSpace(sourceIp))
        {
            filters.Add($"src_ip = {SqlString(sourceIp)}");
        }

        if (!string.IsNullOrWhiteSpace(destinationIp))
        {
            filters.Add($"dst_ip = {SqlString(destinationIp)}");
        }

        if (!string.IsNullOrWhiteSpace(protocol))
        {
            filters.Add($"proto = {SqlString(protocol.ToLowerInvariant())}");
        }

        return filters.Count == 0 ? string.Empty : $"WHERE {string.Join(" AND ", filters)}";
    }

    private static string BuildNetworkWhere(int lookbackHours)
    {
        return lookbackHours > 0
            ? $"WHERE ts >= now() - INTERVAL {lookbackHours} HOUR"
            : string.Empty;
    }

    private static string BuildAlertWhere(
        int lookbackHours,
        string? severity = null,
        bool unacknowledgedOnly = false)
    {
        var filters = new List<string>();
        if (lookbackHours > 0)
        {
            filters.Add($"ts >= now() - INTERVAL {lookbackHours} HOUR");
        }

        if (!string.IsNullOrWhiteSpace(severity))
        {
            filters.Add($"severity = {SqlString(severity.ToLowerInvariant())}");
        }

        if (unacknowledgedOnly)
        {
            filters.Add("acknowledged = 0");
        }

        return filters.Count == 0 ? string.Empty : $"WHERE {string.Join(" AND ", filters)}";
    }

    private static string SqlString(string value)
    {
        return $"'{value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("'", "\\'", StringComparison.Ordinal)}'";
    }

    private static DateTimeOffset? Timestamp(long milliseconds)
    {
        return milliseconds <= 0 ? null : DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);
    }

    private sealed record SummaryRow(
        [property: JsonPropertyName("total")] long Total,
        [property: JsonPropertyName("anomalies")] long Anomalies,
        [property: JsonPropertyName("anomaly_rate")] double AnomalyRate,
        [property: JsonPropertyName("distinct_sources")] long DistinctSources,
        [property: JsonPropertyName("distinct_destinations")] long DistinctDestinations,
        [property: JsonPropertyName("model_versions")] long ModelVersions,
        [property: JsonPropertyName("avg_error")] double AverageError,
        [property: JsonPropertyName("avg_threshold")] double AverageThreshold,
        [property: JsonPropertyName("max_error")] double MaxError,
        [property: JsonPropertyName("latest_threshold")] double LatestThreshold,
        [property: JsonPropertyName("earliest_ms")] long EarliestMs,
        [property: JsonPropertyName("latest_ms")] long LatestMs)
    {
        public static readonly SummaryRow Empty = new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

        public OverviewSummary ToDto()
        {
            return new OverviewSummary(
                Total,
                Anomalies,
                AnomalyRate,
                DistinctSources,
                DistinctDestinations,
                ModelVersions,
                AverageError,
                AverageThreshold,
                MaxError,
                LatestThreshold,
                Timestamp(EarliestMs),
                Timestamp(LatestMs));
        }
    }

    private sealed record CountRow(
        [property: JsonPropertyName("total")] long Total,
        [property: JsonPropertyName("anomalies")] long Anomalies);

    private sealed record AlertSummaryRow(
        [property: JsonPropertyName("total")] long Total,
        [property: JsonPropertyName("unacknowledged")] long Unacknowledged,
        [property: JsonPropertyName("critical")] long Critical,
        [property: JsonPropertyName("high")] long High,
        [property: JsonPropertyName("medium")] long Medium)
    {
        public static readonly AlertSummaryRow Empty = new(0, 0, 0, 0, 0);

        public AlertSummary ToDto()
        {
            return new AlertSummary(Total, Unacknowledged, Critical, High, Medium);
        }
    }

    private sealed record TimelineRow(
        [property: JsonPropertyName("bucket_ms")] long BucketMs,
        [property: JsonPropertyName("total")] long Total,
        [property: JsonPropertyName("anomalies")] long Anomalies,
        [property: JsonPropertyName("anomaly_rate")] double AnomalyRate,
        [property: JsonPropertyName("avg_error")] double AverageError,
        [property: JsonPropertyName("avg_threshold")] double AverageThreshold)
    {
        public TimelineBucket ToDto()
        {
            return new TimelineBucket(
                Timestamp(BucketMs) ?? DateTimeOffset.UnixEpoch,
                Total,
                Anomalies,
                AnomalyRate,
                AverageError,
                AverageThreshold);
        }
    }

    private sealed record NetworkSummaryRow(
        [property: JsonPropertyName("total_flows")] long TotalFlows,
        [property: JsonPropertyName("total_bytes")] double TotalBytes,
        [property: JsonPropertyName("total_packets")] double TotalPackets,
        [property: JsonPropertyName("distinct_sources")] long DistinctSources,
        [property: JsonPropertyName("distinct_destinations")] long DistinctDestinations,
        [property: JsonPropertyName("earliest_ms")] long EarliestMs,
        [property: JsonPropertyName("latest_ms")] long LatestMs)
    {
        public static readonly NetworkSummaryRow Empty = new(0, 0, 0, 0, 0, 0, 0);

        public NetworkStatsSummary ToDto()
        {
            var earliest = Timestamp(EarliestMs);
            var latest = Timestamp(LatestMs);
            var seconds = earliest is not null && latest is not null
                ? Math.Max(1, (latest.Value - earliest.Value).TotalSeconds)
                : 0;

            return new NetworkStatsSummary(
                TotalFlows,
                TotalBytes,
                TotalPackets,
                seconds > 0 ? TotalBytes / seconds : 0,
                seconds > 0 ? TotalPackets / seconds : 0,
                seconds > 0 ? TotalFlows / seconds : 0,
                DistinctSources,
                DistinctDestinations,
                earliest,
                latest);
        }
    }

    private sealed record NetworkTimelineRow(
        [property: JsonPropertyName("bucket_ms")] long BucketMs,
        [property: JsonPropertyName("flows")] long Flows,
        [property: JsonPropertyName("bytes")] double Bytes,
        [property: JsonPropertyName("packets")] double Packets)
    {
        public NetworkTimelineBucket ToDto(int bucketMinutes)
        {
            var seconds = Math.Max(1, bucketMinutes * 60);
            return new NetworkTimelineBucket(
                Timestamp(BucketMs) ?? DateTimeOffset.UnixEpoch,
                Flows,
                Bytes,
                Packets,
                Bytes / seconds,
                Packets / seconds,
                Flows / (double)seconds);
        }
    }

    private sealed record NetworkDimensionRow(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("flows")] long Flows,
        [property: JsonPropertyName("bytes")] double Bytes,
        [property: JsonPropertyName("packets")] double Packets);

    private sealed record DimensionRow(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("total")] long Total,
        [property: JsonPropertyName("anomalies")] long Anomalies,
        [property: JsonPropertyName("anomaly_rate")] double AnomalyRate,
        [property: JsonPropertyName("max_error")] double MaxError);

    private sealed record DetectionRow(
        [property: JsonPropertyName("timestamp_ms")] long TimestampMs,
        [property: JsonPropertyName("src_ip")] string SourceIp,
        [property: JsonPropertyName("dst_ip")] string DestinationIp,
        [property: JsonPropertyName("dst_port")] int DestinationPort,
        [property: JsonPropertyName("proto")] string Protocol,
        [property: JsonPropertyName("reconstruction_error")] double ReconstructionError,
        [property: JsonPropertyName("threshold")] double Threshold,
        [property: JsonPropertyName("is_anomaly")] byte IsAnomaly,
        [property: JsonPropertyName("threshold_method")] string ThresholdMethod,
        [property: JsonPropertyName("model_version")] string ModelVersion,
        [property: JsonPropertyName("window_size")] int WindowSize,
        [property: JsonPropertyName("stride")] int Stride)
    {
        public DetectionItem ToDto()
        {
            var ratio = Threshold > 0 ? ReconstructionError / Threshold : (double?)null;
            return new DetectionItem(
                Timestamp(TimestampMs) ?? DateTimeOffset.UnixEpoch,
                SourceIp,
                DestinationIp,
                DestinationPort,
                Protocol,
                ReconstructionError,
                Threshold,
                ratio,
                IsAnomaly == 1,
                GetSeverity(IsAnomaly == 1, ratio),
                ThresholdMethod,
                ModelVersion,
                WindowSize,
                Stride);
        }

        private static string GetSeverity(bool isAnomaly, double? ratio)
        {
            if (!isAnomaly)
            {
                return "normal";
            }

            if (ratio >= 2)
            {
                return "critical";
            }

            return ratio >= 1.25 ? "high" : "medium";
        }
    }

    private sealed record AlertRow(
        [property: JsonPropertyName("timestamp_ms")] long TimestampMs,
        [property: JsonPropertyName("severity")] string Severity,
        [property: JsonPropertyName("src_ip")] string SourceIp,
        [property: JsonPropertyName("dst_ip")] string DestinationIp,
        [property: JsonPropertyName("dst_port")] int DestinationPort,
        [property: JsonPropertyName("proto")] string Protocol,
        [property: JsonPropertyName("reconstruction_error")] double ReconstructionError,
        [property: JsonPropertyName("threshold")] double Threshold,
        [property: JsonPropertyName("message")] string Message,
        [property: JsonPropertyName("acknowledged")] byte Acknowledged)
    {
        public AlertItem ToDto()
        {
            var ratio = Threshold > 0 ? ReconstructionError / Threshold : (double?)null;
            return new AlertItem(
                Timestamp(TimestampMs) ?? DateTimeOffset.UnixEpoch,
                Severity,
                SourceIp,
                DestinationIp,
                DestinationPort,
                Protocol,
                ReconstructionError,
                Threshold,
                ratio,
                Message,
                Acknowledged == 1);
        }
    }
}
