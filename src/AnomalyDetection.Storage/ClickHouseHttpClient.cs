using System.Globalization;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AnomalyDetection.Contracts;

namespace AnomalyDetection.Storage;

public sealed class ClickHouseHttpClient : IDisposable
{
    private readonly ClickHouseOptions _options;
    private readonly HttpClient _client;
    private readonly bool _ownsClient;

    public ClickHouseHttpClient(ClickHouseOptions options, HttpClient? client = null)
    {
        _options = options;
        _client = client ?? new HttpClient();
        _ownsClient = client is null;
    }

    public async Task<bool> PingAsync(CancellationToken cancellationToken = default)
    {
        using var response = await _client.GetAsync(_options.BuildUri("SELECT 1"), cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        return response.IsSuccessStatusCode && body.Trim().Equals("1", StringComparison.OrdinalIgnoreCase);
    }

    public async Task ExecuteAsync(string sql, CancellationToken cancellationToken = default)
    {
        using var content = new StringContent(sql, Encoding.UTF8, "text/plain");
        using var response = await _client.PostAsync(_options.BuildUri(), content, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
    }

    public async Task InitializeSchemaAsync(CancellationToken cancellationToken = default)
    {
        foreach (var statement in ClickHouseSchema.Statements)
        {
            await ExecuteAsync(statement, cancellationToken);
        }
    }

    public async Task InsertDetectionsAsync(
        IReadOnlyCollection<InferenceResult> detections,
        int windowSize,
        int stride,
        CancellationToken cancellationToken = default)
    {
        if (detections.Count == 0)
        {
            return;
        }

        var builder = new StringBuilder("INSERT INTO anomaly_detections FORMAT JSONEachRow\n");
        foreach (var detection in detections)
        {
            var row = DetectionRow.From(detection, windowSize, stride);
            builder.Append(JsonSerializer.Serialize(row, JsonOptions.Default));
            builder.Append('\n');
        }

        using var content = new StringContent(builder.ToString(), Encoding.UTF8, "text/plain");
        using var response = await _client.PostAsync(_options.BuildUri(), content, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
    }

    public async Task InsertZeekEventsAsync(
        IReadOnlyCollection<ZeekConnEvent> events,
        CancellationToken cancellationToken = default)
    {
        if (events.Count == 0)
        {
            return;
        }

        var builder = new StringBuilder("INSERT INTO zeek_conn_events FORMAT JSONEachRow\n");
        foreach (var conn in events)
        {
            builder.Append(JsonSerializer.Serialize(ZeekConnRow.From(conn), JsonOptions.Default));
            builder.Append('\n');
        }

        using var content = new StringContent(builder.ToString(), Encoding.UTF8, "text/plain");
        using var response = await _client.PostAsync(_options.BuildUri(), content, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
    }

    public async Task InsertAlertsAsync(
        IReadOnlyCollection<AlertEvent> alerts,
        CancellationToken cancellationToken = default)
    {
        if (alerts.Count == 0)
        {
            return;
        }

        var builder = new StringBuilder("INSERT INTO anomaly_alerts FORMAT JSONEachRow\n");
        foreach (var alert in alerts)
        {
            builder.Append(JsonSerializer.Serialize(AlertRow.From(alert), JsonOptions.Default));
            builder.Append('\n');
        }

        using var content = new StringContent(builder.ToString(), Encoding.UTF8, "text/plain");
        using var response = await _client.PostAsync(_options.BuildUri(), content, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
    }

    public async Task<long> CountDetectionsAsync(CancellationToken cancellationToken = default)
    {
        using var content = new StringContent("SELECT count() FROM anomaly_detections", Encoding.UTF8, "text/plain");
        using var response = await _client.PostAsync(_options.BuildUri(), content, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        return long.TryParse(body.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var count) ? count : 0;
    }

    public async Task<IReadOnlyList<T>> QueryJsonEachRowAsync<T>(
        string sql,
        CancellationToken cancellationToken = default)
    {
        var query = EnsureJsonEachRowFormat(sql);
        using var content = new StringContent(query, Encoding.UTF8, "text/plain");
        using var response = await _client.PostAsync(_options.BuildUri(), content, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var rows = new List<T>();
        while (!reader.EndOfStream)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var line = await reader.ReadLineAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var row = JsonSerializer.Deserialize<T>(line, JsonOptions.Read);
            if (row is not null)
            {
                rows.Add(row);
            }
        }

        return rows;
    }

    public void Dispose()
    {
        if (_ownsClient)
        {
            _client.Dispose();
        }
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        throw new HttpRequestException($"ClickHouse request failed: {(int)response.StatusCode} {response.ReasonPhrase}\n{body}");
    }

    private static string EnsureJsonEachRowFormat(string sql)
    {
        var query = sql.Trim().TrimEnd(';');
        return query.Contains("FORMAT JSONEachRow", StringComparison.OrdinalIgnoreCase)
            ? query
            : $"{query}\nFORMAT JSONEachRow";
    }

    private sealed record DetectionRow(
        [property: JsonPropertyName("ts")] string Timestamp,
        [property: JsonPropertyName("src_ip")] string SourceIp,
        [property: JsonPropertyName("dst_ip")] string DestinationIp,
        [property: JsonPropertyName("dst_port")] int DestinationPort,
        [property: JsonPropertyName("proto")] string Protocol,
        [property: JsonPropertyName("reconstruction_error")] float ReconstructionError,
        [property: JsonPropertyName("threshold")] float Threshold,
        [property: JsonPropertyName("is_anomaly")] byte IsAnomaly,
        [property: JsonPropertyName("threshold_method")] string ThresholdMethod,
        [property: JsonPropertyName("model_version")] string ModelVersion,
        [property: JsonPropertyName("context_key")] string ContextKey,
        [property: JsonPropertyName("parent_context_key")] string ParentContextKey,
        [property: JsonPropertyName("p_value")] float? PValue,
        [property: JsonPropertyName("calibration_decision")] string CalibrationDecision,
        [property: JsonPropertyName("calibration_mode")] string CalibrationMode,
        [property: JsonPropertyName("effective_sample_size")] float? EffectiveSampleSize,
        [property: JsonPropertyName("p_min")] float? PMin,
        [property: JsonPropertyName("bank_size")] int? BankSize,
        [property: JsonPropertyName("trusted_bank_size")] int? TrustedBankSize,
        [property: JsonPropertyName("adaptive_bank_size")] int? AdaptiveBankSize,
        [property: JsonPropertyName("bank_frozen")] byte BankFrozen,
        [property: JsonPropertyName("freeze_reason")] string FreezeReason,
        [property: JsonPropertyName("window_size")] int WindowSize,
        [property: JsonPropertyName("stride")] int Stride)
    {
        public static DetectionRow From(InferenceResult result, int windowSize, int stride)
        {
            return new DetectionRow(
                result.Timestamp.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
                result.SourceIp,
                result.DestinationIp,
                result.DestinationPort,
                result.Protocol,
                result.ReconstructionError,
                result.Threshold,
                result.IsAnomaly ? (byte)1 : (byte)0,
                result.ThresholdMethod,
                result.ModelVersion,
                result.ContextKey ?? string.Empty,
                result.ParentContextKey ?? string.Empty,
                result.PValue,
                result.CalibrationDecision ?? string.Empty,
                result.CalibrationMode ?? string.Empty,
                result.EffectiveSampleSize,
                result.PMin,
                result.BankSize,
                result.TrustedBankSize,
                result.AdaptiveBankSize,
                result.BankFrozen is true ? (byte)1 : (byte)0,
                result.FreezeReason ?? string.Empty,
                windowSize,
                stride);
        }
    }

    private sealed record ZeekConnRow(
        [property: JsonPropertyName("ts")] string Timestamp,
        [property: JsonPropertyName("uid")] string Uid,
        [property: JsonPropertyName("src_ip")] string SourceIp,
        [property: JsonPropertyName("src_port")] int SourcePort,
        [property: JsonPropertyName("dst_ip")] string DestinationIp,
        [property: JsonPropertyName("dst_port")] int DestinationPort,
        [property: JsonPropertyName("proto")] string Protocol,
        [property: JsonPropertyName("service")] string Service,
        [property: JsonPropertyName("duration")] double Duration,
        [property: JsonPropertyName("orig_bytes")] double OrigBytes,
        [property: JsonPropertyName("resp_bytes")] double RespBytes,
        [property: JsonPropertyName("orig_pkts")] double OrigPkts,
        [property: JsonPropertyName("resp_pkts")] double RespPkts,
        [property: JsonPropertyName("orig_ip_bytes")] double OrigIpBytes,
        [property: JsonPropertyName("resp_ip_bytes")] double RespIpBytes,
        [property: JsonPropertyName("conn_state")] string ConnState,
        [property: JsonPropertyName("history")] string History)
    {
        public static ZeekConnRow From(ZeekConnEvent conn)
        {
            return new ZeekConnRow(
                conn.Timestamp.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
                conn.Uid,
                conn.SourceIp,
                ClampPort(conn.SourcePort),
                conn.DestinationIp,
                ClampPort(conn.DestinationPort),
                Normalize(conn.Protocol, "other"),
                Normalize(conn.Service, "other"),
                NonNegative(conn.Duration),
                NonNegative(conn.OrigBytes),
                NonNegative(conn.RespBytes),
                NonNegative(conn.OrigPkts),
                NonNegative(conn.RespPkts),
                NonNegative(conn.OrigIpBytes),
                NonNegative(conn.RespIpBytes),
                Normalize(conn.ConnState, "other"),
                conn.History ?? string.Empty);
        }

        private static int ClampPort(int port)
        {
            return Math.Clamp(port, 0, 65535);
        }

        private static double NonNegative(double value)
        {
            return double.IsFinite(value) ? Math.Max(value, 0) : 0;
        }

        private static string Normalize(string value, string fallback)
        {
            return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
        }
    }

    private sealed record AlertRow(
        [property: JsonPropertyName("ts")] string Timestamp,
        [property: JsonPropertyName("severity")] string Severity,
        [property: JsonPropertyName("src_ip")] string SourceIp,
        [property: JsonPropertyName("dst_ip")] string DestinationIp,
        [property: JsonPropertyName("dst_port")] int DestinationPort,
        [property: JsonPropertyName("proto")] string Protocol,
        [property: JsonPropertyName("reconstruction_error")] float ReconstructionError,
        [property: JsonPropertyName("threshold")] float Threshold,
        [property: JsonPropertyName("message")] string Message,
        [property: JsonPropertyName("acknowledged")] byte Acknowledged)
    {
        public static AlertRow From(AlertEvent alert)
        {
            return new AlertRow(
                alert.Timestamp.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
                alert.Severity,
                alert.SourceIp,
                alert.DestinationIp,
                alert.DestinationPort,
                alert.Protocol,
                alert.ReconstructionError,
                alert.Threshold,
                alert.Message,
                alert.Acknowledged ? (byte)1 : (byte)0);
        }
    }

    private static class JsonOptions
    {
        public static readonly JsonSerializerOptions Default = new()
        {
            PropertyNamingPolicy = null
        };

        public static readonly JsonSerializerOptions Read = new()
        {
            NumberHandling = JsonNumberHandling.AllowReadingFromString,
            PropertyNameCaseInsensitive = true
        };
    }
}
