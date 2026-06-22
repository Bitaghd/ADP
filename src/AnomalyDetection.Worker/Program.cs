using System.Diagnostics;
using System.Text.Json;
using AnomalyDetection.Contracts;
using AnomalyDetection.Features;
using AnomalyDetection.Inference;
using AnomalyDetection.Storage;
using AnomalyDetection.Windowing;
using Confluent.Kafka;

var options = ReplayOptions.Parse(args);
if (options is null)
{
    ReplayOptions.PrintUsage();
    return 2;
}

Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(options.Output)) ?? ".");

var schema = FeatureSchema.Load(options.Schema);
var extractor = new FeatureExtractor(schema);
var preprocessor = FeaturePreprocessor.Load(options.Scaler);
using var runner = new OnnxModelRunner(options.Model);
var threshold = ThresholdConfig.Load(options.Threshold);
var evaluator = new ThresholdEvaluator(threshold);
var buffer = new FlowWindowBuffer(options.WindowSize, options.Stride, TimeSpan.FromSeconds(options.MaxWindowAgeSeconds));
ClickHouseHttpClient? clickHouse = null;
var clickHouseBatch = new List<InferenceResult>(options.ClickHouseBatchSize);
var zeekClickHouseBatch = new List<ZeekConnEvent>(options.ClickHouseBatchSize);
var clickHouseInserted = 0;
var zeekClickHouseInserted = 0;

if (!string.IsNullOrWhiteSpace(options.ClickHouseUrl))
{
    clickHouse = new ClickHouseHttpClient(
        new ClickHouseOptions(
            options.ClickHouseUrl,
            options.ClickHouseDatabase,
            options.ClickHouseUser,
            options.ClickHousePassword));
    await clickHouse.InitializeSchemaAsync();
}

var processedEvents = 0;
var producedWindows = 0;
var anomalies = 0;
var jsonOptions = new JsonSerializerOptions { WriteIndented = false };
var stopwatch = Stopwatch.StartNew();

await using var writer = new StreamWriter(options.Output, append: false);
try
{
    foreach (var line in ReadInputLines(options))
    {
        if (string.IsNullOrWhiteSpace(line) || line[0] == '#')
        {
            continue;
        }

        var conn = ZeekConnJsonParser.ParseLine(line);
        if (clickHouse is not null)
        {
            zeekClickHouseBatch.Add(conn);
            if (zeekClickHouseBatch.Count >= options.ClickHouseBatchSize)
            {
                zeekClickHouseInserted += await FlushZeekClickHouseAsync(clickHouse, zeekClickHouseBatch);
            }
        }

        var vector = preprocessor.Transform(extractor.Extract(conn));
        foreach (var window in buffer.Add(vector))
        {
            var error = runner.Score(window);
            var result = evaluator.Evaluate(window, error);
            if (result.IsAnomaly)
            {
                anomalies++;
            }

            producedWindows++;
            await writer.WriteLineAsync(JsonSerializer.Serialize(result, jsonOptions));

            if (clickHouse is not null)
            {
                clickHouseBatch.Add(result);
                if (clickHouseBatch.Count >= options.ClickHouseBatchSize)
                {
                    clickHouseInserted += await FlushClickHouseAsync(clickHouse, clickHouseBatch, options);
                }
            }
        }

        processedEvents++;
        if (options.MaxEvents > 0 && processedEvents >= options.MaxEvents)
        {
            break;
        }
    }

    if (clickHouse is not null)
    {
        zeekClickHouseInserted += await FlushZeekClickHouseAsync(clickHouse, zeekClickHouseBatch);
        clickHouseInserted += await FlushClickHouseAsync(clickHouse, clickHouseBatch, options);
    }
}
finally
{
    clickHouse?.Dispose();
}
stopwatch.Stop();

var summary = new
{
    processed_events = processedEvents,
    windows = producedWindows,
    anomalies,
    elapsed_ms = stopwatch.Elapsed.TotalMilliseconds,
    events_per_second = stopwatch.Elapsed.TotalSeconds > 0 ? processedEvents / stopwatch.Elapsed.TotalSeconds : 0,
    windows_per_second = stopwatch.Elapsed.TotalSeconds > 0 ? producedWindows / stopwatch.Elapsed.TotalSeconds : 0,
    output = options.Output,
    clickhouse_enabled = clickHouse is not null,
    clickhouse_inserted = clickHouseInserted,
    clickhouse_zeek_inserted = zeekClickHouseInserted
};
Console.WriteLine(JsonSerializer.Serialize(summary));
return 0;

static async Task<int> FlushClickHouseAsync(
    ClickHouseHttpClient clickHouse,
    List<InferenceResult> batch,
    ReplayOptions options)
{
    if (batch.Count == 0)
    {
        return 0;
    }

    await clickHouse.InsertDetectionsAsync(batch, options.WindowSize, options.Stride);
    var inserted = batch.Count;
    batch.Clear();
    return inserted;
}

static async Task<int> FlushZeekClickHouseAsync(
    ClickHouseHttpClient clickHouse,
    List<ZeekConnEvent> batch)
{
    if (batch.Count == 0)
    {
        return 0;
    }

    await clickHouse.InsertZeekEventsAsync(batch);
    var inserted = batch.Count;
    batch.Clear();
    return inserted;
}

static IEnumerable<string> ReadInputLines(ReplayOptions options)
{
    if (!string.IsNullOrWhiteSpace(options.KafkaBootstrapServers))
    {
        return ReadKafkaLines(options);
    }

    if (string.IsNullOrWhiteSpace(options.ConnLog))
    {
        throw new ArgumentException("Either --conn-log or --kafka-bootstrap must be provided.");
    }

    return File.ReadLines(options.ConnLog);
}

static IEnumerable<string> ReadKafkaLines(ReplayOptions options)
{
    var config = new ConsumerConfig
    {
        BootstrapServers = options.KafkaBootstrapServers,
        GroupId = options.KafkaGroupId,
        AutoOffsetReset = AutoOffsetReset.Earliest,
        EnableAutoCommit = false,
        EnablePartitionEof = true
    };
    config.Set("broker.address.family", options.KafkaAddressFamily);

    using var consumer = new ConsumerBuilder<Ignore, string>(config).Build();
    consumer.Subscribe(options.KafkaTopic);
    var idleDeadline = BuildKafkaIdleDeadline(options);
    try
    {
        while (idleDeadline is null || DateTimeOffset.UtcNow < idleDeadline.Value)
        {
            var result = consumer.Consume(TimeSpan.FromMilliseconds(500));
            if (result is null)
            {
                continue;
            }

            if (result.IsPartitionEOF)
            {
                continue;
            }

            idleDeadline = BuildKafkaIdleDeadline(options);
            yield return result.Message.Value;
            try
            {
                consumer.Commit(result);
            }
            catch (KafkaException exception)
            {
                Console.Error.WriteLine($"Kafka offset commit failed: {exception.Error.Reason}");
            }
        }
    }
    finally
    {
        consumer.Close();
    }
}

static DateTimeOffset? BuildKafkaIdleDeadline(ReplayOptions options)
{
    return options.KafkaIdleTimeoutSeconds > 0
        ? DateTimeOffset.UtcNow.AddSeconds(options.KafkaIdleTimeoutSeconds)
        : null;
}

internal sealed record ReplayOptions(
    string? ConnLog,
    string Schema,
    string Scaler,
    string Threshold,
    string Model,
    string Output,
    string? ClickHouseUrl,
    string ClickHouseDatabase,
    string ClickHouseUser,
    string ClickHousePassword,
    int ClickHouseBatchSize,
    string? KafkaBootstrapServers,
    string KafkaTopic,
    string KafkaGroupId,
    string KafkaAddressFamily,
    int KafkaIdleTimeoutSeconds,
    int WindowSize,
    int Stride,
    int MaxWindowAgeSeconds,
    int MaxEvents)
{
    public static ReplayOptions? Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index++)
        {
            var arg = args[index];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            var key = arg[2..];
            if (index + 1 >= args.Length)
            {
                return null;
            }

            values[key] = args[++index];
        }

        string? Required(string key) => values.TryGetValue(key, out var value) ? value : null;
        var connLog = Required("conn-log");
        var scaler = Required("scaler");
        var threshold = Required("threshold");
        var model = Required("model");
        var output = Required("output");
        var kafkaBootstrap = values.GetValueOrDefault("kafka-bootstrap");
        if ((connLog is null && kafkaBootstrap is null) || scaler is null || threshold is null || model is null || output is null)
        {
            return null;
        }

        return new ReplayOptions(
            connLog,
            values.GetValueOrDefault("schema", Path.Combine("configs", "feature_schema.json")),
            scaler,
            threshold,
            model,
            output,
            values.GetValueOrDefault("clickhouse-url"),
            values.GetValueOrDefault("clickhouse-database", "default"),
            values.GetValueOrDefault("clickhouse-user", "default"),
            values.GetValueOrDefault("clickhouse-password", "adp"),
            ParseInt(values, "clickhouse-batch-size", 500),
            kafkaBootstrap,
            values.GetValueOrDefault("kafka-topic", "zeek.conn.raw"),
            values.GetValueOrDefault("kafka-group-id", $"adp-worker-{Guid.NewGuid():N}"),
            values.GetValueOrDefault("kafka-address-family", "v4"),
            ParseInt(values, "kafka-idle-timeout-seconds", 5),
            ParseInt(values, "window-size", 10),
            ParseInt(values, "stride", 1),
            ParseInt(values, "max-window-age-seconds", 300),
            ParseInt(values, "max-events", 0));
    }

    public static void PrintUsage()
    {
        Console.WriteLine(
            """
            Usage:
              dotnet run --project src\AnomalyDetection.Worker -- \
                --conn-log artifacts\zeek\example\conn.log \
                --scaler artifacts\scalers\example.scaler.json \
                --threshold artifacts\thresholds\example.threshold_config.json \
                --model models\cnn_gru_ae_example.onnx \
                --output artifacts\runtime\example.detections.jsonl \
                --clickhouse-url http://localhost:8123 \
                --clickhouse-user default \
                --clickhouse-password adp

              dotnet run --project src\AnomalyDetection.Worker -- \
                --kafka-bootstrap localhost:9092 \
                --kafka-topic zeek.conn.raw \
                --kafka-address-family v4 \
                --kafka-idle-timeout-seconds 0 \
                --max-events 674 \
                --scaler artifacts\scalers\example.scaler.json \
                --threshold artifacts\thresholds\example.threshold_config.json \
                --model models\cnn_gru_ae_example.onnx \
                --output artifacts\runtime\example.kafka.detections.jsonl \
                --clickhouse-url http://localhost:8123
            """);
    }

    private static int ParseInt(IReadOnlyDictionary<string, string> values, string key, int defaultValue)
    {
        return values.TryGetValue(key, out var raw) && int.TryParse(raw, out var value) ? value : defaultValue;
    }
}
