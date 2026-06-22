using System.Runtime.CompilerServices;
using System.Text.Json;
using Confluent.Kafka;

var options = CollectorOptions.Parse(args);
if (options is null)
{
    CollectorOptions.PrintUsage();
    return 2;
}

using var shutdown = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    shutdown.Cancel();
};

var config = new ProducerConfig
{
    BootstrapServers = options.BootstrapServers,
    Acks = Acks.All,
    EnableIdempotence = true
};
config.Set("broker.address.family", options.KafkaAddressFamily);

var produced = 0;
var skipped = 0;
var startedAt = DateTimeOffset.UtcNow;
using var producer = new ProducerBuilder<Null, string>(config).Build();

try
{
    await foreach (var line in ReadInputLinesAsync(options, shutdown.Token))
    {
        if (string.IsNullOrWhiteSpace(line) || line[0] == '#')
        {
            skipped++;
            continue;
        }

        await producer.ProduceAsync(options.Topic, new Message<Null, string> { Value = line }, shutdown.Token);
        produced++;
        if (options.MaxEvents > 0 && produced >= options.MaxEvents)
        {
            break;
        }
    }
}
catch (OperationCanceledException)
{
    // Ctrl+C should flush and return a useful summary instead of a stack trace.
}

producer.Flush(TimeSpan.FromSeconds(10));
Console.WriteLine(JsonSerializer.Serialize(new
{
    produced,
    skipped,
    options.Topic,
    options.BootstrapServers,
    options.Follow,
    options.FromEnd,
    elapsed_seconds = Math.Round((DateTimeOffset.UtcNow - startedAt).TotalSeconds, 3)
}));
return 0;

static async IAsyncEnumerable<string> ReadInputLinesAsync(
    CollectorOptions options,
    [EnumeratorCancellation] CancellationToken cancellationToken)
{
    if (!options.Follow)
    {
        foreach (var line in File.ReadLines(options.ConnLog))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return line;
            await Task.Yield();
        }

        yield break;
    }

    await foreach (var line in FollowFileAsync(options, cancellationToken))
    {
        yield return line;
    }
}

static async IAsyncEnumerable<string> FollowFileAsync(
    CollectorOptions options,
    [EnumeratorCancellation] CancellationToken cancellationToken)
{
    var path = Path.GetFullPath(options.ConnLog);
    var pollInterval = TimeSpan.FromMilliseconds(options.PollIntervalMilliseconds);
    var idleDeadline = BuildIdleDeadline(options);
    FileStream? stream = null;
    StreamReader? reader = null;

    try
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            if (reader is null)
            {
                if (!File.Exists(path))
                {
                    if (!options.WaitForFile)
                    {
                        throw new FileNotFoundException("conn.log was not found.", path);
                    }

                    if (IdleExpired(idleDeadline))
                    {
                        yield break;
                    }

                    await Task.Delay(pollInterval, cancellationToken);
                    continue;
                }

                stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (options.FromEnd)
                {
                    stream.Seek(0, SeekOrigin.End);
                }

                reader = new StreamReader(stream);
            }

            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is not null)
            {
                idleDeadline = BuildIdleDeadline(options);
                yield return line;
                continue;
            }

            if (stream is not null && File.Exists(path))
            {
                var currentLength = new FileInfo(path).Length;
                if (currentLength < stream.Position)
                {
                    reader.Dispose();
                    stream.Dispose();
                    reader = null;
                    stream = null;
                    continue;
                }
            }

            if (IdleExpired(idleDeadline))
            {
                yield break;
            }

            await Task.Delay(pollInterval, cancellationToken);
        }
    }
    finally
    {
        reader?.Dispose();
        stream?.Dispose();
    }
}

static DateTimeOffset? BuildIdleDeadline(CollectorOptions options)
{
    return options.IdleTimeoutSeconds > 0
        ? DateTimeOffset.UtcNow.AddSeconds(options.IdleTimeoutSeconds)
        : null;
}

static bool IdleExpired(DateTimeOffset? idleDeadline)
{
    return idleDeadline is not null && DateTimeOffset.UtcNow >= idleDeadline;
}

internal sealed record CollectorOptions(
    string ConnLog,
    string BootstrapServers,
    string Topic,
    int MaxEvents,
    bool Follow,
    bool FromEnd,
    bool WaitForFile,
    int PollIntervalMilliseconds,
    int IdleTimeoutSeconds,
    string KafkaAddressFamily)
{
    public static CollectorOptions? Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "follow",
            "from-end",
            "wait-for-file"
        };

        for (var index = 0; index < args.Length; index++)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            var key = args[index][2..];
            if (flags.Contains(key))
            {
                values[key] = "true";
                continue;
            }

            if (index + 1 >= args.Length)
            {
                return null;
            }

            values[key] = args[++index];
        }

        if (!values.TryGetValue("conn-log", out var connLog))
        {
            return null;
        }

        return new CollectorOptions(
            connLog,
            values.GetValueOrDefault("kafka-bootstrap", "localhost:9092"),
            values.GetValueOrDefault("topic", "zeek.conn.raw"),
            ParseInt(values, "max-events", 0),
            ParseBool(values, "follow", false),
            ParseBool(values, "from-end", false),
            ParseBool(values, "wait-for-file", false),
            ParseInt(values, "poll-ms", 500),
            ParseInt(values, "idle-timeout-seconds", 0),
            values.GetValueOrDefault("kafka-address-family", "v4"));
    }

    public static void PrintUsage()
    {
        Console.WriteLine(
            """
            Usage:
              dotnet run --project src\AnomalyDetection.Collector -- \
                --conn-log artifacts\zeek\example\conn.log \
                --kafka-bootstrap localhost:9092 \
                --topic zeek.conn.raw

            Live tail mode:
              dotnet run --project src\AnomalyDetection.Collector -- \
                --conn-log C:\zeek-live\conn.log \
                --follow \
                --from-end \
                --wait-for-file \
                --kafka-bootstrap localhost:9092 \
                --kafka-address-family v4 \
                --topic zeek.conn.raw

            Test-friendly follow mode:
              dotnet run --project src\AnomalyDetection.Collector -- \
                --conn-log artifacts\zeek\example\conn.log \
                --follow \
                --idle-timeout-seconds 3 \
                --max-events 100
            """);
    }

    private static int ParseInt(IReadOnlyDictionary<string, string> values, string key, int defaultValue)
    {
        return values.TryGetValue(key, out var raw) && int.TryParse(raw, out var value) ? value : defaultValue;
    }

    private static bool ParseBool(IReadOnlyDictionary<string, string> values, string key, bool defaultValue)
    {
        return values.TryGetValue(key, out var raw) && bool.TryParse(raw, out var value) ? value : defaultValue;
    }
}
