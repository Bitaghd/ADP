using AnomalyDetection.Alerts;
using AnomalyDetection.Storage;
using System.Globalization;
using System.Text.Json;

var options = AlertOptions.Parse(args);
if (options is null)
{
    AlertOptions.PrintUsage();
    return 2;
}

using var clickHouse = new ClickHouseHttpClient(new ClickHouseOptions(
    options.ClickHouseUrl,
    options.ClickHouseDatabase,
    options.ClickHouseUser,
    options.ClickHousePassword));

var engine = new AlertRuleEngine(new AlertRuleOptions(
    options.RuleWindowMinutes,
    options.SeriesAnomalyCount,
    options.HighRateMinimumWindows,
    options.HighAnomalyRate));
var materializer = new ClickHouseAlertMaterializer(clickHouse, engine);
var result = await materializer.RunAsync(new AlertMaterializationOptions(
    options.LookbackHours,
    options.MaxDetections,
    options.MaxAlertsToInsert,
    options.DryRun));

Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
return 0;

internal sealed record AlertOptions(
    string ClickHouseUrl,
    string ClickHouseDatabase,
    string ClickHouseUser,
    string ClickHousePassword,
    int LookbackHours,
    int MaxDetections,
    int MaxAlertsToInsert,
    int RuleWindowMinutes,
    int SeriesAnomalyCount,
    int HighRateMinimumWindows,
    double HighAnomalyRate,
    bool DryRun)
{
    public static AlertOptions? Parse(string[] args)
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
            if (key.Equals("dry-run", StringComparison.OrdinalIgnoreCase))
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

        return new AlertOptions(
            values.GetValueOrDefault("clickhouse-url", "http://localhost:8123"),
            values.GetValueOrDefault("clickhouse-database", "default"),
            values.GetValueOrDefault("clickhouse-user", "default"),
            values.GetValueOrDefault("clickhouse-password", "adp"),
            ParseInt(values, "lookback-hours", 0),
            ParseInt(values, "max-detections", 100_000),
            ParseInt(values, "max-alerts-to-insert", 10_000),
            ParseInt(values, "rule-window-minutes", 15),
            ParseInt(values, "series-anomaly-count", 3),
            ParseInt(values, "high-rate-minimum-windows", 20),
            ParseDouble(values, "high-anomaly-rate", 0.2),
            values.TryGetValue("dry-run", out var dryRun) && bool.TryParse(dryRun, out var enabled) && enabled);
    }

    public static void PrintUsage()
    {
        Console.WriteLine(
            """
            Usage:
              dotnet run --project src\AnomalyDetection.Alerts -- \
                --clickhouse-url http://localhost:8123 \
                --clickhouse-user default \
                --clickhouse-password adp

            Optional:
              --lookback-hours 24
              --rule-window-minutes 15
              --series-anomaly-count 3
              --high-anomaly-rate 0.2
              --dry-run
            """);
    }

    private static int ParseInt(IReadOnlyDictionary<string, string> values, string key, int defaultValue)
    {
        return values.TryGetValue(key, out var raw) && int.TryParse(raw, out var value) ? value : defaultValue;
    }

    private static double ParseDouble(IReadOnlyDictionary<string, string> values, string key, double defaultValue)
    {
        return values.TryGetValue(key, out var raw)
            && double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var value)
                ? value
                : defaultValue;
    }
}
