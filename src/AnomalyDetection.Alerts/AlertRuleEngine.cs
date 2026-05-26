using AnomalyDetection.Contracts;

namespace AnomalyDetection.Alerts;

public sealed class AlertRuleEngine
{
    private readonly AlertRuleOptions _options;

    public AlertRuleEngine(AlertRuleOptions options)
    {
        _options = options;
    }

    public IReadOnlyList<AlertEvent> Evaluate(IReadOnlyCollection<DetectionSnapshot> detections)
    {
        if (detections.Count == 0)
        {
            return Array.Empty<AlertEvent>();
        }

        var alerts = new List<AlertEvent>();
        var ordered = detections.OrderBy(static detection => detection.Timestamp).ToArray();
        var anomalies = ordered.Where(static detection => detection.IsAnomaly).ToArray();

        foreach (var anomaly in anomalies)
        {
            alerts.Add(CreateSingleAnomalyAlert(anomaly));
        }

        var latestTimestamp = ordered[^1].Timestamp;
        var windowStart = latestTimestamp - _options.RuleWindow;
        var recent = ordered.Where(detection => detection.Timestamp >= windowStart).ToArray();
        var recentAnomalies = recent.Where(static detection => detection.IsAnomaly).ToArray();

        alerts.AddRange(CreateSourceSeriesAlerts(recentAnomalies));
        var rateAlert = CreateHighRateAlert(recent, recentAnomalies, latestTimestamp);
        if (rateAlert is not null)
        {
            alerts.Add(rateAlert);
        }

        return alerts
            .GroupBy(static alert => AlertKey.From(alert))
            .Select(static group => group.First())
            .OrderByDescending(static alert => alert.Timestamp)
            .ToArray();
    }

    private AlertEvent CreateSingleAnomalyAlert(DetectionSnapshot anomaly)
    {
        var ratio = ScoreRatio(anomaly);
        return new AlertEvent
        {
            Timestamp = anomaly.Timestamp,
            Severity = SeverityFromRatio(ratio),
            SourceIp = anomaly.SourceIp,
            DestinationIp = anomaly.DestinationIp,
            DestinationPort = anomaly.DestinationPort,
            Protocol = anomaly.Protocol,
            ReconstructionError = anomaly.ReconstructionError,
            Threshold = anomaly.Threshold,
            Message = "Anomalous traffic"
        };
    }

    private IEnumerable<AlertEvent> CreateSourceSeriesAlerts(IReadOnlyCollection<DetectionSnapshot> recentAnomalies)
    {
        return recentAnomalies
            .GroupBy(static detection => detection.SourceIp)
            .Where(group => group.Count() >= _options.SeriesAnomalyCount)
            .Select(group =>
            {
                var latest = group.OrderByDescending(static detection => detection.Timestamp).First();
                var count = group.Count();
                var maxRatio = group.Max(ScoreRatio);
                return new AlertEvent
                {
                    Timestamp = latest.Timestamp,
                    Severity = count >= _options.SeriesAnomalyCount * 2 || maxRatio >= _options.CriticalSeverityRatio
                        ? "critical"
                        : "high",
                    SourceIp = latest.SourceIp,
                    DestinationIp = "*",
                    DestinationPort = 0,
                    Protocol = "*",
                    ReconstructionError = latest.ReconstructionError,
                    Threshold = latest.Threshold,
                    Message = "Source anomaly activity"
                };
            });
    }

    private AlertEvent? CreateHighRateAlert(
        IReadOnlyCollection<DetectionSnapshot> recent,
        IReadOnlyCollection<DetectionSnapshot> recentAnomalies,
        DateTimeOffset latestTimestamp)
    {
        if (recent.Count < _options.HighRateMinimumWindows)
        {
            return null;
        }

        var rate = (double)recentAnomalies.Count / recent.Count;
        if (rate < _options.HighAnomalyRate)
        {
            return null;
        }

        var strongest = recentAnomalies
            .OrderByDescending(ScoreRatio)
            .FirstOrDefault();

        return new AlertEvent
        {
            Timestamp = latestTimestamp,
            Severity = rate >= _options.HighAnomalyRate * 2 ? "critical" : "high",
            SourceIp = "*",
            DestinationIp = "*",
            DestinationPort = 0,
            Protocol = "*",
            ReconstructionError = strongest?.ReconstructionError ?? 0,
            Threshold = strongest?.Threshold ?? 0,
            Message = "Elevated anomaly rate"
        };
    }

    private string SeverityFromRatio(double ratio)
    {
        if (ratio >= _options.CriticalSeverityRatio)
        {
            return "critical";
        }

        return ratio >= _options.HighSeverityRatio ? "high" : "medium";
    }

    private static double ScoreRatio(DetectionSnapshot detection)
    {
        return detection.Threshold > 0 ? detection.ReconstructionError / detection.Threshold : 0;
    }

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
    }
}
