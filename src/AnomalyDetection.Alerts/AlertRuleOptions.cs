namespace AnomalyDetection.Alerts;

public sealed record AlertRuleOptions(
    int RuleWindowMinutes = 15,
    int SeriesAnomalyCount = 3,
    int HighRateMinimumWindows = 20,
    double HighAnomalyRate = 0.2,
    double HighSeverityRatio = 1.25,
    double CriticalSeverityRatio = 2.0)
{
    public TimeSpan RuleWindow => TimeSpan.FromMinutes(Math.Clamp(RuleWindowMinutes, 1, 24 * 60));
}
