namespace AnomalyDetection.Contracts;

public sealed record FeatureVector
{
    public required DateTimeOffset Timestamp { get; init; }
    public required string Uid { get; init; }
    public required string SourceIp { get; init; }
    public required int SourcePort { get; init; }
    public required string DestinationIp { get; init; }
    public required int DestinationPort { get; init; }
    public required string Protocol { get; init; }
    public required string Service { get; init; }
    public required string Label { get; init; }
    public required bool IsAnomaly { get; init; }
    public required IReadOnlyList<string> FeatureNames { get; init; }
    public required float[] Values { get; init; }

    public float GetValue(string featureName)
    {
        var index = -1;
        for (var candidate = 0; candidate < FeatureNames.Count; candidate++)
        {
            if (string.Equals(FeatureNames[candidate], featureName, StringComparison.Ordinal))
            {
                index = candidate;
                break;
            }
        }

        if (index < 0)
        {
            throw new KeyNotFoundException($"Feature not found: {featureName}");
        }

        return Values[index];
    }
}
