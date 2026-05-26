namespace AnomalyDetection.Contracts;

public sealed record TrafficWindow
{
    public required DateTimeOffset EndTimestamp { get; init; }
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required int DestinationPort { get; init; }
    public required string Protocol { get; init; }
    public required string Service { get; init; }
    public required int WindowSize { get; init; }
    public required int FeatureCount { get; init; }
    public required IReadOnlyList<string> FeatureNames { get; init; }
    public required float[] Values { get; init; }
    public required bool IsAnomaly { get; init; }

    public static TrafficWindow FromVectors(IReadOnlyList<FeatureVector> vectors)
    {
        if (vectors.Count == 0)
        {
            throw new ArgumentException("At least one feature vector is required.", nameof(vectors));
        }

        var first = vectors[0];
        var featureCount = first.Values.Length;
        var values = new float[vectors.Count * featureCount];

        for (var row = 0; row < vectors.Count; row++)
        {
            if (vectors[row].Values.Length != featureCount)
            {
                throw new InvalidOperationException("All feature vectors in a window must have the same width.");
            }

            Array.Copy(vectors[row].Values, 0, values, row * featureCount, featureCount);
        }

        var last = vectors[^1];
        return new TrafficWindow
        {
            EndTimestamp = last.Timestamp,
            SourceIp = last.SourceIp,
            DestinationIp = last.DestinationIp,
            DestinationPort = last.DestinationPort,
            Protocol = last.Protocol,
            Service = last.Service,
            WindowSize = vectors.Count,
            FeatureCount = featureCount,
            FeatureNames = first.FeatureNames,
            Values = values,
            IsAnomaly = vectors.Any(vector => vector.IsAnomaly)
        };
    }
}
