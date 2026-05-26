namespace AnomalyDetection.Features;

public sealed record FeatureDefinition(
    string Name,
    int Order,
    string Kind,
    string? Source,
    string? Formula,
    string? Encoding,
    bool Log1P,
    bool NonNegative,
    bool Clip);
