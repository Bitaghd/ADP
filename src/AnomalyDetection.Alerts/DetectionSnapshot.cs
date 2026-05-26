namespace AnomalyDetection.Alerts;

public sealed record DetectionSnapshot(
    DateTimeOffset Timestamp,
    string SourceIp,
    string DestinationIp,
    int DestinationPort,
    string Protocol,
    float ReconstructionError,
    float Threshold,
    bool IsAnomaly,
    string ModelVersion);
