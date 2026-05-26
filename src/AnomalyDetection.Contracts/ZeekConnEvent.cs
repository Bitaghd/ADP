namespace AnomalyDetection.Contracts;

public sealed record ZeekConnEvent
{
    public DateTimeOffset Timestamp { get; init; }
    public string Uid { get; init; } = string.Empty;
    public string SourceIp { get; init; } = string.Empty;
    public int SourcePort { get; init; }
    public string DestinationIp { get; init; } = string.Empty;
    public int DestinationPort { get; init; }
    public string Protocol { get; init; } = "other";
    public string Service { get; init; } = "other";
    public string ConnState { get; init; } = "other";
    public double Duration { get; init; }
    public double OrigBytes { get; init; }
    public double RespBytes { get; init; }
    public double OrigPkts { get; init; }
    public double RespPkts { get; init; }
    public double OrigIpBytes { get; init; }
    public double RespIpBytes { get; init; }
    public double MissedBytes { get; init; }
    public string History { get; init; } = string.Empty;
    public string Label { get; init; } = "unknown";
    public bool IsAnomaly { get; init; }
}
