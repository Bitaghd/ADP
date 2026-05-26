namespace AnomalyDetection.Contracts;

public sealed record AlertEvent
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required DateTimeOffset Timestamp { get; init; }
    public required string Severity { get; init; }
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required int DestinationPort { get; init; }
    public required string Protocol { get; init; }
    public required float ReconstructionError { get; init; }
    public required float Threshold { get; init; }
    public required string Message { get; init; }
    public bool Acknowledged { get; init; }
}
