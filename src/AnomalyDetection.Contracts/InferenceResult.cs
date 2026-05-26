namespace AnomalyDetection.Contracts;

public sealed record InferenceResult
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required DateTimeOffset Timestamp { get; init; }
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required int DestinationPort { get; init; }
    public required string Protocol { get; init; }
    public required float ReconstructionError { get; init; }
    public required float Threshold { get; init; }
    public required bool IsAnomaly { get; init; }
    public bool? GroundTruthIsAnomaly { get; init; }
    public required string ThresholdMethod { get; init; }
    public required string ModelVersion { get; init; }
    public string? ContextKey { get; init; }
    public string? ParentContextKey { get; init; }
    public float? PValue { get; init; }
    public string? CalibrationDecision { get; init; }
    public string? CalibrationMode { get; init; }
    public float? EffectiveSampleSize { get; init; }
    public float? PMin { get; init; }
    public int? BankSize { get; init; }
    public int? TrustedBankSize { get; init; }
    public int? AdaptiveBankSize { get; init; }
    public bool? BankFrozen { get; init; }
    public string? FreezeReason { get; init; }
}
