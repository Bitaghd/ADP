namespace AnomalyDetection.Api;

public sealed record OverviewQuery(int LookbackHours, int BucketMinutes);

public sealed record NetworkStatsQuery(int LookbackHours, int BucketMinutes);

public sealed record DetectionsQuery(
    int Limit,
    int Offset,
    bool AnomaliesOnly,
    int LookbackHours,
    string? SourceIp,
    string? DestinationIp,
    string? Protocol);

public sealed record AlertsQuery(
    int Limit,
    int Offset,
    int LookbackHours,
    string? Severity,
    bool UnacknowledgedOnly);

public sealed record OverviewResponse(
    DateTimeOffset GeneratedAt,
    int LookbackHours,
    int BucketMinutes,
    OverviewSummary Summary,
    IReadOnlyList<TimelineBucket> Timeline,
    IReadOnlyList<DimensionBreakdown> TopSources,
    IReadOnlyList<DimensionBreakdown> TopDestinations,
    IReadOnlyList<DimensionBreakdown> Protocols,
    IReadOnlyList<DetectionItem> LatestAnomalies);

public sealed record OverviewSummary(
    long TotalDetections,
    long Anomalies,
    double AnomalyRate,
    long DistinctSources,
    long DistinctDestinations,
    long ModelVersions,
    double AverageError,
    double AverageThreshold,
    double MaxError,
    double LatestThreshold,
    DateTimeOffset? EarliestTimestamp,
    DateTimeOffset? LatestTimestamp);

public sealed record TimelineBucket(
    DateTimeOffset Timestamp,
    long Total,
    long Anomalies,
    double AnomalyRate,
    double AverageError,
    double AverageThreshold);

public sealed record NetworkStatsResponse(
    DateTimeOffset GeneratedAt,
    int LookbackHours,
    int BucketMinutes,
    NetworkStatsSummary Summary,
    IReadOnlyList<NetworkTimelineBucket> Timeline,
    IReadOnlyList<NetworkDimensionBreakdown> Protocols,
    IReadOnlyList<NetworkDimensionBreakdown> TopSources,
    IReadOnlyList<NetworkDimensionBreakdown> TopDestinations);

public sealed record NetworkStatsSummary(
    long TotalFlows,
    double TotalBytes,
    double TotalPackets,
    double BytesPerSecond,
    double PacketsPerSecond,
    double FlowsPerSecond,
    long DistinctSources,
    long DistinctDestinations,
    DateTimeOffset? EarliestTimestamp,
    DateTimeOffset? LatestTimestamp);

public sealed record NetworkTimelineBucket(
    DateTimeOffset Timestamp,
    long Flows,
    double Bytes,
    double Packets,
    double BytesPerSecond,
    double PacketsPerSecond,
    double FlowsPerSecond);

public sealed record NetworkDimensionBreakdown(
    string Name,
    long Flows,
    double Bytes,
    double Packets,
    double ByteShare);

public sealed record DimensionBreakdown(
    string Name,
    long Total,
    long Anomalies,
    double AnomalyRate,
    double MaxError);

public sealed record DetectionPage(
    DateTimeOffset GeneratedAt,
    int Limit,
    int Offset,
    long Total,
    long TotalAnomalies,
    IReadOnlyList<DetectionItem> Items);

public sealed record DetectionItem(
    DateTimeOffset Timestamp,
    string SourceIp,
    string DestinationIp,
    int DestinationPort,
    string Protocol,
    double ReconstructionError,
    double Threshold,
    double? ScoreRatio,
    bool IsAnomaly,
    string Severity,
    string ThresholdMethod,
    string ModelVersion,
    int WindowSize,
    int Stride);

public sealed record AlertPage(
    DateTimeOffset GeneratedAt,
    int Limit,
    int Offset,
    AlertSummary Summary,
    IReadOnlyList<AlertItem> Items);

public sealed record AlertSummary(
    long Total,
    long Unacknowledged,
    long Critical,
    long High,
    long Medium);

public sealed record AlertItem(
    DateTimeOffset Timestamp,
    string Severity,
    string SourceIp,
    string DestinationIp,
    int DestinationPort,
    string Protocol,
    double ReconstructionError,
    double Threshold,
    double? ScoreRatio,
    string Message,
    bool Acknowledged);

public sealed record StorageStatus(
    bool Reachable,
    string Status,
    long TotalDetections,
    long TotalAnomalies,
    DateTimeOffset? LatestDetectionAt,
    double LatencyMs,
    string? Error);

public sealed record ArtifactStatus(
    string Label,
    string Path,
    bool Exists,
    long SizeBytes,
    DateTimeOffset? UpdatedAt);

public sealed record ThresholdStatus(
    string? ActiveMethod,
    double? Threshold,
    double? TargetRecall,
    string? ModelVersion,
    int FallbackMethodCount,
    bool AdaptiveEnabled,
    string? AdaptiveMethod,
    int? AdaptiveReferenceWindow,
    double? AdaptiveQuantile);

public sealed record TrainingStatus(
    DateTimeOffset? GeneratedAt,
    string? Device,
    long? WindowCount,
    long? NormalWindows,
    long? AnomalyWindows,
    int? WindowSize,
    int? FeatureCount,
    double? BestValidationLoss);

public sealed record ConfusionMatrix(long? TruePositive, long? FalsePositive, long? TrueNegative, long? FalseNegative);

public sealed record EvaluationStatus(
    DateTimeOffset? GeneratedAt,
    double? RocAuc,
    double? PrAuc,
    string? ActiveMethod,
    double? ActiveThreshold,
    double? Precision,
    double? Recall,
    double? F1,
    double? FalsePositiveRate,
    double? FalseDiscoveryRate,
    ConfusionMatrix? ConfusionMatrix);

public sealed record ModelStatusResponse(
    DateTimeOffset GeneratedAt,
    string Status,
    string? ModelVersion,
    ArtifactStatus ModelArtifact,
    ArtifactStatus ThresholdArtifact,
    ArtifactStatus TrainingReport,
    ArtifactStatus EvaluationReport,
    ArtifactStatus OnnxValidationReport,
    ArtifactStatus PreprocessingConfig,
    ThresholdStatus? Threshold,
    TrainingStatus? Training,
    EvaluationStatus? Evaluation,
    StorageStatus Storage);

public sealed record SystemLoadResponse(
    DateTimeOffset GeneratedAt,
    double? CpuPercent,
    double WorkingSetMb,
    double ManagedMemoryMb,
    int ThreadCount,
    int ProcessorCount,
    double UptimeSeconds);
