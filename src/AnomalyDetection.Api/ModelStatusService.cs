using System.Text.Json;

namespace AnomalyDetection.Api;

public sealed class ModelStatusService
{
    private readonly ModelStatusOptions _options;

    public ModelStatusService(ModelStatusOptions options)
    {
        _options = options;
    }

    public async Task<ModelStatusResponse> GetStatusAsync(
        ClickHouseTelemetryRepository repository,
        CancellationToken cancellationToken = default)
    {
        var model = GetArtifact("ONNX model", _options.ModelPath);
        var thresholdArtifact = GetArtifact("Threshold config", _options.ThresholdConfigPath);
        var trainingArtifact = GetArtifact("Training report", _options.TrainingReportPath);
        var evaluationArtifact = GetArtifact("Evaluation report", _options.EvaluationReportPath);
        var onnxValidationArtifact = GetArtifact("ONNX validation", _options.OnnxValidationReportPath);
        var preprocessingArtifact = GetArtifact("Preprocessing config", _options.PreprocessingConfigPath);

        var threshold = ReadThreshold(_options.ThresholdConfigPath);
        var training = ReadTraining(_options.TrainingReportPath);
        var evaluation = ReadEvaluation(_options.EvaluationReportPath);
        var storage = await repository.GetStorageStatusAsync(cancellationToken);
        var modelVersion = threshold?.ModelVersion ?? Path.GetFileNameWithoutExtension(_options.ModelPath);

        var status = model.Exists && thresholdArtifact.Exists && storage.Reachable
            ? "ready"
            : model.Exists && thresholdArtifact.Exists
                ? "degraded"
                : "missing_artifacts";

        return new ModelStatusResponse(
            DateTimeOffset.UtcNow,
            status,
            modelVersion,
            model,
            thresholdArtifact,
            trainingArtifact,
            evaluationArtifact,
            onnxValidationArtifact,
            preprocessingArtifact,
            threshold,
            training,
            evaluation,
            storage);
    }

    private static ArtifactStatus GetArtifact(string label, string path)
    {
        var file = new FileInfo(path);
        return new ArtifactStatus(
            label,
            path,
            file.Exists,
            file.Exists ? file.Length : 0,
            file.Exists ? new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero) : null);
    }

    private static ThresholdStatus? ReadThreshold(string path)
    {
        using var document = TryOpenJson(path);
        if (document is null)
        {
            return null;
        }

        var root = document.RootElement;
        var adaptive = root.TryGetProperty("adaptive", out var adaptiveValue) && adaptiveValue.ValueKind == JsonValueKind.Object
            ? adaptiveValue
            : default;
        var hasAdaptive = adaptive.ValueKind == JsonValueKind.Object;
        return new ThresholdStatus(
            GetString(root, "active_method"),
            GetDouble(root, "threshold"),
            GetDouble(root, "target_recall"),
            GetString(root, "model_version"),
            root.TryGetProperty("fallback_methods", out var fallbackMethods) && fallbackMethods.ValueKind == JsonValueKind.Object
                ? fallbackMethods.EnumerateObject().Count()
                : 0,
            hasAdaptive && GetBool(adaptive, "enabled") == true,
            hasAdaptive ? GetString(adaptive, "method") : null,
            hasAdaptive ? GetInt(adaptive, "reference_window") : null,
            hasAdaptive ? GetDouble(adaptive, "quantile") : null);
    }

    private static TrainingStatus? ReadTraining(string path)
    {
        using var document = TryOpenJson(path);
        if (document is null)
        {
            return null;
        }

        var root = document.RootElement;
        return new TrainingStatus(
            GetTimestamp(root, "generated_at"),
            GetString(root, "device"),
            GetLong(root, "window_count"),
            GetLong(root, "normal_windows"),
            GetLong(root, "anomaly_windows"),
            GetInt(root, "window_size"),
            GetInt(root, "feature_count"),
            GetDouble(root, "best_val_loss"));
    }

    private static EvaluationStatus? ReadEvaluation(string path)
    {
        using var document = TryOpenJson(path);
        if (document is null)
        {
            return null;
        }

        var root = document.RootElement;
        var metrics = root.TryGetProperty("active_metrics", out var value) ? value : default;
        var hasMetrics = metrics.ValueKind == JsonValueKind.Object;
        var confusion = hasMetrics
            ? new ConfusionMatrix(
                GetLong(metrics, "tp"),
                GetLong(metrics, "fp"),
                GetLong(metrics, "tn"),
                GetLong(metrics, "fn"))
            : null;

        return new EvaluationStatus(
            GetTimestamp(root, "generated_at"),
            GetDouble(root, "roc_auc"),
            GetDouble(root, "pr_auc"),
            GetString(root, "active_method"),
            GetDouble(root, "active_threshold"),
            hasMetrics ? GetDouble(metrics, "precision") : null,
            hasMetrics ? GetDouble(metrics, "recall") : null,
            hasMetrics ? GetDouble(metrics, "f1") : null,
            hasMetrics ? GetDouble(metrics, "fpr") : null,
            hasMetrics ? GetDouble(metrics, "fdr") : null,
            confusion);
    }

    private static JsonDocument? TryOpenJson(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            return JsonDocument.Parse(File.ReadAllText(path));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static double? GetDouble(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Number
            ? value.GetDouble()
            : null;
    }

    private static long? GetLong(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Number
            ? value.GetInt64()
            : null;
    }

    private static int? GetInt(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Number
            ? value.GetInt32()
            : null;
    }

    private static bool? GetBool(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }

    private static DateTimeOffset? GetTimestamp(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value)
            && value.ValueKind == JsonValueKind.String
            && DateTimeOffset.TryParse(value.GetString(), out var timestamp)
                ? timestamp
                : null;
    }
}
