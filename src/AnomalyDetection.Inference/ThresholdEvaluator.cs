using System.Text.Json;
using AnomalyDetection.Contracts;

namespace AnomalyDetection.Inference;

public sealed record ThresholdConfig(
    string ActiveMethod,
    float Threshold,
    string ModelVersion = "not_trained",
    AdaptiveThresholdConfig? Adaptive = null)
{
    public static ThresholdConfig Load(string path)
    {
        using var stream = File.OpenRead(path);
        using var document = JsonDocument.Parse(stream);
        var root = document.RootElement;
        return new ThresholdConfig(
            root.TryGetProperty("active_method", out var method) ? method.GetString() ?? "unknown" : "unknown",
            root.TryGetProperty("threshold", out var threshold) ? threshold.GetSingle() : 0f,
            root.TryGetProperty("model_version", out var version) ? version.GetString() ?? "not_trained" : "not_trained",
            root.TryGetProperty("adaptive", out var adaptive) && adaptive.ValueKind == JsonValueKind.Object
                ? AdaptiveThresholdConfig.Load(adaptive)
                : AdaptiveThresholdConfig.Disabled);
    }
}

public sealed record AdaptiveThresholdConfig(
    bool Enabled = false,
    string Method = "rolling_quantile_mad",
    int WarmupWindows = 128,
    int ReferenceWindow = 512,
    float Quantile = 0.99f,
    float MadMultiplier = 6f,
    float SmoothingAlpha = 0.05f,
    float MinThresholdMultiplier = 0.5f,
    float MaxThresholdMultiplier = 3f,
    bool UpdateOnAnomalies = false,
    bool ShadowMode = true,
    float Alpha = 0.01f,
    float TriageBeta = 0.1f,
    int BankSize = 2048,
    int MinEffectiveSampleSize = 100,
    int RecencyHalfLifeWindows = 1024,
    float WeightClipMin = 0.25f,
    float WeightClipMax = 4f,
    int PendingDelayWindows = 30,
    int PendingFlushWindows = 5,
    int MonitorWindow = 256,
    float BurstAlertRate = 0.2f,
    float DriftScoreMeanRatio = 2f,
    int FreezeDurationWindows = 512,
    int TrustedBankSize = 0,
    int AdaptiveBankSize = 0,
    int TrustedWarmupWindows = 0,
    float TrustedSampleWeight = 1f,
    float AdaptiveSampleWeight = 0.1f,
    string TrustedSeedPath = "",
    float ThresholdQuantile = 0f,
    string PValueMode = "upper_tail",
    bool DecayTrustedSeed = false,
    bool RelaxPMinForContext = true,
    bool UseStaticThresholdSafetyNet = false,
    float StaticSafetyNetMaxPValue = 0.2f,
    bool RollingUseContext = false,
    bool RollingUseTrustedSeed = false,
    bool RollingUseDelayedAdmission = false,
    bool RollingUseFreeze = false,
    bool RollingUseAsymmetricSmoothing = false,
    float SmoothingAlphaUp = 0.05f,
    float SmoothingAlphaDown = 0.01f,
    bool CsUseChangeDetection = true,
    int CsMinRecentWindows = 64,
    bool CsResetToRecent = true)
{
    public static AdaptiveThresholdConfig Disabled { get; } = new();

    public static AdaptiveThresholdConfig Load(JsonElement root)
    {
        return new AdaptiveThresholdConfig(
            GetBool(root, "enabled", Disabled.Enabled),
            GetString(root, "method", Disabled.Method),
            GetInt(root, "warmup_windows", Disabled.WarmupWindows),
            GetInt(root, "reference_window", Disabled.ReferenceWindow),
            GetFloat(root, "quantile", Disabled.Quantile),
            GetFloat(root, "mad_multiplier", Disabled.MadMultiplier),
            GetFloat(root, "smoothing_alpha", Disabled.SmoothingAlpha),
            GetFloat(root, "min_threshold_multiplier", Disabled.MinThresholdMultiplier),
            GetFloat(root, "max_threshold_multiplier", Disabled.MaxThresholdMultiplier),
            GetBool(root, "update_on_anomalies", Disabled.UpdateOnAnomalies),
            GetBool(root, "shadow_mode", Disabled.ShadowMode),
            GetFloat(root, "alpha", Disabled.Alpha),
            GetFloat(root, "triage_beta", Disabled.TriageBeta),
            GetInt(root, "bank_size", Disabled.BankSize),
            GetInt(root, "min_effective_sample_size", Disabled.MinEffectiveSampleSize),
            GetInt(root, "recency_half_life_windows", Disabled.RecencyHalfLifeWindows),
            GetFloat(root, "weight_clip_min", Disabled.WeightClipMin),
            GetFloat(root, "weight_clip_max", Disabled.WeightClipMax),
            GetInt(root, "pending_delay_windows", Disabled.PendingDelayWindows),
            GetInt(root, "pending_flush_windows", Disabled.PendingFlushWindows),
            GetInt(root, "monitor_window", Disabled.MonitorWindow),
            GetFloat(root, "burst_alert_rate", Disabled.BurstAlertRate),
            GetFloat(root, "drift_score_mean_ratio", Disabled.DriftScoreMeanRatio),
            GetInt(root, "freeze_duration_windows", Disabled.FreezeDurationWindows),
            GetInt(root, "trusted_bank_size", Disabled.TrustedBankSize),
            GetInt(root, "adaptive_bank_size", Disabled.AdaptiveBankSize),
            GetInt(root, "trusted_warmup_windows", Disabled.TrustedWarmupWindows),
            GetFloat(root, "trusted_sample_weight", Disabled.TrustedSampleWeight),
            GetFloat(root, "adaptive_sample_weight", Disabled.AdaptiveSampleWeight),
            GetString(root, "trusted_seed_path", Disabled.TrustedSeedPath),
            GetFloat(root, "threshold_quantile", Disabled.ThresholdQuantile),
            GetString(root, "p_value_mode", Disabled.PValueMode),
            GetBool(root, "decay_trusted_seed", Disabled.DecayTrustedSeed),
            GetBool(root, "relax_p_min_for_context", Disabled.RelaxPMinForContext),
            GetBool(root, "use_static_threshold_safety_net", Disabled.UseStaticThresholdSafetyNet),
            GetFloat(root, "static_safety_net_max_p_value", Disabled.StaticSafetyNetMaxPValue),
            GetBool(root, "rolling_use_context", Disabled.RollingUseContext),
            GetBool(root, "rolling_use_trusted_seed", Disabled.RollingUseTrustedSeed),
            GetBool(root, "rolling_use_delayed_admission", Disabled.RollingUseDelayedAdmission),
            GetBool(root, "rolling_use_freeze", Disabled.RollingUseFreeze),
            GetBool(root, "rolling_use_asymmetric_smoothing", Disabled.RollingUseAsymmetricSmoothing),
            GetFloat(root, "smoothing_alpha_up", Disabled.SmoothingAlphaUp),
            GetFloat(root, "smoothing_alpha_down", Disabled.SmoothingAlphaDown),
            GetBool(root, "cs_use_change_detection", Disabled.CsUseChangeDetection),
            GetInt(root, "cs_min_recent_windows", Disabled.CsMinRecentWindows),
            GetBool(root, "cs_reset_to_recent", Disabled.CsResetToRecent))
            .Sanitize();
    }

    public AdaptiveThresholdConfig Sanitize()
    {
        var referenceWindow = Math.Max(2, ReferenceWindow);
        var warmupWindows = Math.Clamp(WarmupWindows, 2, referenceWindow);
        var quantile = Math.Clamp(Quantile, 0.5f, 0.9999f);
        var smoothingAlpha = Math.Clamp(SmoothingAlpha, 0.001f, 1f);
        var minMultiplier = Math.Max(0f, MinThresholdMultiplier);
        var maxMultiplier = Math.Max(minMultiplier, MaxThresholdMultiplier);
        var method = string.IsNullOrWhiteSpace(Method) ? Disabled.Method : Method.Trim();
        var alpha = Math.Clamp(Alpha, 0.0001f, 0.5f);
        var triageBeta = Math.Clamp(Math.Max(TriageBeta, alpha), alpha, 0.9999f);
        var weightMin = Math.Max(0.0001f, WeightClipMin);
        var weightMax = Math.Max(weightMin, WeightClipMax);
        var bankSize = Math.Max(2, BankSize);
        var trustedBankSize = TrustedBankSize > 0 ? TrustedBankSize : bankSize;
        var adaptiveBankSize = AdaptiveBankSize > 0 ? AdaptiveBankSize : bankSize;
        trustedBankSize = Math.Max(2, trustedBankSize);
        adaptiveBankSize = Math.Max(2, adaptiveBankSize);
        var trustedWarmupWindows = TrustedWarmupWindows > 0 ? TrustedWarmupWindows : warmupWindows;
        trustedWarmupWindows = Math.Clamp(trustedWarmupWindows, 2, trustedBankSize);
        var thresholdQuantile = ThresholdQuantile > 0
            ? Math.Clamp(ThresholdQuantile, 0.5f, 0.9999f)
            : 0f;
        var pValueMode = string.Equals(PValueMode, "two_sided", StringComparison.OrdinalIgnoreCase)
            ? "two_sided"
            : "upper_tail";
        var smoothingAlphaUp = Math.Clamp(SmoothingAlphaUp, 0.001f, 1f);
        var smoothingAlphaDown = Math.Clamp(SmoothingAlphaDown, 0.001f, 1f);
        var csMinRecentWindows = Math.Clamp(CsMinRecentWindows, 2, Math.Max(2, MonitorWindow));

        return this with
        {
            Method = method,
            WarmupWindows = warmupWindows,
            ReferenceWindow = referenceWindow,
            Quantile = quantile,
            MadMultiplier = Math.Max(0f, MadMultiplier),
            SmoothingAlpha = smoothingAlpha,
            MinThresholdMultiplier = minMultiplier,
            MaxThresholdMultiplier = maxMultiplier,
            Alpha = alpha,
            TriageBeta = triageBeta,
            BankSize = bankSize,
            MinEffectiveSampleSize = Math.Max(1, MinEffectiveSampleSize),
            RecencyHalfLifeWindows = Math.Max(1, RecencyHalfLifeWindows),
            WeightClipMin = weightMin,
            WeightClipMax = weightMax,
            PendingDelayWindows = Math.Max(0, PendingDelayWindows),
            PendingFlushWindows = Math.Max(1, PendingFlushWindows),
            MonitorWindow = Math.Max(8, MonitorWindow),
            BurstAlertRate = Math.Clamp(BurstAlertRate, 0.01f, 1f),
            DriftScoreMeanRatio = Math.Max(1f, DriftScoreMeanRatio),
            FreezeDurationWindows = Math.Max(1, FreezeDurationWindows),
            TrustedBankSize = trustedBankSize,
            AdaptiveBankSize = adaptiveBankSize,
            TrustedWarmupWindows = trustedWarmupWindows,
            TrustedSampleWeight = Math.Max(0.0001f, TrustedSampleWeight),
            AdaptiveSampleWeight = Math.Max(0f, AdaptiveSampleWeight),
            TrustedSeedPath = TrustedSeedPath?.Trim() ?? string.Empty,
            ThresholdQuantile = thresholdQuantile,
            PValueMode = pValueMode,
            StaticSafetyNetMaxPValue = Math.Clamp(StaticSafetyNetMaxPValue, alpha, 1f),
            SmoothingAlphaUp = smoothingAlphaUp,
            SmoothingAlphaDown = smoothingAlphaDown,
            CsMinRecentWindows = csMinRecentWindows
        };
    }

    private static string GetString(JsonElement root, string property, string fallback)
    {
        return root.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? fallback
            : fallback;
    }

    private static bool GetBool(JsonElement root, string property, bool fallback)
    {
        return root.TryGetProperty(property, out var value)
            ? value.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => fallback
            }
            : fallback;
    }

    private static int GetInt(JsonElement root, string property, int fallback)
    {
        return root.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Number
            ? value.GetInt32()
            : fallback;
    }

    private static float GetFloat(JsonElement root, string property, float fallback)
    {
        return root.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Number
            ? value.GetSingle()
            : fallback;
    }
}

public sealed class ThresholdEvaluator
{
    private readonly ThresholdConfig _config;
    private readonly AdaptiveThresholdCalibrator? _adaptiveThreshold;
    private readonly ConfidenceSequenceThresholdCalibrator? _confidenceSequence;
    private readonly WeightedConformalCalibrator? _weightedConformal;

    public ThresholdEvaluator(ThresholdConfig config)
    {
        _config = config;
        if (config.Adaptive is not { Enabled: true } adaptive)
        {
            return;
        }

        if (string.Equals(adaptive.Method, "weighted_conformal", StringComparison.OrdinalIgnoreCase))
        {
            _weightedConformal = new WeightedConformalCalibrator(config.Threshold, config.ActiveMethod, adaptive);
        }
        else if (string.Equals(adaptive.Method, "confidence_sequence", StringComparison.OrdinalIgnoreCase))
        {
            _confidenceSequence = new ConfidenceSequenceThresholdCalibrator(config.Threshold, config.ActiveMethod, adaptive);
        }
        else
        {
            _adaptiveThreshold = new AdaptiveThresholdCalibrator(config.Threshold, config.ActiveMethod, adaptive);
        }
    }

    public InferenceResult Evaluate(TrafficWindow window, float reconstructionError)
    {
        if (_weightedConformal is not null)
        {
            var staticIsAnomaly = reconstructionError > _config.Threshold;
            var decision = _weightedConformal.Evaluate(window, reconstructionError, staticIsAnomaly);
            return new InferenceResult
            {
                Timestamp = window.EndTimestamp,
                SourceIp = window.SourceIp,
                DestinationIp = window.DestinationIp,
                DestinationPort = window.DestinationPort,
                Protocol = window.Protocol,
                ReconstructionError = reconstructionError,
                Threshold = decision.Threshold,
                IsAnomaly = decision.IsAnomaly,
                GroundTruthIsAnomaly = window.IsAnomaly,
                ThresholdMethod = decision.MethodName,
                ModelVersion = _config.ModelVersion,
                ContextKey = decision.ContextKey,
                ParentContextKey = decision.ParentContextKey,
                PValue = decision.PValue,
                CalibrationDecision = decision.Decision,
                CalibrationMode = decision.Mode,
                EffectiveSampleSize = decision.EffectiveSampleSize,
                PMin = decision.PMin,
                BankSize = decision.BankSize,
                TrustedBankSize = decision.TrustedBankSize,
                AdaptiveBankSize = decision.AdaptiveBankSize,
                BankFrozen = decision.BankFrozen,
                FreezeReason = decision.FreezeReason
            };
        }

        var confidenceSequenceDecision = _confidenceSequence?.Evaluate(window, reconstructionError);
        if (confidenceSequenceDecision is not null)
        {
            return new InferenceResult
            {
                Timestamp = window.EndTimestamp,
                SourceIp = window.SourceIp,
                DestinationIp = window.DestinationIp,
                DestinationPort = window.DestinationPort,
                Protocol = window.Protocol,
                ReconstructionError = reconstructionError,
                Threshold = confidenceSequenceDecision.Threshold,
                IsAnomaly = confidenceSequenceDecision.IsAnomaly,
                GroundTruthIsAnomaly = window.IsAnomaly,
                ThresholdMethod = confidenceSequenceDecision.MethodName,
                ModelVersion = _config.ModelVersion,
                ContextKey = confidenceSequenceDecision.ContextKey,
                ParentContextKey = confidenceSequenceDecision.ParentContextKey,
                PValue = confidenceSequenceDecision.PValue,
                CalibrationDecision = confidenceSequenceDecision.Decision,
                CalibrationMode = confidenceSequenceDecision.Mode,
                EffectiveSampleSize = confidenceSequenceDecision.EffectiveSampleSize,
                PMin = confidenceSequenceDecision.PMin,
                BankSize = confidenceSequenceDecision.BankSize,
                TrustedBankSize = confidenceSequenceDecision.TrustedBankSize,
                AdaptiveBankSize = confidenceSequenceDecision.AdaptiveBankSize,
                BankFrozen = confidenceSequenceDecision.BankFrozen,
                FreezeReason = confidenceSequenceDecision.FreezeReason
            };
        }

        var rollingDecision = _adaptiveThreshold?.Evaluate(window, reconstructionError);
        var threshold = rollingDecision?.Threshold ?? _config.Threshold;
        var isAnomaly = rollingDecision?.IsAnomaly ?? reconstructionError > threshold;
        var result = new InferenceResult
        {
            Timestamp = window.EndTimestamp,
            SourceIp = window.SourceIp,
            DestinationIp = window.DestinationIp,
            DestinationPort = window.DestinationPort,
            Protocol = window.Protocol,
            ReconstructionError = reconstructionError,
            Threshold = threshold,
            IsAnomaly = isAnomaly,
            GroundTruthIsAnomaly = window.IsAnomaly,
            ThresholdMethod = rollingDecision?.MethodName ?? _config.ActiveMethod,
            ModelVersion = _config.ModelVersion,
            ContextKey = rollingDecision?.ContextKey,
            ParentContextKey = rollingDecision?.ParentContextKey,
            CalibrationDecision = rollingDecision?.Decision,
            CalibrationMode = rollingDecision?.Mode,
            BankSize = rollingDecision?.BankSize,
            TrustedBankSize = rollingDecision?.TrustedBankSize,
            AdaptiveBankSize = rollingDecision?.AdaptiveBankSize,
            BankFrozen = rollingDecision?.BankFrozen,
            FreezeReason = rollingDecision?.FreezeReason
        };
        return result;
    }
}
