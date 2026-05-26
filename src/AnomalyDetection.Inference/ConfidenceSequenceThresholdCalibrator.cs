using System.Text.Json;
using AnomalyDetection.Contracts;

namespace AnomalyDetection.Inference;

public sealed class ConfidenceSequenceThresholdCalibrator
{
    private const string GlobalContextKey = "global";

    private readonly AdaptiveThresholdConfig _config;
    private readonly float _baselineThreshold;
    private readonly string _baselineMethod;
    private readonly Dictionary<string, ConfidenceSequenceBank> _banks = new(StringComparer.Ordinal);
    private long _sequence;

    public ConfidenceSequenceThresholdCalibrator(
        float baselineThreshold,
        string baselineMethod,
        AdaptiveThresholdConfig config)
    {
        _baselineThreshold = Math.Max(0f, baselineThreshold);
        _baselineMethod = string.IsNullOrWhiteSpace(baselineMethod) ? "unknown" : baselineMethod.Trim();
        _config = config.Sanitize();
        MethodName = $"{_baselineMethod}+{_config.Method}";
        LoadTrustedSeedIfConfigured();
    }

    public string MethodName { get; }

    public CalibrationDecision Evaluate(TrafficWindow window, float reconstructionError)
    {
        _sequence++;

        var score = SanitizeScore(reconstructionError);
        var contextKey = _config.RollingUseContext ? BuildContextKey(window) : GlobalContextKey;
        var parentContextKey = _config.RollingUseContext ? BuildParentContextKey(window) : GlobalContextKey;
        var selected = SelectBank(contextKey, parentContextKey);

        if (selected.Bank.ShouldResetForChange(_config))
        {
            selected.Bank.ResetAfterChange(_config);
            var resetThreshold = selected.Bank.TryConfidenceInterval(_config)?.Upper ?? _baselineThreshold;
            AdmitScore(score, isAlert: false, contextKey, parentContextKey);
            return new CalibrationDecision(
                Threshold: ApplyThresholdBounds(resetThreshold),
                IsAnomaly: false,
                Decision: "abstain",
                Mode: $"{selected.Mode}:cs:change_reset",
                ContextKey: contextKey,
                ParentContextKey: parentContextKey,
                PValue: null,
                EffectiveSampleSize: selected.Bank.SampleCount,
                PMin: null,
                BankSize: selected.Bank.SampleCount,
                TrustedBankSize: selected.Bank.SampleCount,
                AdaptiveBankSize: 0,
                BankFrozen: false,
                FreezeReason: "confidence_sequence_intersection_empty",
                MethodName);
        }

        if (selected.Bank.SampleCount < _config.WarmupWindows)
        {
            AdmitScore(score, isAlert: false, contextKey, parentContextKey);
            return new CalibrationDecision(
                Threshold: _baselineThreshold,
                IsAnomaly: false,
                Decision: "abstain",
                Mode: $"{selected.Mode}:cs:warmup",
                ContextKey: contextKey,
                ParentContextKey: parentContextKey,
                PValue: null,
                EffectiveSampleSize: selected.Bank.SampleCount,
                PMin: null,
                BankSize: selected.Bank.SampleCount,
                TrustedBankSize: selected.Bank.SampleCount,
                AdaptiveBankSize: 0,
                BankFrozen: false,
                FreezeReason: null,
                MethodName);
        }

        var interval = selected.Bank.TryConfidenceInterval(_config);
        if (interval is null)
        {
            AdmitScore(score, isAlert: false, contextKey, parentContextKey);
            return new CalibrationDecision(
                Threshold: _baselineThreshold,
                IsAnomaly: false,
                Decision: "abstain",
                Mode: $"{selected.Mode}:cs:empty",
                ContextKey: contextKey,
                ParentContextKey: parentContextKey,
                PValue: null,
                EffectiveSampleSize: 0,
                PMin: null,
                BankSize: selected.Bank.SampleCount,
                TrustedBankSize: selected.Bank.SampleCount,
                AdaptiveBankSize: 0,
                BankFrozen: false,
                FreezeReason: null,
                MethodName);
        }

        var upperThreshold = ApplyThresholdBounds(interval.Upper);
        var lowerThreshold = Math.Min(interval.Lower, upperThreshold);
        var isAlert = score > upperThreshold;
        var decision = isAlert
            ? "alert"
            : score >= lowerThreshold
                ? "abstain"
                : "normal";

        if (_config.UseStaticThresholdSafetyNet && !isAlert && score > _baselineThreshold)
        {
            isAlert = true;
            decision = "fallback_alert";
        }

        AdmitScore(score, isAlert, contextKey, parentContextKey);

        return new CalibrationDecision(
            Threshold: upperThreshold,
            IsAnomaly: isAlert,
            Decision: decision,
            Mode: $"{selected.Mode}:cs",
            ContextKey: contextKey,
            ParentContextKey: parentContextKey,
            PValue: null,
            EffectiveSampleSize: selected.Bank.SampleCount,
            PMin: null,
            BankSize: selected.Bank.SampleCount,
            TrustedBankSize: selected.Bank.SampleCount,
            AdaptiveBankSize: 0,
            BankFrozen: false,
            FreezeReason: null,
            MethodName);
    }

    private SelectedBank SelectBank(string contextKey, string parentContextKey)
    {
        if (!_config.RollingUseContext)
        {
            return new SelectedBank(GetBank(GlobalContextKey), "global");
        }

        foreach (var (key, mode) in new[]
        {
            (contextKey, "context"),
            (parentContextKey, "parent"),
            (GlobalContextKey, "global")
        })
        {
            var bank = GetBank(key);
            if (bank.SampleCount >= _config.WarmupWindows)
            {
                return new SelectedBank(bank, mode);
            }
        }

        return new SelectedBank(GetBank(contextKey), "context");
    }

    private IEnumerable<ConfidenceSequenceBank> TargetBanks(string contextKey, string parentContextKey)
    {
        if (!_config.RollingUseContext)
        {
            yield return GetBank(GlobalContextKey);
            yield break;
        }

        foreach (var key in new[] { contextKey, parentContextKey, GlobalContextKey }.Distinct(StringComparer.Ordinal))
        {
            yield return GetBank(key);
        }
    }

    private void AdmitScore(float score, bool isAlert, string contextKey, string parentContextKey)
    {
        if (!float.IsFinite(score) || score < 0)
        {
            return;
        }

        if (isAlert && !_config.UpdateOnAnomalies)
        {
            return;
        }

        foreach (var bank in TargetBanks(contextKey, parentContextKey))
        {
            bank.AddScore(score, _config);
        }
    }

    private ConfidenceSequenceBank GetBank(string contextKey)
    {
        if (_banks.TryGetValue(contextKey, out var bank))
        {
            return bank;
        }

        bank = new ConfidenceSequenceBank(contextKey);
        _banks[contextKey] = bank;
        return bank;
    }

    private void LoadTrustedSeedIfConfigured()
    {
        if (string.IsNullOrWhiteSpace(_config.TrustedSeedPath))
        {
            return;
        }

        var path = Path.GetFullPath(_config.TrustedSeedPath);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Trusted calibration seed file was not found.", path);
        }

        using var stream = File.OpenRead(path);
        using var document = JsonDocument.Parse(stream);
        if (!document.RootElement.TryGetProperty("banks", out var banks) || banks.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("Trusted calibration seed must contain a 'banks' array.");
        }

        foreach (var bankElement in banks.EnumerateArray())
        {
            if (!bankElement.TryGetProperty("context_key", out var keyElement) || keyElement.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            if (!bankElement.TryGetProperty("trusted_scores", out var scoresElement) || scoresElement.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            var contextKey = Normalize(keyElement.GetString() ?? string.Empty);
            if (string.IsNullOrWhiteSpace(contextKey))
            {
                continue;
            }

            if (!_config.RollingUseContext && contextKey != GlobalContextKey)
            {
                continue;
            }

            var bank = GetBank(contextKey);
            foreach (var scoreElement in scoresElement.EnumerateArray())
            {
                if (scoreElement.ValueKind == JsonValueKind.Number)
                {
                    bank.AddScore(SanitizeScore(scoreElement.GetSingle()), _config);
                }
            }
        }
    }

    private float ApplyThresholdBounds(float threshold)
    {
        var candidate = threshold > 0 ? threshold : _baselineThreshold;
        if (_baselineThreshold <= 0)
        {
            return Math.Max(0f, candidate);
        }

        var min = _baselineThreshold * _config.MinThresholdMultiplier;
        var max = _baselineThreshold * _config.MaxThresholdMultiplier;
        return Math.Clamp(candidate, min, max);
    }

    private static string BuildContextKey(TrafficWindow window)
    {
        return string.Join(
            '|',
            Normalize(window.Protocol),
            Normalize(window.Service),
            $"h{window.EndTimestamp.ToUniversalTime().Hour:00}");
    }

    private static string BuildParentContextKey(TrafficWindow window)
    {
        return string.Join('|', Normalize(window.Protocol), Normalize(window.Service));
    }

    private static string Normalize(string value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? "unknown"
            : value.Trim().ToLowerInvariant();
    }

    private static float SanitizeScore(float score)
    {
        return float.IsFinite(score) ? Math.Max(0f, score) : 0f;
    }

    private sealed record SelectedBank(ConfidenceSequenceBank Bank, string Mode);

    private sealed record ConfidenceInterval(float Lower, float Upper);

    private sealed class ConfidenceSequenceBank
    {
        private readonly Queue<float> _scores = new();
        private readonly List<float> _sortedScores = new();
        private readonly Queue<float> _recentScores = new();
        private readonly List<float> _recentSortedScores = new();

        public ConfidenceSequenceBank(string contextKey)
        {
            ContextKey = contextKey;
        }

        public string ContextKey { get; }

        public int SampleCount => _scores.Count;

        public void AddScore(float score, AdaptiveThresholdConfig config)
        {
            if (!float.IsFinite(score) || score < 0)
            {
                return;
            }

            Enqueue(_scores, _sortedScores, score, config.ReferenceWindow);
            Enqueue(_recentScores, _recentSortedScores, score, config.MonitorWindow);
        }

        public bool ShouldResetForChange(AdaptiveThresholdConfig config)
        {
            if (!config.CsUseChangeDetection)
            {
                return false;
            }

            if (_sortedScores.Count < config.WarmupWindows || _recentSortedScores.Count < config.CsMinRecentWindows)
            {
                return false;
            }

            var baseline = BuildConfidenceInterval(_sortedScores, config);
            var recent = BuildConfidenceInterval(_recentSortedScores, config);
            return baseline.Upper < recent.Lower || recent.Upper < baseline.Lower;
        }

        public void ResetAfterChange(AdaptiveThresholdConfig config)
        {
            var recent = _recentScores.ToArray();
            _scores.Clear();
            _sortedScores.Clear();
            _recentScores.Clear();
            _recentSortedScores.Clear();

            if (!config.CsResetToRecent)
            {
                return;
            }

            foreach (var score in recent)
            {
                AddScore(score, config);
            }
        }

        public ConfidenceInterval? TryConfidenceInterval(AdaptiveThresholdConfig config)
        {
            return _sortedScores.Count == 0 ? null : BuildConfidenceInterval(_sortedScores, config);
        }

        private static void Enqueue(Queue<float> queue, List<float> sorted, float score, int maxSize)
        {
            queue.Enqueue(score);
            InsertSorted(sorted, score);

            while (queue.Count > maxSize)
            {
                var removed = queue.Dequeue();
                RemoveSorted(sorted, removed);
            }
        }

        private static ConfidenceInterval BuildConfidenceInterval(IReadOnlyList<float> sortedScores, AdaptiveThresholdConfig config)
        {
            var radius = ConfidenceRadius(sortedScores.Count, config.Alpha);
            var lowerQuantile = Math.Clamp(config.Quantile - 2f * radius, 0f, 1f);
            var upperQuantile = Math.Clamp(config.Quantile + 2f * radius, 0f, 1f);
            return new ConfidenceInterval(
                Quantile(sortedScores, lowerQuantile),
                Quantile(sortedScores, upperQuantile));
        }

        private static float ConfidenceRadius(int count, float alpha)
        {
            if (count <= 0)
            {
                return 1f;
            }

            var safeAlpha = Math.Clamp(alpha, 0.0001f, 0.5f);
            var time = Math.Max(1d, count);
            var logLog = Math.Log(Math.Log(Math.E * time));
            var logTerm = Math.Log(1612d / safeAlpha);
            var radius = 0.85d * Math.Sqrt(Math.Max(0d, logLog + 0.8d * logTerm) / time);
            return (float)Math.Clamp(radius, 0d, 1d);
        }

        private static float Quantile(IReadOnlyList<float> values, float quantile)
        {
            if (values.Count == 0)
            {
                return 0f;
            }

            if (values.Count == 1)
            {
                return values[0];
            }

            var position = (values.Count - 1) * Math.Clamp(quantile, 0f, 1f);
            var lowerIndex = (int)Math.Floor(position);
            var upperIndex = (int)Math.Ceiling(position);
            if (lowerIndex == upperIndex)
            {
                return values[lowerIndex];
            }

            var weight = position - lowerIndex;
            return values[lowerIndex] + (values[upperIndex] - values[lowerIndex]) * weight;
        }

        private static void InsertSorted(List<float> sorted, float score)
        {
            var index = sorted.BinarySearch(score);
            if (index < 0)
            {
                index = ~index;
            }

            sorted.Insert(index, score);
        }

        private static void RemoveSorted(List<float> sorted, float score)
        {
            var index = sorted.BinarySearch(score);
            if (index >= 0)
            {
                sorted.RemoveAt(index);
            }
        }
    }
}
