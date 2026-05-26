using System.Text.Json;
using AnomalyDetection.Contracts;

namespace AnomalyDetection.Inference;

public sealed class AdaptiveThresholdCalibrator
{
    private const string GlobalContextKey = "global";

    private readonly AdaptiveThresholdConfig _config;
    private readonly float _baselineThreshold;
    private readonly string _baselineMethod;
    private readonly Dictionary<string, RollingThresholdBank> _banks = new(StringComparer.Ordinal);
    private long _sequence;

    public AdaptiveThresholdCalibrator(
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

    public float CurrentThreshold => GetBank(GlobalContextKey).CurrentThreshold;

    public string MethodName { get; }

    public int SampleCount => GetBank(GlobalContextKey).SampleCount;

    public CalibrationDecision Evaluate(TrafficWindow window, float reconstructionError)
    {
        _sequence++;
        FlushPendingIfNeeded();

        var score = SanitizeScore(reconstructionError);
        var contextKey = _config.RollingUseContext ? BuildContextKey(window) : GlobalContextKey;
        var parentContextKey = _config.RollingUseContext ? BuildParentContextKey(window) : GlobalContextKey;
        var selected = SelectBank(contextKey, parentContextKey);
        var threshold = selected.Bank.CurrentThreshold;
        var isAnomaly = score > threshold;

        var targetBanks = TargetBanks(contextKey, parentContextKey).ToArray();
        foreach (var bank in targetBanks)
        {
            bank.RecordTelemetry(score, isAnomaly, _sequence, _config);
        }

        if (ShouldAdmit(score, isAnomaly, targetBanks))
        {
            foreach (var bank in targetBanks)
            {
                if (_config.RollingUseDelayedAdmission)
                {
                    bank.QueueCandidate(score, _sequence + _config.PendingDelayWindows);
                }
                else
                {
                    bank.AddScore(score, _config);
                }
            }
        }

        var mode = selected.Mode;
        if (selected.Bank.SampleCount < _config.WarmupWindows)
        {
            mode = $"{mode}:warmup";
        }

        return new CalibrationDecision(
            Threshold: threshold,
            IsAnomaly: isAnomaly,
            Decision: isAnomaly ? "alert" : "normal",
            Mode: mode,
            ContextKey: contextKey,
            ParentContextKey: parentContextKey,
            PValue: null,
            EffectiveSampleSize: null,
            PMin: null,
            BankSize: selected.Bank.SampleCount,
            TrustedBankSize: selected.Bank.SampleCount,
            AdaptiveBankSize: 0,
            BankFrozen: selected.Bank.IsFrozen(_sequence),
            FreezeReason: selected.Bank.FreezeReason,
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

    private IEnumerable<RollingThresholdBank> TargetBanks(string contextKey, string parentContextKey)
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

    private bool ShouldAdmit(float score, bool isAnomaly, IReadOnlyCollection<RollingThresholdBank> targetBanks)
    {
        if (!float.IsFinite(score) || score < 0)
        {
            return false;
        }

        if (isAnomaly && !_config.UpdateOnAnomalies)
        {
            return false;
        }

        return !_config.RollingUseFreeze || !targetBanks.Any(bank => bank.IsFrozen(_sequence));
    }

    private void FlushPendingIfNeeded()
    {
        if (!_config.RollingUseDelayedAdmission || _sequence % _config.PendingFlushWindows != 0)
        {
            return;
        }

        foreach (var bank in _banks.Values)
        {
            bank.FlushPending(_sequence, _config);
        }
    }

    private RollingThresholdBank GetBank(string contextKey)
    {
        if (_banks.TryGetValue(contextKey, out var bank))
        {
            return bank;
        }

        bank = new RollingThresholdBank(contextKey, _baselineThreshold);
        _banks[contextKey] = bank;
        return bank;
    }

    private void LoadTrustedSeedIfConfigured()
    {
        if (!_config.RollingUseTrustedSeed || string.IsNullOrWhiteSpace(_config.TrustedSeedPath))
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

            foreach (var scoreElement in scoresElement.EnumerateArray())
            {
                if (scoreElement.ValueKind == JsonValueKind.Number)
                {
                    GetBank(contextKey).AddScore(SanitizeScore(scoreElement.GetSingle()), _config);
                }
            }
        }
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

    private sealed record SelectedBank(RollingThresholdBank Bank, string Mode);

    private sealed class RollingThresholdBank
    {
        private readonly float _baselineThreshold;
        private readonly Queue<float> _scores = new();
        private readonly List<float> _sortedScores = new();
        private readonly Queue<PendingRollingScore> _pending = new();
        private readonly Queue<float> _recentScores = new();
        private readonly Queue<bool> _recentAlerts = new();
        private long _frozenUntilSequence;
        private bool _hasAdaptiveEstimate;

        public RollingThresholdBank(string contextKey, float baselineThreshold)
        {
            ContextKey = contextKey;
            _baselineThreshold = Math.Max(0f, baselineThreshold);
            CurrentThreshold = _baselineThreshold;
        }

        public string ContextKey { get; }

        public float CurrentThreshold { get; private set; }

        public int SampleCount => _scores.Count;

        public string? FreezeReason { get; private set; }

        public bool IsFrozen(long sequence)
        {
            if (sequence < _frozenUntilSequence)
            {
                return true;
            }

            _frozenUntilSequence = 0;
            FreezeReason = null;
            return false;
        }

        public void QueueCandidate(float score, long matureAtSequence)
        {
            _pending.Enqueue(new PendingRollingScore(score, matureAtSequence));
        }

        public void FlushPending(long sequence, AdaptiveThresholdConfig config)
        {
            if (IsFrozen(sequence))
            {
                DropMaturePending(sequence);
                return;
            }

            while (_pending.Count > 0 && _pending.Peek().MatureAtSequence <= sequence)
            {
                AddScore(_pending.Dequeue().Score, config);
            }
        }

        public void AddScore(float score, AdaptiveThresholdConfig config)
        {
            if (!float.IsFinite(score) || score < 0)
            {
                return;
            }

            _scores.Enqueue(score);
            InsertSorted(score);

            if (_scores.Count > config.ReferenceWindow)
            {
                var removed = _scores.Dequeue();
                RemoveSorted(removed);
            }

            UpdateThreshold(config);
        }

        public void RecordTelemetry(float score, bool isAlert, long sequence, AdaptiveThresholdConfig config)
        {
            if (!config.RollingUseFreeze)
            {
                return;
            }

            _recentScores.Enqueue(score);
            _recentAlerts.Enqueue(isAlert);
            while (_recentScores.Count > config.MonitorWindow)
            {
                _recentScores.Dequeue();
            }

            while (_recentAlerts.Count > config.MonitorWindow)
            {
                _recentAlerts.Dequeue();
            }

            if (_recentScores.Count < config.MonitorWindow || IsFrozen(sequence))
            {
                return;
            }

            var alertRate = _recentAlerts.Count(value => value) / (float)_recentAlerts.Count;
            if (alertRate >= config.BurstAlertRate)
            {
                Freeze(sequence, config, "burst_alert_rate");
                return;
            }

            if (_scores.Count == 0)
            {
                return;
            }

            var referenceMean = _scores.Average();
            var currentMean = _recentScores.Average();
            if (referenceMean > 0 && currentMean > referenceMean * config.DriftScoreMeanRatio)
            {
                Freeze(sequence, config, "score_mean_drift");
            }
        }

        private void UpdateThreshold(AdaptiveThresholdConfig config)
        {
            if (_scores.Count < config.WarmupWindows)
            {
                return;
            }

            var quantileThreshold = Quantile(_sortedScores, config.Quantile);
            var median = Quantile(_sortedScores, 0.5f);
            var mad = MedianAbsoluteDeviation(median);
            var robustThreshold = median + config.MadMultiplier * mad;
            var candidate = ClampToBaseline(Math.Max(quantileThreshold, robustThreshold), config);

            if (!_hasAdaptiveEstimate)
            {
                CurrentThreshold = candidate;
                _hasAdaptiveEstimate = true;
                return;
            }

            CurrentThreshold = Smooth(CurrentThreshold, candidate, config);
        }

        private void DropMaturePending(long sequence)
        {
            while (_pending.Count > 0 && _pending.Peek().MatureAtSequence <= sequence)
            {
                _pending.Dequeue();
            }
        }

        private void InsertSorted(float score)
        {
            var index = _sortedScores.BinarySearch(score);
            if (index < 0)
            {
                index = ~index;
            }

            _sortedScores.Insert(index, score);
        }

        private void RemoveSorted(float score)
        {
            var index = _sortedScores.BinarySearch(score);
            if (index >= 0)
            {
                _sortedScores.RemoveAt(index);
            }
        }

        private float MedianAbsoluteDeviation(float median)
        {
            var deviations = new List<float>(_sortedScores.Count);
            foreach (var score in _sortedScores)
            {
                deviations.Add(Math.Abs(score - median));
            }

            deviations.Sort();
            return Quantile(deviations, 0.5f);
        }

        private float ClampToBaseline(float candidate, AdaptiveThresholdConfig config)
        {
            if (_baselineThreshold <= 0)
            {
                return Math.Max(0f, candidate);
            }

            var minThreshold = _baselineThreshold * config.MinThresholdMultiplier;
            var maxThreshold = _baselineThreshold * config.MaxThresholdMultiplier;
            return Math.Clamp(candidate, minThreshold, maxThreshold);
        }

        private float Smooth(float current, float candidate, AdaptiveThresholdConfig config)
        {
            var alpha = config.RollingUseAsymmetricSmoothing
                ? candidate > current ? config.SmoothingAlphaUp : config.SmoothingAlphaDown
                : config.SmoothingAlpha;
            return current + alpha * (candidate - current);
        }

        private void Freeze(long sequence, AdaptiveThresholdConfig config, string reason)
        {
            _frozenUntilSequence = sequence + config.FreezeDurationWindows;
            FreezeReason = reason;
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

        private sealed record PendingRollingScore(float Score, long MatureAtSequence);
    }
}
