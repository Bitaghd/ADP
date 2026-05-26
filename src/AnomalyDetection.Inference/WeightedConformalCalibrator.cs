using System.Text.Json;
using AnomalyDetection.Contracts;

namespace AnomalyDetection.Inference;

public sealed record CalibrationDecision(
    float Threshold,
    bool IsAnomaly,
    string Decision,
    string Mode,
    string ContextKey,
    string ParentContextKey,
    float? PValue,
    float? EffectiveSampleSize,
    float? PMin,
    int BankSize,
    int TrustedBankSize,
    int AdaptiveBankSize,
    bool BankFrozen,
    string? FreezeReason,
    string MethodName);

public sealed class WeightedConformalCalibrator
{
    private const string GlobalContextKey = "global";

    private readonly float _baselineThreshold;
    private readonly string _baselineMethod;
    private readonly AdaptiveThresholdConfig _config;
    private readonly Dictionary<string, CalibrationBank> _banks = new(StringComparer.Ordinal);
    private long _sequence;

    public WeightedConformalCalibrator(
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

    public CalibrationDecision Evaluate(TrafficWindow window, float reconstructionError, bool staticIsAnomaly)
    {
        _sequence++;
        FlushPendingIfNeeded();

        var contextKey = BuildContextKey(window);
        var parentContextKey = BuildParentContextKey(window);
        var score = SanitizeScore(reconstructionError);
        var requestedBank = GetBank(contextKey);
        var selected = SelectBank(contextKey, parentContextKey, score);

        var conformalDecision = selected is null
            ? FallbackDecision(contextKey, parentContextKey, score, staticIsAnomaly, "insufficient_bank")
            : ConformalDecision(contextKey, parentContextKey, selected, score, staticIsAnomaly);

        var shouldAdmit = ShouldAdmit(score, staticIsAnomaly, conformalDecision);
        if (shouldAdmit)
        {
            QueueCandidate(requestedBank, window.SourceIp, score);
            QueueCandidate(GetBank(parentContextKey), window.SourceIp, score);
            QueueCandidate(GetBank(GlobalContextKey), window.SourceIp, score);
        }

        requestedBank.RecordTelemetry(score, conformalDecision.Decision == "alert", _sequence, _config);

        if (_config.ShadowMode)
        {
            return conformalDecision with
            {
                IsAnomaly = staticIsAnomaly,
                Mode = $"{conformalDecision.Mode}:shadow"
            };
        }

        return conformalDecision;
    }

    private CalibrationDecision? SelectBank(string contextKey, string parentContextKey, float score)
    {
        foreach (var key in new[] { contextKey, parentContextKey, GlobalContextKey })
        {
            var bank = GetBank(key);
            if (!bank.IsReady(_config) || bank.IsFrozen(_sequence))
            {
                continue;
            }

            var stats = bank.ComputeStats(score, _sequence, _config);
            if (stats.EffectiveSampleSize < _config.MinEffectiveSampleSize)
            {
                continue;
            }

            var isExactOrParentContext = key == contextKey || key == parentContextKey;
            if (stats.PMin > _config.Alpha && (!_config.RelaxPMinForContext || !isExactOrParentContext))
            {
                continue;
            }

            var mode = key == contextKey
                ? "context"
                : key == parentContextKey
                    ? "parent"
                    : "global";
            if (stats.PMin > _config.Alpha)
            {
                mode = $"{mode}:relaxed_pmin";
            }

            return new CalibrationDecision(
                Threshold: ApplyThresholdBounds(
                    bank.WeightedQuantile(
                    stats.Direction == TailDirection.Low ? 1f - EffectiveThresholdQuantile() : EffectiveThresholdQuantile(),
                    _sequence,
                    _config) ?? _baselineThreshold,
                    stats.Direction),
                IsAnomaly: false,
                Decision: "candidate",
                Mode: $"{mode}:trusted_adaptive:{stats.Direction.ToString().ToLowerInvariant()}",
                ContextKey: contextKey,
                ParentContextKey: parentContextKey,
                PValue: stats.PValue,
                EffectiveSampleSize: stats.EffectiveSampleSize,
                PMin: stats.PMin,
                BankSize: bank.SampleCount,
                TrustedBankSize: bank.TrustedSampleCount,
                AdaptiveBankSize: bank.AdaptiveSampleCount,
                BankFrozen: false,
                FreezeReason: null,
                MethodName);
        }

        return null;
    }

    private CalibrationDecision ConformalDecision(
        string contextKey,
        string parentContextKey,
        CalibrationDecision selected,
        float score,
        bool staticIsAnomaly)
    {
        var pValue = selected.PValue ?? 1f;
        var isLowTail = selected.Mode.Contains(":low", StringComparison.Ordinal);
        var threshold = ApplyThresholdBounds(selected.Threshold, isLowTail ? TailDirection.Low : TailDirection.High);
        var thresholdPassed = isLowTail ? score < threshold : score > threshold;
        var decision = "normal";
        if (pValue <= _config.Alpha && thresholdPassed)
        {
            decision = "alert";
        }
        else if (_config.UseStaticThresholdSafetyNet && staticIsAnomaly && pValue <= _config.StaticSafetyNetMaxPValue)
        {
            decision = "alert";
        }
        else if (pValue <= _config.TriageBeta)
        {
            decision = "triage";
        }

        return selected with
        {
            IsAnomaly = decision == "alert",
            Decision = decision,
            ContextKey = contextKey,
            ParentContextKey = parentContextKey,
            Threshold = threshold
        };
    }

    private CalibrationDecision FallbackDecision(
        string contextKey,
        string parentContextKey,
        float score,
        bool staticIsAnomaly,
        string reason)
    {
        var bank = GetBank(contextKey);
        var isFrozen = bank.IsFrozen(_sequence);
        var freezeReason = isFrozen ? bank.FreezeReason : reason;

        return new CalibrationDecision(
            Threshold: _baselineThreshold,
            IsAnomaly: staticIsAnomaly,
            Decision: staticIsAnomaly ? "fallback_alert" : "fallback_normal",
            Mode: "static_fallback",
            ContextKey: contextKey,
            ParentContextKey: parentContextKey,
            PValue: null,
            EffectiveSampleSize: null,
            PMin: null,
            BankSize: bank.SampleCount,
            TrustedBankSize: bank.TrustedSampleCount,
            AdaptiveBankSize: bank.AdaptiveSampleCount,
            BankFrozen: isFrozen,
            FreezeReason: freezeReason,
            MethodName);
    }

    private bool ShouldAdmit(float score, bool staticIsAnomaly, CalibrationDecision decision)
    {
        if (!float.IsFinite(score) || score < 0)
        {
            return false;
        }

        if (staticIsAnomaly && !_config.UpdateOnAnomalies)
        {
            return false;
        }

        if (decision.Decision is "alert" or "triage" or "fallback_alert")
        {
            return false;
        }

        return decision.PValue is null || decision.PValue > _config.TriageBeta;
    }

    private void QueueCandidate(CalibrationBank bank, string sourceIp, float score)
    {
        if (bank.IsFrozen(_sequence))
        {
            return;
        }

        bank.QueueCandidate(new PendingCalibrationCandidate(
            score,
            _sequence,
            _sequence + _config.PendingDelayWindows,
            sourceIp,
            bank.NextLayer(_config)));
    }

    private void FlushPendingIfNeeded()
    {
        if (_sequence % _config.PendingFlushWindows != 0)
        {
            return;
        }

        foreach (var bank in _banks.Values)
        {
            bank.FlushPending(_sequence, _config);
        }
    }

    private CalibrationBank GetBank(string contextKey)
    {
        if (_banks.TryGetValue(contextKey, out var bank))
        {
            return bank;
        }

        bank = new CalibrationBank(contextKey);
        _banks[contextKey] = bank;
        return bank;
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

            var scores = scoresElement
                .EnumerateArray()
                .Where(item => item.ValueKind == JsonValueKind.Number)
                .Select(item => SanitizeScore(item.GetSingle()))
                .Where(float.IsFinite);
            GetBank(contextKey).SeedTrustedScores(scores, _sequence, _config);
        }
    }

    private float ApplyThresholdBounds(float threshold, TailDirection direction = TailDirection.High)
    {
        var candidate = threshold > 0 ? threshold : _baselineThreshold;
        if (_baselineThreshold <= 0)
        {
            return Math.Max(0f, candidate);
        }

        var max = _baselineThreshold * _config.MaxThresholdMultiplier;
        if (direction == TailDirection.Low)
        {
            return Math.Clamp(candidate, 0f, max);
        }

        var min = _baselineThreshold * _config.MinThresholdMultiplier;
        return Math.Clamp(candidate, min, max);
    }

    private float EffectiveThresholdQuantile()
    {
        return _config.ThresholdQuantile > 0
            ? _config.ThresholdQuantile
            : 1f - _config.Alpha;
    }

    private enum CalibrationLayer
    {
        Trusted,
        Adaptive
    }

    private enum TailDirection
    {
        High,
        Low
    }

    private sealed record CalibrationSample(float Score, long Sequence, string SourceIp, bool IsSeed);

    private sealed record PendingCalibrationCandidate(
        float Score,
        long ObservedSequence,
        long MatureAtSequence,
        string SourceIp,
        CalibrationLayer Layer);

    private sealed record BankStats(float PValue, float EffectiveSampleSize, float PMin, TailDirection Direction);

    private sealed class CalibrationBank
    {
        private readonly Queue<CalibrationSample> _trustedSamples = new();
        private readonly Queue<CalibrationSample> _adaptiveSamples = new();
        private readonly Queue<PendingCalibrationCandidate> _trustedPending = new();
        private readonly Queue<PendingCalibrationCandidate> _adaptivePending = new();
        private readonly Queue<float> _recentScores = new();
        private readonly Queue<bool> _recentAlerts = new();
        private long _frozenUntilSequence;

        public CalibrationBank(string contextKey)
        {
            ContextKey = contextKey;
        }

        public string ContextKey { get; }

        public int TrustedSampleCount => _trustedSamples.Count;

        public int AdaptiveSampleCount => _adaptiveSamples.Count;

        public int SampleCount => TrustedSampleCount + AdaptiveSampleCount;

        public string? FreezeReason { get; private set; }

        public bool IsReady(AdaptiveThresholdConfig config)
        {
            return _trustedSamples.Count >= config.TrustedWarmupWindows;
        }

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

        public void QueueCandidate(PendingCalibrationCandidate candidate)
        {
            if (candidate.Layer == CalibrationLayer.Trusted)
            {
                _trustedPending.Enqueue(candidate);
            }
            else
            {
                _adaptivePending.Enqueue(candidate);
            }
        }

        public void SeedTrustedScores(IEnumerable<float> scores, long sequence, AdaptiveThresholdConfig config)
        {
            foreach (var score in scores)
            {
                if (!float.IsFinite(score) || score < 0)
                {
                    continue;
                }

                _trustedSamples.Enqueue(new CalibrationSample(score, sequence, "trusted_seed", IsSeed: true));
                while (_trustedSamples.Count > config.TrustedBankSize)
                {
                    _trustedSamples.Dequeue();
                }
            }
        }

        public void FlushPending(long sequence, AdaptiveThresholdConfig config)
        {
            if (IsFrozen(sequence))
            {
                DropMaturePending(_trustedPending, sequence);
                DropMaturePending(_adaptivePending, sequence);
                return;
            }

            FlushPendingQueue(_trustedPending, _trustedSamples, sequence, config.TrustedBankSize);
            FlushPendingQueue(_adaptivePending, _adaptiveSamples, sequence, config.AdaptiveBankSize);
        }

        public CalibrationLayer NextLayer(AdaptiveThresholdConfig config)
        {
            var trustedInFlight = _trustedSamples.Count + _trustedPending.Count;
            return trustedInFlight < config.TrustedWarmupWindows
                ? CalibrationLayer.Trusted
                : CalibrationLayer.Adaptive;
        }

        private static void DropMaturePending(Queue<PendingCalibrationCandidate> pending, long sequence)
        {
            while (pending.Count > 0 && pending.Peek().MatureAtSequence <= sequence)
            {
                pending.Dequeue();
            }
        }

        private static void FlushPendingQueue(
            Queue<PendingCalibrationCandidate> pending,
            Queue<CalibrationSample> samples,
            long sequence,
            int maxSize)
        {
            while (pending.Count > 0 && pending.Peek().MatureAtSequence <= sequence)
            {
                var candidate = pending.Dequeue();
                samples.Enqueue(new CalibrationSample(candidate.Score, sequence, candidate.SourceIp, IsSeed: false));
                while (samples.Count > maxSize)
                {
                    samples.Dequeue();
                }
            }
        }

        public BankStats ComputeStats(float score, long sequence, AdaptiveThresholdConfig config)
        {
            var sum = 0d;
            var sumSquares = 0d;
            var highTail = 0d;
            var lowTail = 0d;

            foreach (var weighted in EnumerateWeightedSamples(sequence, config))
            {
                sum += weighted.Weight;
                sumSquares += weighted.Weight * weighted.Weight;
                if (weighted.Score >= score)
                {
                    highTail += weighted.Weight;
                }

                if (weighted.Score <= score)
                {
                    lowTail += weighted.Weight;
                }
            }

            const double testWeight = 1d;
            var denominator = sum + testWeight;
            var highPValue = denominator > 0 ? (highTail + testWeight) / denominator : 1d;
            var lowPValue = denominator > 0 ? (lowTail + testWeight) / denominator : 1d;
            var direction = TailDirection.High;
            var pValue = highPValue;
            if (config.PValueMode == "two_sided" && lowPValue < highPValue)
            {
                direction = TailDirection.Low;
                pValue = lowPValue;
            }

            if (config.PValueMode == "two_sided")
            {
                pValue = Math.Min(1d, pValue * 2d);
            }

            var effectiveSampleSize = sumSquares > 0 ? sum * sum / sumSquares : 0d;
            var pMin = denominator > 0 ? testWeight / denominator : 1d;
            if (config.PValueMode == "two_sided")
            {
                pMin = Math.Min(1d, pMin * 2d);
            }

            return new BankStats((float)pValue, (float)effectiveSampleSize, (float)pMin, direction);
        }

        public float? WeightedQuantile(float quantile, long sequence, AdaptiveThresholdConfig config)
        {
            if (SampleCount == 0)
            {
                return null;
            }

            var weighted = EnumerateWeightedSamples(sequence, config)
                .Where(item => item.Weight > 0)
                .OrderBy(item => item.Score)
                .ToArray();

            if (weighted.Length == 0)
            {
                return null;
            }

            var total = weighted.Sum(item => item.Weight);
            var target = Math.Clamp(quantile, 0f, 1f) * total;
            var cumulative = 0d;
            foreach (var item in weighted)
            {
                cumulative += item.Weight;
                if (cumulative >= target)
                {
                    return item.Score;
                }
            }

            return weighted[^1].Score;
        }

        public void RecordTelemetry(float score, bool isAlert, long sequence, AdaptiveThresholdConfig config)
        {
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

            if (SampleCount == 0)
            {
                return;
            }

            var referenceMean = TrustedSampleCount > 0
                ? _trustedSamples.Average(sample => sample.Score)
                : _adaptiveSamples.Average(sample => sample.Score);
            var currentMean = _recentScores.Average();
            if (referenceMean > 0 && currentMean > referenceMean * config.DriftScoreMeanRatio)
            {
                Freeze(sequence, config, "score_mean_drift");
            }
        }

        private void Freeze(long sequence, AdaptiveThresholdConfig config, string reason)
        {
            _frozenUntilSequence = sequence + config.FreezeDurationWindows;
            FreezeReason = reason;
        }

        private static double Weight(CalibrationSample sample, long sequence, AdaptiveThresholdConfig config)
        {
            if (sample.IsSeed && !config.DecayTrustedSeed)
            {
                return Math.Clamp(1d, config.WeightClipMin, config.WeightClipMax);
            }

            var age = Math.Max(0, sequence - sample.Sequence);
            var decay = Math.Pow(0.5d, age / (double)config.RecencyHalfLifeWindows);
            return Math.Clamp(decay, config.WeightClipMin, config.WeightClipMax);
        }

        private IEnumerable<WeightedScore> EnumerateWeightedSamples(long sequence, AdaptiveThresholdConfig config)
        {
            foreach (var sample in _trustedSamples)
            {
                var weight = Weight(sample, sequence, config) * config.TrustedSampleWeight;
                if (weight > 0)
                {
                    yield return new WeightedScore(sample.Score, weight);
                }
            }

            foreach (var sample in _adaptiveSamples)
            {
                var weight = Weight(sample, sequence, config) * config.AdaptiveSampleWeight;
                if (weight > 0)
                {
                    yield return new WeightedScore(sample.Score, weight);
                }
            }
        }

        private sealed record WeightedScore(float Score, double Weight);
    }
}
