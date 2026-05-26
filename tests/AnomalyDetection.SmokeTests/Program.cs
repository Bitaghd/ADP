using AnomalyDetection.Contracts;
using AnomalyDetection.Features;
using AnomalyDetection.Inference;
using AnomalyDetection.Windowing;

var root = FindRepositoryRoot();
var schema = FeatureSchema.Load(Path.Combine(root, "configs", "feature_schema.json"));
Assert(schema.FeatureNames.Count == 34, "feature schema must contain 34 features");

var extractor = new FeatureExtractor(schema);
var parsedLabeledConn = ZeekConnJsonParser.ParseLine(
    """
    {"ts":1730358000.643,"uid":"Cuwf","id.orig_h":"143.88.255.11","id.orig_p":53888,"id.resp_h":"8.8.4.4","id.resp_p":53,"proto":"udp","service":"dns","conn_state":"S0","label":"Reconnaissance","is_anomaly":true}
    """);
Assert(parsedLabeledConn.Label == "Reconnaissance", "Zeek JSON parser did not preserve labels");
Assert(parsedLabeledConn.IsAnomaly, "Zeek JSON parser did not preserve anomaly flag");

var buffer = new FlowWindowBuffer(windowSize: 10, stride: 1, maxWindowAge: TimeSpan.FromMinutes(5));
TrafficWindow? producedWindow = null;
FeatureVector? lastVector = null;

for (var index = 0; index < 10; index++)
{
    var vector = extractor.Extract(
        new ZeekConnEvent
        {
            Timestamp = DateTimeOffset.UnixEpoch.AddSeconds(index),
            Uid = $"C{index}",
            SourceIp = "10.0.0.1",
            SourcePort = 51000 + index,
            DestinationIp = "10.0.0.2",
            DestinationPort = 443,
            Protocol = "tcp",
            Service = "ssl",
            ConnState = "SF",
            Duration = 1.5,
            OrigBytes = 120,
            RespBytes = 280,
            OrigPkts = 3,
            RespPkts = 4,
            OrigIpBytes = 180,
            RespIpBytes = 360,
            MissedBytes = 0,
            History = "ShADadFf"
        });

    Assert(Math.Abs(vector.GetValue("total_bytes") - 400f) < 0.001f, "total_bytes derivation failed");
    Assert(vector.GetValue("has_syn") == 1f, "history SYN flag extraction failed");
    Assert(vector.GetValue("has_resp_payload") == 1f, "history responder payload extraction failed");
    lastVector = vector;

    var windows = buffer.Add(vector);
    if (windows.Count > 0)
    {
        producedWindow = windows[0];
    }
}

var preprocessor = new FeaturePreprocessor(
    new[]
    {
        new ScalerStep("total_bytes", Log1P: false, Clip: true, ClipMin: 0, ClipMax: 500, Mean: 100, Std: 10)
    });
var transformed = preprocessor.Transform(lastVector!);
Assert(Math.Abs(transformed.GetValue("total_bytes") - 30f) < 0.001f, "preprocessing scaler step failed");

Assert(producedWindow is not null, "window was not produced after 10 events");
Assert(producedWindow!.Values.Length == 10 * schema.FeatureNames.Count, "window tensor shape is wrong");

var reconstruction = producedWindow.Values.ToArray();
var zeroError = ReconstructionErrorCalculator.MeanSquaredError(producedWindow.Values, reconstruction);
Assert(zeroError == 0f, "identical reconstruction must have zero error");

reconstruction[0] += 10f;
var nonZeroError = ReconstructionErrorCalculator.MeanSquaredError(producedWindow.Values, reconstruction);
var evaluator = new ThresholdEvaluator(new ThresholdConfig("smoke", Threshold: 0.01f, ModelVersion: "smoke"));
var result = evaluator.Evaluate(producedWindow, nonZeroError);
Assert(result.IsAnomaly, "threshold evaluator did not mark high error as anomaly");

var adaptiveEvaluator = new ThresholdEvaluator(
    new ThresholdConfig(
        "target_recall",
        Threshold: 1f,
        ModelVersion: "smoke",
        Adaptive: new AdaptiveThresholdConfig(
            Enabled: true,
            WarmupWindows: 3,
            ReferenceWindow: 5,
            Quantile: 0.75f,
            MadMultiplier: 0f,
            SmoothingAlpha: 1f,
            MinThresholdMultiplier: 0.1f,
            MaxThresholdMultiplier: 10f)));
adaptiveEvaluator.Evaluate(producedWindow, 0.10f);
adaptiveEvaluator.Evaluate(producedWindow, 0.20f);
adaptiveEvaluator.Evaluate(producedWindow, 0.30f);
var adaptiveResult = adaptiveEvaluator.Evaluate(producedWindow, 0.40f);
Assert(adaptiveResult.Threshold < 1f, "adaptive threshold did not calibrate below static threshold");
Assert(adaptiveResult.IsAnomaly, "adaptive threshold did not mark drifted error as anomaly");
Assert(adaptiveResult.ThresholdMethod.Contains("rolling_quantile_mad", StringComparison.Ordinal), "adaptive threshold method was not reported");

var contextRollingEvaluator = new ThresholdEvaluator(
    new ThresholdConfig(
        "target_recall",
        Threshold: 1f,
        ModelVersion: "smoke",
        Adaptive: new AdaptiveThresholdConfig(
            Enabled: true,
            WarmupWindows: 3,
            ReferenceWindow: 5,
            Quantile: 0.75f,
            MadMultiplier: 0f,
            SmoothingAlpha: 1f,
            MinThresholdMultiplier: 0.1f,
            MaxThresholdMultiplier: 10f,
            RollingUseContext: true,
            RollingUseDelayedAdmission: true,
            PendingDelayWindows: 0,
            PendingFlushWindows: 1,
            RollingUseFreeze: true,
            MonitorWindow: 8)));
contextRollingEvaluator.Evaluate(producedWindow, 0.10f);
contextRollingEvaluator.Evaluate(producedWindow, 0.20f);
contextRollingEvaluator.Evaluate(producedWindow, 0.30f);
var contextRollingResult = contextRollingEvaluator.Evaluate(producedWindow, 0.40f);
Assert(contextRollingResult.ContextKey == "tcp|ssl|h00", "context rolling key is wrong");
Assert(contextRollingResult.ParentContextKey == "tcp|ssl", "context rolling parent key is wrong");
Assert(contextRollingResult.BankSize >= 3, "context rolling bank size was not reported");

var confidenceSequenceEvaluator = new ThresholdEvaluator(
    new ThresholdConfig(
        "target_recall",
        Threshold: 1f,
        ModelVersion: "smoke",
        Adaptive: new AdaptiveThresholdConfig(
            Enabled: true,
            Method: "confidence_sequence",
            WarmupWindows: 3,
            ReferenceWindow: 8,
            Quantile: 0.75f,
            Alpha: 0.3f,
            MinThresholdMultiplier: 0.1f,
            MaxThresholdMultiplier: 10f,
            MonitorWindow: 8,
            CsUseChangeDetection: false)));
confidenceSequenceEvaluator.Evaluate(producedWindow, 0.10f);
confidenceSequenceEvaluator.Evaluate(producedWindow, 0.20f);
confidenceSequenceEvaluator.Evaluate(producedWindow, 0.30f);
var confidenceSequenceResult = confidenceSequenceEvaluator.Evaluate(producedWindow, 0.50f);
Assert(confidenceSequenceResult.IsAnomaly, "confidence sequence calibrator did not mark score above CS upper bound as anomaly");
Assert(confidenceSequenceResult.CalibrationDecision == "alert", "confidence sequence decision was not reported as alert");
Assert(confidenceSequenceResult.ThresholdMethod.Contains("confidence_sequence", StringComparison.Ordinal), "confidence sequence method was not reported");

var conformalEvaluator = new ThresholdEvaluator(
    new ThresholdConfig(
        "target_recall",
        Threshold: 100f,
        ModelVersion: "smoke",
        Adaptive: new AdaptiveThresholdConfig(
            Enabled: true,
            Method: "weighted_conformal",
            WarmupWindows: 3,
            ReferenceWindow: 5,
            ShadowMode: false,
            Alpha: 0.3f,
            TriageBeta: 0.6f,
            BankSize: 5,
            MinEffectiveSampleSize: 1,
            RecencyHalfLifeWindows: 100,
            PendingDelayWindows: 0,
            PendingFlushWindows: 1,
            MonitorWindow: 8)));
conformalEvaluator.Evaluate(producedWindow, 0.10f);
conformalEvaluator.Evaluate(producedWindow, 0.20f);
conformalEvaluator.Evaluate(producedWindow, 0.30f);
var conformalResult = conformalEvaluator.Evaluate(producedWindow, 1000f);
Assert(conformalResult.IsAnomaly, "weighted conformal calibrator did not mark tail score as anomaly");
Assert(conformalResult.PValue is > 0 and <= 0.3f, "weighted conformal p-value is outside expected alert range");
Assert(conformalResult.TrustedBankSize == 3, "weighted conformal trusted bank was not seeded");
Assert(conformalResult.AdaptiveBankSize == 0, "weighted conformal adaptive bank should be empty before the first conformal normal");
Assert(conformalResult.ContextKey == "tcp|ssl|h00", "weighted conformal context key is wrong");
Assert(conformalResult.ThresholdMethod.Contains("weighted_conformal", StringComparison.Ordinal), "weighted conformal method was not reported");

var seedPath = Path.Combine(Path.GetTempPath(), $"trusted-bank-seed-{Guid.NewGuid():N}.json");
File.WriteAllText(
    seedPath,
    """
    {
      "schema_version": 1,
      "kind": "weighted_conformal_trusted_bank_seed",
      "banks": [
        {
          "context_key": "tcp|ssl",
          "trusted_scores": [0.1, 0.2, 0.3]
        }
      ]
    }
    """);
try
{
    var seededEvaluator = new ThresholdEvaluator(
        new ThresholdConfig(
            "target_recall",
            Threshold: 100f,
            ModelVersion: "smoke",
            Adaptive: new AdaptiveThresholdConfig(
                Enabled: true,
                Method: "weighted_conformal",
                ShadowMode: false,
                Alpha: 0.3f,
                TriageBeta: 0.6f,
                BankSize: 5,
                TrustedBankSize: 5,
                TrustedWarmupWindows: 3,
                MinEffectiveSampleSize: 1,
                RecencyHalfLifeWindows: 100,
                PendingFlushWindows: 1,
                MonitorWindow: 8,
                TrustedSeedPath: seedPath)));
    var seededResult = seededEvaluator.Evaluate(producedWindow, 1000f);
    Assert(seededResult.IsAnomaly, "seeded trusted bank did not mark tail score as anomaly");
    Assert(seededResult.PValue is > 0 and <= 0.3f, "seeded trusted bank p-value is outside expected alert range");
    Assert(seededResult.TrustedBankSize == 3, "seeded trusted bank size was not reported");
    Assert(seededResult.CalibrationMode?.StartsWith("parent:", StringComparison.Ordinal) == true, "seeded trusted bank parent fallback was not used");
}
finally
{
    File.Delete(seedPath);
}

var onnxPath = Path.Combine(root, "models", "cnn_gru_ae_wednesday_full.onnx");
if (File.Exists(onnxPath))
{
    using var runner = new OnnxModelRunner(onnxPath);
    var onnxScore = runner.Score(producedWindow);
    Assert(float.IsFinite(onnxScore), "ONNX score must be finite");
}

Console.WriteLine(
    $"Smoke OK: features={schema.FeatureNames.Count}, window={producedWindow.WindowSize}x{producedWindow.FeatureCount}, error={nonZeroError:0.0000}");

static string FindRepositoryRoot()
{
    var directory = new DirectoryInfo(Directory.GetCurrentDirectory());
    while (directory is not null)
    {
        if (Directory.Exists(Path.Combine(directory.FullName, "configs")))
        {
            return directory.FullName;
        }

        directory = directory.Parent;
    }

    throw new DirectoryNotFoundException("Could not find repository root with configs directory.");
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
