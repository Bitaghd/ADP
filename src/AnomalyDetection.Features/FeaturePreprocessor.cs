using System.Text.Json;
using AnomalyDetection.Contracts;

namespace AnomalyDetection.Features;

public sealed class FeaturePreprocessor
{
    private readonly IReadOnlyDictionary<string, ScalerStep> _steps;

    public FeaturePreprocessor(IEnumerable<ScalerStep> steps)
    {
        _steps = steps.ToDictionary(step => step.Feature, StringComparer.Ordinal);
    }

    public static FeaturePreprocessor Load(string scalerPath)
    {
        using var stream = File.OpenRead(scalerPath);
        using var document = JsonDocument.Parse(stream);
        var steps = new List<ScalerStep>();

        foreach (var feature in document.RootElement.GetProperty("features").EnumerateArray())
        {
            steps.Add(
                new ScalerStep(
                    feature.GetProperty("feature").GetString() ?? string.Empty,
                    feature.TryGetProperty("log1p", out var log1p) && log1p.GetBoolean(),
                    feature.TryGetProperty("clip", out var clip) && clip.GetBoolean(),
                    GetNullableDouble(feature, "clip_min"),
                    GetNullableDouble(feature, "clip_max"),
                    feature.GetProperty("mean").GetDouble(),
                    feature.GetProperty("std").GetDouble()));
        }

        return new FeaturePreprocessor(steps);
    }

    public FeatureVector Transform(FeatureVector vector)
    {
        var values = new float[vector.Values.Length];
        for (var index = 0; index < vector.Values.Length; index++)
        {
            var featureName = vector.FeatureNames[index];
            if (!_steps.TryGetValue(featureName, out var step))
            {
                values[index] = vector.Values[index];
                continue;
            }

            values[index] = step.Transform(vector.Values[index]);
        }

        return vector with { Values = values };
    }

    private static double? GetNullableDouble(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return property.GetDouble();
    }
}

public sealed record ScalerStep(
    string Feature,
    bool Log1P,
    bool Clip,
    double? ClipMin,
    double? ClipMax,
    double Mean,
    double Std)
{
    public float Transform(double value)
    {
        var prepared = double.IsFinite(value) ? value : 0.0;
        if (Clip)
        {
            if (ClipMin is not null)
            {
                prepared = Math.Max(prepared, ClipMin.Value);
            }

            if (ClipMax is not null)
            {
                prepared = Math.Min(prepared, ClipMax.Value);
            }
        }

        if (Log1P)
        {
            prepared = Math.Log(1.0 + Math.Max(prepared, 0.0));
        }

        var std = Math.Abs(Std) < 1e-8 ? 1.0 : Std;
        return (float)((prepared - Mean) / std);
    }
}
