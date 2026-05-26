using System.Text.Json;

namespace AnomalyDetection.Features;

public sealed class FeatureSchema
{
    public FeatureSchema(
        string schemaVersion,
        double eps,
        IReadOnlyList<FeatureDefinition> features,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, int>> categoricalEncodings)
    {
        SchemaVersion = schemaVersion;
        Eps = eps;
        Features = features.OrderBy(feature => feature.Order).ToArray();
        FeatureNames = Features.Select(feature => feature.Name).ToArray();
        CategoricalEncodings = categoricalEncodings;
    }

    public string SchemaVersion { get; }
    public double Eps { get; }
    public IReadOnlyList<FeatureDefinition> Features { get; }
    public IReadOnlyList<string> FeatureNames { get; }
    public IReadOnlyDictionary<string, IReadOnlyDictionary<string, int>> CategoricalEncodings { get; }

    public static FeatureSchema Load(string path)
    {
        using var stream = File.OpenRead(path);
        using var document = JsonDocument.Parse(stream);
        var root = document.RootElement;
        var schemaVersion = root.GetProperty("schema_version").GetString() ?? "unknown";
        var eps = root.TryGetProperty("eps", out var epsElement) ? epsElement.GetDouble() : 1e-8;

        var encodings = new Dictionary<string, IReadOnlyDictionary<string, int>>(StringComparer.OrdinalIgnoreCase);
        foreach (var encoding in root.GetProperty("categorical_encodings").EnumerateObject())
        {
            var values = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var value in encoding.Value.EnumerateObject())
            {
                values[value.Name] = value.Value.GetInt32();
            }

            encodings[encoding.Name] = values;
        }

        var features = new List<FeatureDefinition>();
        foreach (var feature in root.GetProperty("features").EnumerateArray())
        {
            features.Add(
                new FeatureDefinition(
                    feature.GetProperty("name").GetString() ?? string.Empty,
                    feature.GetProperty("order").GetInt32(),
                    feature.GetProperty("kind").GetString() ?? "numeric",
                    GetOptionalString(feature, "source"),
                    GetOptionalString(feature, "formula"),
                    GetOptionalString(feature, "encoding"),
                    feature.TryGetProperty("log1p", out var log1p) && log1p.GetBoolean(),
                    feature.TryGetProperty("non_negative", out var nonNegative) && nonNegative.GetBoolean(),
                    feature.TryGetProperty("clip", out var clip) && clip.GetBoolean()));
        }

        return new FeatureSchema(schemaVersion, eps, features, encodings);
    }

    public int Encode(string encodingName, string? rawValue)
    {
        if (!CategoricalEncodings.TryGetValue(encodingName, out var encoding))
        {
            return 0;
        }

        var value = string.IsNullOrWhiteSpace(rawValue) ? "other" : rawValue.Trim();
        if (encoding.TryGetValue(value, out var encoded))
        {
            return encoded;
        }

        if (encoding.TryGetValue(value.ToLowerInvariant(), out encoded))
        {
            return encoded;
        }

        return encoding.TryGetValue("other", out var other) ? other : 0;
    }

    public int IndexOf(string featureName)
    {
        for (var index = 0; index < FeatureNames.Count; index++)
        {
            if (string.Equals(FeatureNames[index], featureName, StringComparison.Ordinal))
            {
                return index;
            }
        }

        return -1;
    }

    private static string? GetOptionalString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var property) ? property.GetString() : null;
    }
}
