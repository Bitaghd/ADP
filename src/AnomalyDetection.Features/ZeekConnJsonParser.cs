using System.Globalization;
using System.Text.Json;
using AnomalyDetection.Contracts;

namespace AnomalyDetection.Features;

public static class ZeekConnJsonParser
{
    public static ZeekConnEvent ParseLine(string jsonLine)
    {
        using var document = JsonDocument.Parse(jsonLine);
        var root = document.RootElement;
        return new ZeekConnEvent
        {
            Timestamp = GetTimestamp(root, "ts"),
            Uid = GetString(root, "uid"),
            SourceIp = GetString(root, "id.orig_h"),
            SourcePort = GetInt(root, "id.orig_p"),
            DestinationIp = GetString(root, "id.resp_h"),
            DestinationPort = GetInt(root, "id.resp_p"),
            Protocol = GetString(root, "proto", "other"),
            Service = GetString(root, "service", "other"),
            ConnState = GetString(root, "conn_state", "other"),
            Duration = GetDouble(root, "duration"),
            OrigBytes = GetDouble(root, "orig_bytes"),
            RespBytes = GetDouble(root, "resp_bytes"),
            OrigPkts = GetDouble(root, "orig_pkts"),
            RespPkts = GetDouble(root, "resp_pkts"),
            OrigIpBytes = GetDouble(root, "orig_ip_bytes"),
            RespIpBytes = GetDouble(root, "resp_ip_bytes"),
            MissedBytes = GetDouble(root, "missed_bytes"),
            History = GetString(root, "history"),
            Label = GetString(root, "label", GetString(root, "label_tactic", "unknown")),
            IsAnomaly = GetBool(root, "is_anomaly") || GetBool(root, "label_binary")
        };
    }

    private static DateTimeOffset GetTimestamp(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var property))
        {
            return DateTimeOffset.UnixEpoch;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetDouble(out var epochSeconds))
        {
            var wholeSeconds = Math.Truncate(epochSeconds);
            var fractional = epochSeconds - wholeSeconds;
            return DateTimeOffset.FromUnixTimeSeconds((long)wholeSeconds)
                .AddTicks((long)(fractional * TimeSpan.TicksPerSecond));
        }

        var raw = property.GetString();
        return DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed)
            ? parsed
            : DateTimeOffset.UnixEpoch;
    }

    private static string GetString(JsonElement root, string propertyName, string defaultValue = "")
    {
        if (!root.TryGetProperty(propertyName, out var property))
        {
            return defaultValue;
        }

        return property.ValueKind switch
        {
            JsonValueKind.String => property.GetString() ?? defaultValue,
            JsonValueKind.Number => property.GetRawText(),
            _ => defaultValue
        };
    }

    private static int GetInt(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var property))
        {
            return 0;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt32(out var value))
        {
            return value;
        }

        return int.TryParse(property.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value)
            ? value
            : 0;
    }

    private static double GetDouble(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var property))
        {
            return 0;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetDouble(out var value))
        {
            return value;
        }

        var raw = property.GetString();
        return raw is null || raw == "-"
            ? 0
            : double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out value)
                ? value
                : 0;
    }

    private static bool GetBool(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var property))
        {
            return false;
        }

        return property.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Number when property.TryGetInt32(out var value) => value != 0,
            JsonValueKind.String => IsTruthy(property.GetString()),
            _ => false
        };
    }

    private static bool IsTruthy(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        return raw.Trim().ToLowerInvariant() switch
        {
            "true" or "1" or "yes" or "y" or "attack" or "anomaly" or "malicious" => true,
            _ => false
        };
    }
}
