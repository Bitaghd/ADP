using AnomalyDetection.Contracts;

namespace AnomalyDetection.Features;

public sealed class FeatureExtractor
{
    private readonly FeatureSchema _schema;

    public FeatureExtractor(FeatureSchema schema)
    {
        _schema = schema;
    }

    public FeatureVector Extract(ZeekConnEvent conn)
    {
        var proto = NormalizeProtocol(conn.Protocol);
        var service = NormalizeService(conn.Service, conn.DestinationPort);
        var connState = string.IsNullOrWhiteSpace(conn.ConnState) ? "other" : conn.ConnState.Trim();

        var origBytes = NonNegative(conn.OrigBytes);
        var respBytes = NonNegative(conn.RespBytes);
        var origPkts = NonNegative(conn.OrigPkts);
        var respPkts = NonNegative(conn.RespPkts);
        var origIpBytes = NonNegative(conn.OrigIpBytes);
        var respIpBytes = NonNegative(conn.RespIpBytes);
        var missedBytes = NonNegative(conn.MissedBytes);
        var duration = NonNegative(conn.Duration);
        var totalBytes = origBytes + respBytes;
        var totalIpBytes = origIpBytes + respIpBytes;
        var totalPkts = origPkts + respPkts;
        var durationDenom = Math.Max(duration, _schema.Eps);

        var rawValues = new Dictionary<string, double>(StringComparer.Ordinal)
        {
            ["protocol_encoded"] = _schema.Encode("protocol", proto),
            ["service_encoded"] = _schema.Encode("service", service),
            ["conn_state_encoded"] = _schema.Encode("conn_state", connState),
            ["duration"] = duration,
            ["orig_bytes"] = origBytes,
            ["resp_bytes"] = respBytes,
            ["orig_pkts"] = origPkts,
            ["resp_pkts"] = respPkts,
            ["orig_ip_bytes"] = origIpBytes,
            ["resp_ip_bytes"] = respIpBytes,
            ["missed_bytes"] = missedBytes,
            ["src_port"] = Math.Max(conn.SourcePort, 0),
            ["dst_port"] = Math.Max(conn.DestinationPort, 0),
            ["total_bytes"] = totalBytes,
            ["total_ip_bytes"] = totalIpBytes,
            ["total_pkts"] = totalPkts,
            ["bytes_per_sec"] = totalBytes / durationDenom,
            ["pkts_per_sec"] = totalPkts / durationDenom,
            ["orig_bytes_per_sec"] = origBytes / durationDenom,
            ["resp_bytes_per_sec"] = respBytes / durationDenom,
            ["orig_pkts_per_sec"] = origPkts / durationDenom,
            ["resp_pkts_per_sec"] = respPkts / durationDenom,
            ["orig_resp_bytes_ratio"] = origBytes / (respBytes + _schema.Eps),
            ["orig_resp_pkts_ratio"] = origPkts / (respPkts + _schema.Eps),
            ["avg_packet_size"] = totalBytes / Math.Max(totalPkts, 1),
            ["avg_orig_packet_size"] = origBytes / Math.Max(origPkts, 1),
            ["avg_resp_packet_size"] = respBytes / Math.Max(respPkts, 1),
            ["ip_payload_ratio"] = totalBytes / Math.Max(totalIpBytes, 1),
            ["has_syn"] = ContainsHistory(conn.History, 'S'),
            ["has_ack"] = ContainsHistory(conn.History, 'A'),
            ["has_fin"] = ContainsHistory(conn.History, 'F'),
            ["has_rst"] = ContainsHistory(conn.History, 'R'),
            ["has_orig_payload"] = ContainsHistory(conn.History, 'D'),
            ["has_resp_payload"] = ContainsHistory(conn.History, 'd')
        };

        var values = new float[_schema.Features.Count];
        for (var index = 0; index < _schema.Features.Count; index++)
        {
            var feature = _schema.Features[index];
            if (!rawValues.TryGetValue(feature.Name, out var value))
            {
                throw new InvalidOperationException($"Feature was not produced: {feature.Name}");
            }

            values[index] = ToFiniteFloat(value);
        }

        return new FeatureVector
        {
            Timestamp = conn.Timestamp,
            Uid = conn.Uid,
            SourceIp = conn.SourceIp,
            SourcePort = conn.SourcePort,
            DestinationIp = conn.DestinationIp,
            DestinationPort = conn.DestinationPort,
            Protocol = proto,
            Service = service,
            Label = conn.Label,
            IsAnomaly = conn.IsAnomaly,
            FeatureNames = _schema.FeatureNames,
            Values = values
        };
    }

    private static double NonNegative(double value)
    {
        return double.IsFinite(value) ? Math.Max(value, 0) : 0;
    }

    private static float ContainsHistory(string history, char value)
    {
        return history.IndexOf(value, StringComparison.Ordinal) >= 0 ? 1f : 0f;
    }

    private static float ToFiniteFloat(double value)
    {
        return double.IsFinite(value) ? (float)value : 0f;
    }

    private static string NormalizeProtocol(string protocol)
    {
        var value = protocol.Trim().ToLowerInvariant();
        return value switch
        {
            "6" => "tcp",
            "17" => "udp",
            "1" => "icmp",
            "tcp" or "udp" or "icmp" => value,
            _ => "other"
        };
    }

    private static string NormalizeService(string service, int destinationPort)
    {
        var value = service.Trim().ToLowerInvariant() switch
        {
            "https" or "tls" => "ssl",
            var known when known is "http" or "dns" or "ssl" or "ssh" => known,
            _ => string.Empty
        };

        if (!string.IsNullOrEmpty(value))
        {
            return value;
        }

        return destinationPort switch
        {
            80 or 8000 or 8008 or 8080 or 8081 => "http",
            53 => "dns",
            443 or 8443 => "ssl",
            22 => "ssh",
            _ => "other"
        };
    }
}
