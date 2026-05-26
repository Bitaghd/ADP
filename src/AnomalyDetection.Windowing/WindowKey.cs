using AnomalyDetection.Contracts;

namespace AnomalyDetection.Windowing;

public readonly record struct WindowKey(
    string SourceIp,
    string DestinationIp,
    int DestinationPort,
    string Protocol)
{
    public static WindowKey FromFeatureVector(FeatureVector vector)
    {
        return new WindowKey(
            vector.SourceIp,
            vector.DestinationIp,
            vector.DestinationPort,
            vector.Protocol);
    }
}
