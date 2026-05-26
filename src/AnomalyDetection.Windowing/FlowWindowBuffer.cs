using AnomalyDetection.Contracts;

namespace AnomalyDetection.Windowing;

public sealed class FlowWindowBuffer
{
    private readonly Dictionary<WindowKey, Queue<FeatureVector>> _buffers = new();
    private readonly Dictionary<WindowKey, DateTimeOffset> _lastSeen = new();
    private readonly int _windowSize;
    private readonly int _stride;
    private readonly TimeSpan _maxWindowAge;

    public FlowWindowBuffer(int windowSize = 10, int stride = 1, TimeSpan? maxWindowAge = null)
    {
        if (windowSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(windowSize));
        }

        if (stride <= 0 || stride > windowSize)
        {
            throw new ArgumentOutOfRangeException(nameof(stride));
        }

        _windowSize = windowSize;
        _stride = stride;
        _maxWindowAge = maxWindowAge ?? TimeSpan.FromMinutes(5);
    }

    public IReadOnlyList<TrafficWindow> Add(FeatureVector vector)
    {
        var key = WindowKey.FromFeatureVector(vector);
        if (!_buffers.TryGetValue(key, out var queue))
        {
            queue = new Queue<FeatureVector>();
            _buffers[key] = queue;
        }

        if (_lastSeen.TryGetValue(key, out var lastSeen) && vector.Timestamp - lastSeen > _maxWindowAge)
        {
            queue.Clear();
        }

        _lastSeen[key] = vector.Timestamp;
        queue.Enqueue(vector);

        if (queue.Count < _windowSize)
        {
            return Array.Empty<TrafficWindow>();
        }

        var window = TrafficWindow.FromVectors(queue.Take(_windowSize).ToArray());
        for (var index = 0; index < _stride && queue.Count > 0; index++)
        {
            queue.Dequeue();
        }

        return new[] { window };
    }

    public int BufferedKeyCount => _buffers.Count;
}
