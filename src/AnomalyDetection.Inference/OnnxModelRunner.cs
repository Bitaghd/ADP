using AnomalyDetection.Contracts;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

namespace AnomalyDetection.Inference;

public sealed class OnnxModelRunner : IDisposable
{
    private readonly InferenceSession _session;
    private readonly string _inputName;
    private readonly string _outputName;

    public OnnxModelRunner(string modelPath, string inputName = "input", string outputName = "reconstruction")
    {
        if (!File.Exists(modelPath))
        {
            throw new FileNotFoundException("ONNX model file was not found.", modelPath);
        }

        _session = new InferenceSession(modelPath);
        _inputName = inputName;
        _outputName = outputName;
    }

    public float[] Reconstruct(TrafficWindow window)
    {
        if (window.Values.Length != window.WindowSize * window.FeatureCount)
        {
            throw new ArgumentException("Window values do not match window dimensions.", nameof(window));
        }

        var tensor = new DenseTensor<float>(
            window.Values,
            new[] { 1, window.WindowSize, window.FeatureCount });

        var inputs = new List<NamedOnnxValue>
        {
            NamedOnnxValue.CreateFromTensor(_inputName, tensor)
        };
        using var results = _session.Run(inputs);
        var output = results.FirstOrDefault(result => result.Name == _outputName)
            ?? throw new InvalidOperationException($"ONNX output was not found: {_outputName}");

        return output.AsTensor<float>().ToArray();
    }

    public float Score(TrafficWindow window)
    {
        var reconstruction = Reconstruct(window);
        return ReconstructionErrorCalculator.MeanSquaredError(window.Values, reconstruction);
    }

    public void Dispose()
    {
        _session.Dispose();
    }
}
