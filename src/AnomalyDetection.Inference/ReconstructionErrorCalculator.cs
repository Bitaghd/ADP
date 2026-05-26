namespace AnomalyDetection.Inference;

public static class ReconstructionErrorCalculator
{
    public static float MeanSquaredError(ReadOnlySpan<float> input, ReadOnlySpan<float> reconstruction)
    {
        if (input.Length != reconstruction.Length)
        {
            throw new ArgumentException("Input and reconstruction lengths must match.");
        }

        if (input.Length == 0)
        {
            return 0;
        }

        double sum = 0;
        for (var index = 0; index < input.Length; index++)
        {
            var delta = input[index] - reconstruction[index];
            sum += delta * delta;
        }

        return (float)(sum / input.Length);
    }
}
