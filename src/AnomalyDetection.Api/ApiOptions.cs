using Microsoft.Extensions.Configuration;

namespace AnomalyDetection.Api;

public sealed record AppPaths(string RepositoryRoot);

public sealed record ModelStatusOptions(
    string ModelPath,
    string ThresholdConfigPath,
    string TrainingReportPath,
    string EvaluationReportPath,
    string OnnxValidationReportPath,
    string PreprocessingConfigPath)
{
    public static ModelStatusOptions FromConfiguration(IConfiguration configuration, string repositoryRoot)
    {
        var section = configuration.GetSection("ModelStatus");
        return new ModelStatusOptions(
            RepositoryPaths.Resolve(repositoryRoot, section["ModelPath"] ?? Path.Combine("models", "cnn_gru_ae_example.onnx")),
            RepositoryPaths.Resolve(repositoryRoot, section["ThresholdConfigPath"] ?? Path.Combine("artifacts", "thresholds", "example.threshold_config.json")),
            RepositoryPaths.Resolve(repositoryRoot, section["TrainingReportPath"] ?? Path.Combine("artifacts", "training", "wednesday_full.training.json")),
            RepositoryPaths.Resolve(repositoryRoot, section["EvaluationReportPath"] ?? Path.Combine("artifacts", "evaluation", "wednesday_full.evaluation_report.json")),
            RepositoryPaths.Resolve(repositoryRoot, section["OnnxValidationReportPath"] ?? Path.Combine("artifacts", "onnx", "wednesday_full.onnx_validation_report.json")),
            RepositoryPaths.Resolve(repositoryRoot, section["PreprocessingConfigPath"] ?? Path.Combine("artifacts", "preprocessing", "wednesday_full.preprocessing.json")));
    }
}

public static class RepositoryPaths
{
    public static string FindRoot(params string[] candidates)
    {
        foreach (var candidate in candidates.Where(static value => !string.IsNullOrWhiteSpace(value)))
        {
            var directory = new DirectoryInfo(Path.GetFullPath(candidate));
            while (directory is not null)
            {
                if (File.Exists(Path.Combine(directory.FullName, "TrafficAnomalyDetection.slnx"))
                    || File.Exists(Path.Combine(directory.FullName, "configs", "feature_schema.json")))
                {
                    return directory.FullName;
                }

                directory = directory.Parent;
            }
        }

        return Directory.GetCurrentDirectory();
    }

    public static string Resolve(string repositoryRoot, string path)
    {
        return Path.IsPathRooted(path)
            ? Path.GetFullPath(path)
            : Path.GetFullPath(Path.Combine(repositoryRoot, path));
    }
}
