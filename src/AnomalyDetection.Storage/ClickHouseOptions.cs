namespace AnomalyDetection.Storage;

public sealed record ClickHouseOptions(
    string BaseUrl = "http://localhost:8123",
    string Database = "default",
    string User = "default",
    string Password = "adp")
{
    public Uri BuildUri(string? query = null)
    {
        var builder = new UriBuilder(BaseUrl);
        var parameters = new List<string>
        {
            $"database={Uri.EscapeDataString(Database)}",
            $"user={Uri.EscapeDataString(User)}",
            $"password={Uri.EscapeDataString(Password)}"
        };

        if (!string.IsNullOrWhiteSpace(query))
        {
            parameters.Add($"query={Uri.EscapeDataString(query)}");
        }

        builder.Query = string.Join("&", parameters);
        return builder.Uri;
    }
}
