using AnomalyDetection.Api;
using AnomalyDetection.Storage;
using System.Net;

var builder = WebApplication.CreateBuilder(args);

var configuredUrls = builder.Configuration["Urls"];
if (!string.IsNullOrWhiteSpace(configuredUrls))
{
    builder.WebHost.UseUrls(configuredUrls);
}

var repositoryRoot = RepositoryPaths.FindRoot(
    Directory.GetCurrentDirectory(),
    builder.Environment.ContentRootPath,
    AppContext.BaseDirectory);

builder.Services.AddSingleton(new AppPaths(repositoryRoot));
builder.Services.AddSingleton(BindClickHouseOptions(builder.Configuration));
builder.Services.AddSingleton(new HttpClient { Timeout = TimeSpan.FromSeconds(10) });
builder.Services.AddScoped<ClickHouseHttpClient>();
builder.Services.AddScoped<ClickHouseTelemetryRepository>();
builder.Services.AddSingleton(ModelStatusOptions.FromConfiguration(builder.Configuration, repositoryRoot));
builder.Services.AddSingleton<ModelStatusService>();
builder.Services.AddSingleton<SystemLoadService>();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

var api = app.MapGroup("/api");

api.MapGet("/overview", async (
    ClickHouseTelemetryRepository repository,
    int? lookbackHours,
    int? bucketMinutes,
    CancellationToken cancellationToken) =>
{
    return await ReadResult(() => repository.GetOverviewAsync(
        new OverviewQuery(lookbackHours ?? 0, bucketMinutes ?? 1),
        cancellationToken));
});

api.MapGet("/detections", async (
    ClickHouseTelemetryRepository repository,
    int? limit,
    int? offset,
    bool? anomaliesOnly,
    int? lookbackHours,
    string? srcIp,
    string? dstIp,
    string? proto,
    CancellationToken cancellationToken) =>
{
    return await ReadResult(() => repository.GetDetectionsAsync(
        new DetectionsQuery(
            limit ?? 100,
            offset ?? 0,
            anomaliesOnly ?? false,
            lookbackHours ?? 0,
            srcIp,
            dstIp,
            proto),
        cancellationToken));
});

api.MapGet("/network/stats", async (
    ClickHouseTelemetryRepository repository,
    int? lookbackHours,
    int? bucketMinutes,
    CancellationToken cancellationToken) =>
{
    return await ReadResult(() => repository.GetNetworkStatsAsync(
        new NetworkStatsQuery(lookbackHours ?? 0, bucketMinutes ?? 1),
        cancellationToken));
});

api.MapGet("/alerts", async (
    ClickHouseTelemetryRepository repository,
    int? limit,
    int? offset,
    int? lookbackHours,
    string? severity,
    bool? unacknowledgedOnly,
    CancellationToken cancellationToken) =>
{
    return await ReadResult(() => repository.GetAlertsAsync(
        new AlertsQuery(
            limit ?? 100,
            offset ?? 0,
            lookbackHours ?? 0,
            severity,
            unacknowledgedOnly ?? false),
        cancellationToken));
});

api.MapGet("/model/status", async (
    ModelStatusService statusService,
    ClickHouseTelemetryRepository repository,
    CancellationToken cancellationToken) =>
{
    return await ReadResult(() => statusService.GetStatusAsync(repository, cancellationToken));
});

api.MapGet("/system/load", (SystemLoadService loadService) =>
{
    return Results.Ok(loadService.GetSnapshot());
});

api.MapGet("/health", async (
    ClickHouseTelemetryRepository repository,
    CancellationToken cancellationToken) =>
{
    var storage = await repository.GetStorageStatusAsync(cancellationToken);
    return Results.Json(new
    {
        status = storage.Reachable ? "ok" : "degraded",
        storage
    }, statusCode: storage.Reachable ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable);
});

app.MapFallbackToFile("index.html");

app.Run();

static ClickHouseOptions BindClickHouseOptions(IConfiguration configuration)
{
    var section = configuration.GetSection("ClickHouse");
    return new ClickHouseOptions(
        section["BaseUrl"] ?? "http://localhost:8123",
        section["Database"] ?? "default",
        section["User"] ?? "default",
        section["Password"] ?? "adp");
}

static async Task<IResult> ReadResult<T>(Func<Task<T>> read)
{
    try
    {
        return Results.Ok(await read());
    }
    catch (OperationCanceledException)
    {
        throw;
    }
    catch (HttpRequestException exception)
    {
        return Results.Problem(
            title: "ClickHouse request failed",
            detail: exception.Message,
            statusCode: (int)HttpStatusCode.ServiceUnavailable);
    }
    catch (Exception exception)
    {
        return Results.Problem(
            title: "API request failed",
            detail: exception.Message,
            statusCode: (int)HttpStatusCode.InternalServerError);
    }
}
