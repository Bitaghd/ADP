#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ConnLog = "artifacts\zeek\wednesday_first_2min\conn.log",
    [string]$Scaler = "artifacts\scalers\wednesday_full.scaler.json",
    [string]$Threshold = "artifacts\thresholds\wednesday_full.threshold_config.json",
    [string]$Model = "models\cnn_gru_ae_wednesday_full.onnx",
    [string]$Output = "artifacts\runtime\start_system.detections.jsonl",
    [string]$ClickHouseUrl = "http://localhost:8123",
    [string]$ClickHouseDatabase = "default",
    [string]$ClickHouseUser = "default",
    [string]$ClickHousePassword = "adp",
    [string]$ApiUrl = "http://localhost:5088",
    [int]$MaxEvents = 0,
    [switch]$ResetClickHouse,
    [switch]$SkipDocker,
    [switch]$SkipBuild,
    [switch]$SkipReplay,
    [switch]$SkipAlerts,
    [switch]$OpenDashboard
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RuntimeDir = Join-Path $Root "artifacts\runtime"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Resolve-RepoPath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    return Join-Path $Root $Path
}

function Invoke-External {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    Write-Host ">> $FilePath $($Arguments -join ' ')" -ForegroundColor DarkGray
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

function Wait-Until {
    param(
        [string]$Name,
        [scriptblock]$Probe,
        [int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null
    while ((Get-Date) -lt $deadline) {
        try {
            if (& $Probe) {
                Write-Host "$Name is ready" -ForegroundColor Green
                return
            }
        }
        catch {
            $lastError = $_.Exception.Message
        }

        Start-Sleep -Seconds 2
    }

    throw "$Name did not become ready within $TimeoutSeconds seconds. Last error: $lastError"
}

function Test-HttpOk {
    param([string]$Url)
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 5
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 300
    }
    catch {
        return $false
    }
}

function Test-DockerReady {
    & docker version --format "{{.Server.Version}}" *> $null
    return $LASTEXITCODE -eq 0
}

function Get-ClickHouseQueryUrl {
    $user = [Uri]::EscapeDataString($ClickHouseUser)
    $password = [Uri]::EscapeDataString($ClickHousePassword)
    $database = [Uri]::EscapeDataString($ClickHouseDatabase)
    $separator = if ($ClickHouseUrl.Contains("?")) { "&" } else { "?" }
    return "${ClickHouseUrl}${separator}user=${user}&password=${password}&database=${database}"
}

function Invoke-ClickHouseSql {
    param([string]$Sql)
    Invoke-RestMethod `
        -Method Post `
        -Uri (Get-ClickHouseQueryUrl) `
        -Body $Sql `
        -ContentType "text/plain; charset=utf-8" `
        -TimeoutSec 30 | Out-Null
}

function Stop-ApiProcesses {
    $processes = Get-Process -Name "AnomalyDetection.Api" -ErrorAction SilentlyContinue
    if (-not $processes) {
        return
    }

    Write-Step "Stopping existing API process before build"
    foreach ($process in $processes) {
        Write-Host "Stopping AnomalyDetection.Api pid=$($process.Id)"
        Stop-Process -Id $process.Id -Force
    }
}

function Start-ApiIfNeeded {
    if (Test-HttpOk "$ApiUrl/api/health") {
        Write-Host "API already reachable: $ApiUrl" -ForegroundColor Green
        return
    }

    Write-Step "Starting API/dashboard"
    New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null
    $stdout = Join-Path $RuntimeDir "start_system.api.stdout.log"
    $stderr = Join-Path $RuntimeDir "start_system.api.stderr.log"
    $arguments = @(
        "run",
        "--no-build",
        "--project",
        "src\AnomalyDetection.Api\AnomalyDetection.Api.csproj"
    )

    $process = Start-Process `
        -WindowStyle Hidden `
        -FilePath "dotnet" `
        -ArgumentList $arguments `
        -WorkingDirectory $Root `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru

    Wait-Until "API" { Test-HttpOk "$ApiUrl/api/health" } 45
    Write-Host "Started API pid=$($process.Id)"
    Write-Host "API logs: $stdout"
    Write-Host "API errors: $stderr"
}

Set-Location $Root
New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null

Write-Step "Checking required files"
$requiredFiles = @($ConnLog, $Scaler, $Threshold, $Model)
foreach ($file in $requiredFiles) {
    $resolved = Resolve-RepoPath $file
    if (-not (Test-Path $resolved)) {
        throw "Required file not found: $file"
    }
}

if (-not $SkipDocker) {
    Write-Step "Checking Docker daemon"
    if (-not (Test-DockerReady)) {
        throw "Docker daemon is not reachable. Start Docker Desktop, then run this script again. Use -SkipDocker only if ClickHouse and Kafka are already running."
    }

    Write-Step "Starting Docker infrastructure"
    Invoke-External "docker" @("compose", "up", "-d", "clickhouse", "kafka")

    Write-Step "Waiting for ClickHouse"
    Wait-Until "ClickHouse" { Test-HttpOk "$ClickHouseUrl/ping" } 90

    Write-Step "Waiting for Kafka"
    Wait-Until "Kafka" {
        & docker exec adp-kafka kafka-topics --bootstrap-server localhost:9092 --list *> $null
        return $LASTEXITCODE -eq 0
    } 90
}

if (-not $SkipBuild) {
    Stop-ApiProcesses
    Write-Step "Building .NET solution"
    Invoke-External "dotnet" @("build", "TrafficAnomalyDetection.slnx")
}

Write-Step "Initializing ClickHouse schema"
Invoke-External "python" @(
    "scripts\init_clickhouse.py",
    "--url", $ClickHouseUrl,
    "--user", $ClickHouseUser,
    "--password", $ClickHousePassword,
    "--database", $ClickHouseDatabase
)

Write-Step "Ensuring Kafka topics"
Invoke-External "powershell" @(
    "-ExecutionPolicy", "Bypass",
    "-File", "infra\kafka\create_topics.ps1"
)

if ($ResetClickHouse) {
    Write-Step "Resetting Zeek, detection, and alert tables"
    Invoke-ClickHouseSql "TRUNCATE TABLE IF EXISTS zeek_conn_events"
    Invoke-ClickHouseSql "TRUNCATE TABLE IF EXISTS anomaly_alerts"
    Invoke-ClickHouseSql "TRUNCATE TABLE IF EXISTS anomaly_detections"
}

if (-not $SkipReplay) {
    Write-Step "Running worker replay into ClickHouse"
    $workerArgs = @(
        "run",
        "--no-build",
        "--project", "src\AnomalyDetection.Worker\AnomalyDetection.Worker.csproj",
        "--",
        "--conn-log", $ConnLog,
        "--schema", "configs\feature_schema.json",
        "--scaler", $Scaler,
        "--threshold", $Threshold,
        "--model", $Model,
        "--output", $Output,
        "--clickhouse-url", $ClickHouseUrl,
        "--clickhouse-database", $ClickHouseDatabase,
        "--clickhouse-user", $ClickHouseUser,
        "--clickhouse-password", $ClickHousePassword
    )
    if ($MaxEvents -gt 0) {
        $workerArgs += @("--max-events", [string]$MaxEvents)
    }

    Invoke-External "dotnet" $workerArgs
}

if (-not $SkipAlerts) {
    Write-Step "Materializing alerts"
    Invoke-External "dotnet" @(
        "run",
        "--no-build",
        "--project", "src\AnomalyDetection.Alerts\AnomalyDetection.Alerts.csproj",
        "--",
        "--clickhouse-url", $ClickHouseUrl,
        "--clickhouse-database", $ClickHouseDatabase,
        "--clickhouse-user", $ClickHouseUser,
        "--clickhouse-password", $ClickHousePassword
    )
}

Start-ApiIfNeeded

Write-Step "System is ready"
Write-Host "Dashboard: $ApiUrl/"
Write-Host "Health:    $ApiUrl/api/health"
Write-Host "Load:      $ApiUrl/api/system/load"

if ($OpenDashboard) {
    Start-Process "$ApiUrl/"
}
