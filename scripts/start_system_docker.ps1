#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ConnLog = "artifacts/zeek/wednesday_first_2min/conn.log",
    [string]$Output = "artifacts/runtime/docker.detections.jsonl",
    [int]$MaxEvents = 0,
    [switch]$Reset,
    [switch]$Detached,
    [switch]$OpenDashboard
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

if ($Reset) {
    docker compose --profile reset run --rm clickhouse-reset
    if ($LASTEXITCODE -ne 0) {
        throw "ClickHouse reset failed."
    }
}

$env:ADP_CONN_LOG = $ConnLog
$env:ADP_OUTPUT = $Output
$env:ADP_MAX_EVENTS = [string]$MaxEvents

$arguments = @("compose", "--profile", "demo", "up", "--build")
if ($Detached) {
    $arguments += "-d"
}

docker @arguments
if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose startup failed."
}

if ($OpenDashboard) {
    Start-Process "http://localhost:5088/"
}
