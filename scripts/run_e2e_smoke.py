from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def build_clickhouse_url(base_url: str, user: str, password: str, database: str) -> str:
    query = urllib.parse.urlencode(
        {
            "user": user,
            "password": password,
            "database": database,
        }
    )
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}{query}"


def post_sql(args: argparse.Namespace, sql: str) -> str:
    request = urllib.request.Request(
        build_clickhouse_url(args.clickhouse_url, args.clickhouse_user, args.clickhouse_password, args.clickhouse_database),
        data=sql.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    with urllib.request.urlopen(request, timeout=args.http_timeout_seconds) as response:
        return response.read().decode("utf-8")


def query_json_each_row(args: argparse.Namespace, sql: str) -> list[dict[str, Any]]:
    query = sql.strip().rstrip(";")
    if "FORMAT JSONEachRow" not in query.upper():
        query = f"{query}\nFORMAT JSONEachRow"
    body = post_sql(args, query).strip()
    if not body:
        return []
    return [json.loads(line) for line in body.splitlines() if line.strip()]


def get_json(url: str, timeout_seconds: int) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_for_api(api_base_url: str, timeout_seconds: int, http_timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        if api_health_reachable(api_base_url, http_timeout_seconds):
            return
        last_error = RuntimeError("health endpoint is not reachable")
        time.sleep(0.5)
    raise RuntimeError(f"API did not become ready at {api_base_url}: {last_error}")


def start_api_if_needed(args: argparse.Namespace) -> subprocess.Popen[str] | None:
    if api_health_reachable(args.api_url, args.http_timeout_seconds):
        print(f"API already reachable: {args.api_url}")
        return None
    if args.skip_api_start:
        raise RuntimeError(f"API is not reachable: {args.api_url}")

    stdout_path = ROOT / "artifacts" / "runtime" / "e2e_api.stdout.log"
    stderr_path = ROOT / "artifacts" / "runtime" / "e2e_api.stderr.log"
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stdout = stdout_path.open("w", encoding="utf-8")
    stderr = stderr_path.open("w", encoding="utf-8")
    command = [
        "dotnet",
        "run",
        "--no-build",
        "--project",
        str(ROOT / "src" / "AnomalyDetection.Api" / "AnomalyDetection.Api.csproj"),
    ]
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdout=stdout,
        stderr=stderr,
        text=True,
    )
    wait_for_api(args.api_url, args.api_start_timeout_seconds, args.http_timeout_seconds)
    print(f"Started API pid={process.pid}; logs={stdout_path}, {stderr_path}")
    return process


def api_health_reachable(api_base_url: str, http_timeout_seconds: int) -> bool:
    try:
        get_json(f"{api_base_url.rstrip('/')}/api/health", http_timeout_seconds)
        return True
    except urllib.error.HTTPError as error:
        return error.code in {200, 503}
    except Exception:
        return False


def run_command(command: list[str], timeout_seconds: int) -> dict[str, Any]:
    print("RUN", " ".join(command))
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.stdout.strip():
        print(completed.stdout.strip())
    if completed.stderr.strip():
        print(completed.stderr.strip(), file=sys.stderr)
    if completed.returncode != 0:
        raise RuntimeError(f"Command failed with exit code {completed.returncode}: {' '.join(command)}")
    return parse_json_from_stdout(completed.stdout)


def parse_json_from_stdout(stdout: str) -> dict[str, Any]:
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start < 0 or end < start:
        raise ValueError(f"Command did not emit a JSON object: {stdout}")
    return json.loads(stdout[start : end + 1])


def table_counts(args: argparse.Namespace, table: str, anomaly_column: str | None = None) -> dict[str, int]:
    if anomaly_column is None:
        rows = query_json_each_row(args, f"SELECT count() AS total FROM {table}")
    else:
        rows = query_json_each_row(
            args,
            f"SELECT count() AS total, countIf({anomaly_column} = 1) AS positives FROM {table}",
        )
    row = rows[0] if rows else {}
    return {key: int(value) for key, value in row.items()}


def reset_clickhouse(args: argparse.Namespace) -> None:
    print("Resetting anomaly_detections and anomaly_alerts")
    post_sql(args, "TRUNCATE TABLE IF EXISTS anomaly_alerts")
    post_sql(args, "TRUNCATE TABLE IF EXISTS anomaly_detections")


def run_worker(args: argparse.Namespace) -> dict[str, Any]:
    output = resolve(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "dotnet",
        "run",
        "--no-build",
        "--project",
        str(ROOT / "src" / "AnomalyDetection.Worker" / "AnomalyDetection.Worker.csproj"),
        "--",
        "--conn-log",
        str(resolve(args.conn_log)),
        "--schema",
        str(resolve(args.schema)),
        "--scaler",
        str(resolve(args.scaler)),
        "--threshold",
        str(resolve(args.threshold)),
        "--model",
        str(resolve(args.model)),
        "--output",
        str(output),
        "--clickhouse-url",
        args.clickhouse_url,
        "--clickhouse-database",
        args.clickhouse_database,
        "--clickhouse-user",
        args.clickhouse_user,
        "--clickhouse-password",
        args.clickhouse_password,
        "--window-size",
        str(args.window_size),
        "--stride",
        str(args.stride),
        "--max-window-age-seconds",
        str(args.max_window_age_seconds),
    ]
    if args.max_events > 0:
        command.extend(["--max-events", str(args.max_events)])
    return run_command(command, args.command_timeout_seconds)


def run_alerts(args: argparse.Namespace) -> dict[str, Any]:
    command = [
        "dotnet",
        "run",
        "--no-build",
        "--project",
        str(ROOT / "src" / "AnomalyDetection.Alerts" / "AnomalyDetection.Alerts.csproj"),
        "--",
        "--clickhouse-url",
        args.clickhouse_url,
        "--clickhouse-database",
        args.clickhouse_database,
        "--clickhouse-user",
        args.clickhouse_user,
        "--clickhouse-password",
        args.clickhouse_password,
        "--lookback-hours",
        str(args.alert_lookback_hours),
        "--rule-window-minutes",
        str(args.rule_window_minutes),
        "--series-anomaly-count",
        str(args.series_anomaly_count),
        "--high-rate-minimum-windows",
        str(args.high_rate_minimum_windows),
        "--high-anomaly-rate",
        str(args.high_anomaly_rate),
    ]
    return run_command(command, args.command_timeout_seconds)


def verify_api(args: argparse.Namespace) -> dict[str, Any]:
    api_url = args.api_url.rstrip("/")
    overview_query = urllib.parse.urlencode(
        {
            "lookbackHours": args.api_lookback_hours,
            "bucketMinutes": args.api_bucket_minutes,
        }
    )
    detections_query = urllib.parse.urlencode(
        {
            "limit": 5,
            "offset": 0,
            "lookbackHours": args.api_lookback_hours,
        }
    )
    alerts_query = urllib.parse.urlencode(
        {
            "limit": 5,
            "offset": 0,
            "lookbackHours": args.api_lookback_hours,
        }
    )
    overview = get_json(f"{api_url}/api/overview?{overview_query}", args.http_timeout_seconds)
    detections = get_json(f"{api_url}/api/detections?{detections_query}", args.http_timeout_seconds)
    alerts = get_json(f"{api_url}/api/alerts?{alerts_query}", args.http_timeout_seconds)
    model = get_json(f"{api_url}/api/model/status", args.http_timeout_seconds)
    return {
        "overview_total": int(overview["summary"]["totalDetections"]),
        "overview_anomalies": int(overview["summary"]["anomalies"]),
        "detections_page_total": int(detections["total"]),
        "alerts_total": int(alerts["summary"]["total"]),
        "alerts_unacknowledged": int(alerts["summary"]["unacknowledged"]),
        "model_status": model["status"],
        "storage_status": model["storage"]["status"],
    }


def assert_at_least(name: str, actual: int, expected: int) -> None:
    if actual < expected:
        raise AssertionError(f"{name} expected >= {expected}, got {actual}")


def resolve(path: str) -> Path:
    value = Path(path)
    return value if value.is_absolute() else ROOT / value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run an end-to-end smoke check for worker, alerts, and API.")
    parser.add_argument("--conn-log", default="artifacts/zeek/wednesday_first_2min/conn.log")
    parser.add_argument("--schema", default="configs/feature_schema.json")
    parser.add_argument("--scaler", default="artifacts/scalers/wednesday_full.scaler.json")
    parser.add_argument("--threshold", default="artifacts/thresholds/wednesday_full.threshold_config.json")
    parser.add_argument("--model", default="models/cnn_gru_ae_wednesday_full.onnx")
    parser.add_argument("--output", default="artifacts/runtime/e2e_smoke.detections.jsonl")
    parser.add_argument("--max-events", type=int, default=0)
    parser.add_argument("--window-size", type=int, default=10)
    parser.add_argument("--stride", type=int, default=1)
    parser.add_argument("--max-window-age-seconds", type=int, default=300)
    parser.add_argument("--clickhouse-url", default="http://localhost:8123")
    parser.add_argument("--clickhouse-database", default="default")
    parser.add_argument("--clickhouse-user", default="default")
    parser.add_argument("--clickhouse-password", default="adp")
    parser.add_argument("--api-url", default="http://localhost:5088")
    parser.add_argument("--api-lookback-hours", type=int, default=0)
    parser.add_argument("--api-bucket-minutes", type=int, default=1)
    parser.add_argument("--alert-lookback-hours", type=int, default=0)
    parser.add_argument("--rule-window-minutes", type=int, default=15)
    parser.add_argument("--series-anomaly-count", type=int, default=3)
    parser.add_argument("--high-rate-minimum-windows", type=int, default=20)
    parser.add_argument("--high-anomaly-rate", type=float, default=0.2)
    parser.add_argument("--expect-min-windows", type=int, default=1)
    parser.add_argument("--expect-min-anomalies", type=int, default=0)
    parser.add_argument("--expect-min-alert-candidates", type=int, default=0)
    parser.add_argument("--expect-min-alerts-total", type=int, default=0)
    parser.add_argument("--command-timeout-seconds", type=int, default=300)
    parser.add_argument("--http-timeout-seconds", type=int, default=15)
    parser.add_argument("--api-start-timeout-seconds", type=int, default=30)
    parser.add_argument("--skip-api-start", action="store_true")
    parser.add_argument("--keep-started-api", action="store_true")
    parser.add_argument("--reset-clickhouse", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started_api: subprocess.Popen[str] | None = None
    try:
        if args.reset_clickhouse:
            reset_clickhouse(args)

        before_detections = table_counts(args, "anomaly_detections", "is_anomaly")
        before_alerts = table_counts(args, "anomaly_alerts")
        print(json.dumps({"before_detections": before_detections, "before_alerts": before_alerts}, indent=2))

        worker = run_worker(args)
        assert_at_least("worker windows", int(worker["windows"]), args.expect_min_windows)
        assert_at_least("worker anomalies", int(worker["anomalies"]), args.expect_min_anomalies)
        if worker.get("clickhouse_enabled") and int(worker["clickhouse_inserted"]) != int(worker["windows"]):
            raise AssertionError(f"ClickHouse inserted {worker['clickhouse_inserted']} rows, worker produced {worker['windows']} windows")

        alerts = run_alerts(args)
        assert_at_least("alert candidates", int(alerts["CandidateAlerts"]), args.expect_min_alert_candidates)

        started_api = start_api_if_needed(args)
        api = verify_api(args)
        if api["model_status"] not in {"ready", "degraded"}:
            raise AssertionError(f"Unexpected model status: {api['model_status']}")
        if api["storage_status"] != "online":
            raise AssertionError(f"Storage is not online: {api['storage_status']}")
        assert_at_least("API detections total", api["overview_total"], before_detections["total"] + int(worker["windows"]))
        assert_at_least("API alerts total", api["alerts_total"], args.expect_min_alerts_total)

        after_detections = table_counts(args, "anomaly_detections", "is_anomaly")
        after_alerts = table_counts(args, "anomaly_alerts")
        result = {
            "status": "ok",
            "worker": worker,
            "alerts": alerts,
            "api": api,
            "before": {
                "detections": before_detections,
                "alerts": before_alerts,
            },
            "after": {
                "detections": after_detections,
                "alerts": after_alerts,
            },
        }
        print(json.dumps(result, indent=2))
        return 0
    finally:
        if started_api is not None and not args.keep_started_api:
            started_api.terminate()
            try:
                started_api.wait(timeout=5)
            except subprocess.TimeoutExpired:
                started_api.kill()


if __name__ == "__main__":
    raise SystemExit(main())
