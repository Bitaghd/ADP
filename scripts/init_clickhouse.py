from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path


def split_sql(sql: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        current.append(line)
        if stripped.endswith(";"):
            statement = "\n".join(current).strip().rstrip(";").strip()
            if statement:
                statements.append(statement)
            current = []
    if current:
        statements.append("\n".join(current).strip().rstrip(";").strip())
    return statements


def build_url(url: str, user: str, password: str, database: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}user={user}&password={password}&database={database}"


def post_sql(url: str, sql: str, user: str, password: str, database: str) -> str:
    request = urllib.request.Request(
        build_url(url, user, password, database),
        data=sql.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize ClickHouse schema for the anomaly prototype.")
    parser.add_argument("--url", default="http://localhost:8123")
    parser.add_argument("--user", default="default")
    parser.add_argument("--password", default="adp")
    parser.add_argument("--database", default="default")
    parser.add_argument("--schema", default=Path("infra/clickhouse/schema.sql"), type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sql = args.schema.read_text(encoding="utf-8")
    statements = split_sql(sql)
    for statement in statements:
        post_sql(args.url, statement, args.user, args.password, args.database)
    print(json.dumps({"url": args.url, "database": args.database, "statements": len(statements)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
