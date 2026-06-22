#!/usr/bin/env python3
"""Send repeated HTTP requests to a target host for live traffic capture tests."""

from __future__ import annotations

import argparse
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send repeated HTTP requests to a target host."
    )
    parser.add_argument("--target-url", required=True, help="HTTP/HTTPS URL to request.")
    parser.add_argument("--count", type=int, default=300, help="Total request count.")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=12,
        help="Maximum number of concurrent requests.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds.",
    )
    parser.add_argument(
        "--delay-seconds",
        type=float,
        default=0.0,
        help="Delay before scheduling each request.",
    )
    parser.add_argument(
        "--user-agent",
        default="ADP-LiveTrafficProbe/1.0",
        help="User-Agent header value.",
    )
    parser.add_argument(
        "--insecure-skip-certificate-check",
        action="store_true",
        help="Disable TLS certificate verification for HTTPS targets.",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    parsed = urllib.parse.urlparse(args.target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("--target-url must be an absolute http or https URL.")
    if args.count <= 0:
        raise ValueError("--count must be greater than 0.")
    if args.concurrency <= 0:
        raise ValueError("--concurrency must be greater than 0.")
    if args.timeout_seconds <= 0:
        raise ValueError("--timeout-seconds must be greater than 0.")
    if args.delay_seconds < 0:
        raise ValueError("--delay-seconds must be greater than or equal to 0.")


def send_request(
    target_url: str,
    timeout_seconds: float,
    user_agent: str,
    context: ssl.SSLContext | None,
) -> int:
    request = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": user_agent,
            "Cache-Control": "no-cache",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout_seconds,
            context=context,
        ) as response:
            response.read(1)
            return response.status
    except urllib.error.HTTPError as response:
        response.read(1)
        return response.code


def main() -> int:
    args = parse_args()
    try:
        validate_args(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    concurrency = min(args.concurrency, args.count)
    context = (
        ssl._create_unverified_context()
        if args.insecure_skip_certificate_check
        else None
    )
    failures = 0

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = []
        for _ in range(args.count):
            if args.delay_seconds > 0:
                time.sleep(args.delay_seconds)
            futures.append(
                executor.submit(
                    send_request,
                    args.target_url,
                    args.timeout_seconds,
                    args.user_agent,
                    context,
                )
            )

        for future in as_completed(futures):
            try:
                future.result()
            except (OSError, urllib.error.URLError) as exc:
                failures += 1
                print(f"request failed: {exc}", file=sys.stderr)

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
