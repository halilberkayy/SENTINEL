"""Scan orchestration: turn what a scan finds into what it scans next.

A one-click "auto" scan starts from a discovery seed, reads signals out of the
results (an API surfaced, a GraphQL endpoint answered, a JWT was seen, the stack
is WordPress, ...), and schedules the follow-on modules those signals warrant.
It repeats for a bounded number of rounds until nothing new is triggered.

The functions here are pure (no I/O); the engine drives the rounds.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

# Modules to run first in auto mode: cheap discovery that produces signals.
DISCOVERY_SEED: list[str] = [
    "recon_scanner",
    "headers_scanner",
    "security_txt_scanner",
    "robots_scanner",
    "directory_scanner",
    "cors_scanner",
    "js_secrets_scanner",
    "graphql_scanner",
]

# Substrings that, seen anywhere in a result (title, type, evidence, details),
# raise a signal. Lowercase; matched against lowercased result text.
SIGNAL_MARKERS: dict[str, list[str]] = {
    "graphql": ["graphql", "/graphql", "__schema"],
    "jwt": ["jwt", "json web token", "eyj"],  # eyJ = base64url start of a JWT header
    "api": ["/api/", "swagger", "openapi", "application/json", "rest api", "x-api-key"],
    "aws": ["amazonaws.com", "x-amz-", "s3.amazonaws", "aws access key", "aws_secret"],
    "wordpress": ["wp-content", "wp-login", "wp-json", "wordpress"],
    "login": ["login", "sign in", "signin", "password field", "authentication required"],
    "grpc": ["grpc", "application/grpc"],
    "websocket": ["websocket", "ws://", "wss://"],
}

# A signal -> the module ids worth running because of it. Modules that are not
# registered or have already run are filtered out by plan_followups().
TRIGGER_RULES: dict[str, list[str]] = {
    "graphql": ["graphql_scanner"],
    "jwt": ["jwt_scanner"],
    "api": ["graphql_scanner", "jwt_scanner", "rate_limit_scanner", "broken_access_control_scanner"],
    "aws": ["dependency_scanner"],
    "wordpress": ["directory_scanner", "dependency_scanner"],
    "login": ["rate_limit_scanner", "credential_scanner", "broken_access_control_scanner"],
    "grpc": ["grpc_scanner"],
    "websocket": ["recon_scanner"],
}


def _result_text(result: Any) -> str:
    """Flatten one ScanResult (or dict) into searchable lowercase text."""
    parts: list[str] = []
    module = getattr(result, "module_name", None) or (result.get("module_name") if isinstance(result, dict) else "")
    details = getattr(result, "details", None) or (result.get("details") if isinstance(result, dict) else "")
    parts.append(str(module))
    parts.append(str(details))
    vulns = getattr(result, "vulnerabilities", None)
    if vulns is None and isinstance(result, dict):
        vulns = result.get("vulnerabilities", [])
    for v in vulns or []:
        if isinstance(v, dict):
            parts.append(str(v.get("title", "")))
            parts.append(str(v.get("type", "")))
            parts.append(str(v.get("evidence", "")))
        else:
            parts.append(str(getattr(v, "title", "")))
            parts.append(str(getattr(v, "type", "")))
            parts.append(str(getattr(v, "evidence", "")))
    return " ".join(parts).lower()


def extract_signals(results: Iterable[Any]) -> set[str]:
    """Derive the set of signals present across all scan results."""
    blob = " ".join(_result_text(r) for r in results)
    return {signal for signal, markers in SIGNAL_MARKERS.items() if any(m in blob for m in markers)}


def plan_followups(signals: Iterable[str], already_run: Iterable[str], registry: Mapping[str, Any]) -> list[str]:
    """Ordered, de-duplicated module ids to run next: triggered by a signal,
    present in the registry, and not already run. Order is stable for tests."""
    done = set(already_run)
    planned: list[str] = []
    for signal in signals:
        for module_id in TRIGGER_RULES.get(signal, []):
            if module_id in registry and module_id not in done and module_id not in planned:
                planned.append(module_id)
    return planned
