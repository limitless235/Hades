"""D6 — structured security telemetry and simple SIEM detectors."""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Deque, Optional


@dataclass
class TelemetryEvent:
    ts: float
    event_type: str
    username: Optional[str] = None
    role: Optional[str] = None
    defense_level: Optional[str] = None
    request_hash: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    ts: float
    rule: str
    severity: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)


class TelemetryBus:
    def __init__(self, path: Optional[Path] = None, alerts_path: Optional[Path] = None):
        self.path = path
        self.alerts_path = alerts_path
        self.events: list[TelemetryEvent] = []
        self.alerts: list[Alert] = []
        self._restricted_hits: dict[str, Deque[float]] = defaultdict(deque)
        self._acl_denials: dict[str, Deque[float]] = defaultdict(deque)

    def emit(self, event: TelemetryEvent) -> None:
        self.events.append(event)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(event)) + "\n")
        self._evaluate(event)

    def _write_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)
        if self.alerts_path:
            self.alerts_path.parent.mkdir(parents=True, exist_ok=True)
            with self.alerts_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(alert)) + "\n")

    def _evaluate(self, event: TelemetryEvent) -> None:
        user = event.username or "anonymous"
        now = event.ts
        window = 300.0

        if event.event_type == "retrieval":
            classifications = event.detail.get("classifications", [])
            if any(c in {"restricted", "highly_restricted"} for c in classifications):
                q = self._restricted_hits[user]
                q.append(now)
                while q and now - q[0] > window:
                    q.popleft()
                if len(q) >= 50:
                    self._write_alert(
                        Alert(
                            ts=now,
                            rule="burst_restricted_retrieval",
                            severity="high",
                            message=f"{user} retrieved 50+ restricted docs in 5 minutes",
                            detail={"count": len(q)},
                        )
                    )

        if event.event_type == "acl_denial":
            q = self._acl_denials[user]
            q.append(now)
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= 10:
                self._write_alert(
                    Alert(
                        ts=now,
                        rule="repeated_acl_denials",
                        severity="medium",
                        message=f"{user} hit 10+ ACL denials in 5 minutes",
                        detail={"count": len(q)},
                    )
                )

        if event.event_type == "gateway_block" and event.detail.get("classification") == "jailbreak":
            self._write_alert(
                Alert(
                    ts=now,
                    rule="jailbreak_attempt",
                    severity="medium",
                    message=f"Jailbreak-shaped prompt blocked for {user}",
                    detail=event.detail,
                )
            )


_BUS: Optional[TelemetryBus] = None


def get_telemetry() -> TelemetryBus:
    global _BUS
    if _BUS is None:
        _BUS = TelemetryBus()
    return _BUS


def reset_telemetry(
    path: Optional[Path] = None, alerts_path: Optional[Path] = None
) -> TelemetryBus:
    global _BUS
    _BUS = TelemetryBus(path=path, alerts_path=alerts_path)
    return _BUS


def now() -> float:
    return time.time()
