from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]


class Status(enum.StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    NOT_RUN = "NOT_RUN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class Confidence(enum.StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    check_id: str
    title: str
    description: str
    category: str
    severity: Severity
    status: Status
    artifact: str = ""
    path: str | None = None
    line: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    confidence: Confidence = Confidence.MEDIUM
    limitations: str = ""
    baseline_suppressed: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        d["confidence"] = self.confidence.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        return cls(
            check_id=d["check_id"], title=d.get("title", ""), description=d.get("description", ""),
            category=d.get("category", ""), severity=Severity(d.get("severity", "INFO")),
            status=Status(d.get("status", "ERROR")), artifact=d.get("artifact", ""),
            path=d.get("path"), line=d.get("line"), evidence=d.get("evidence") or {},
            remediation=d.get("remediation", ""),
            confidence=Confidence(d.get("confidence", "medium")), limitations=d.get("limitations", ""),
            baseline_suppressed=bool(d.get("baseline_suppressed", False)),
        )


def is_failure(f: Finding, fail_on: set[Severity]) -> bool:
    """A finding counts against policy only when it FAIL/WARNs at/above threshold severities."""
    return f.status in (Status.FAIL, Status.WARN) and f.severity in fail_on
