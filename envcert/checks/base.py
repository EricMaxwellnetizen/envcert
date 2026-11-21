from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from envcert.adapters.base import TaskContext
from envcert.core.models import Confidence, Finding, Severity, Status


@dataclass(frozen=True)
class CheckInfo:
    check_id: str
    title: str
    category: str
    severity: Severity  # severity assigned when the check fails
    description: str
    remediation: str
    limitations: str = ""
    dynamic: bool = False


@dataclass
class CheckContext:
    task: TaskContext
    execution: str = "none"  # none | docker | local-python | external
    repetitions: int = 3
    enable_mutation: bool = False
    max_mutants: int = 10
    external_tools: bool = False
    runner_command: str = ""
    shared: dict = field(default_factory=dict)  # checks stash run artefacts (e.g. image digest) for the report


CheckFn = Callable[[CheckContext], list[Finding]]

REGISTRY: dict[str, tuple[CheckInfo, CheckFn]] = {}


def check(info: CheckInfo):
    def deco(fn: CheckFn) -> CheckFn:
        if info.check_id in REGISTRY:
            raise ValueError(f"duplicate check id {info.check_id}")
        REGISTRY[info.check_id] = (info, fn)
        return fn

    return deco


def finding(info: CheckInfo, status: Status, description: str = "", *, severity: Severity | None = None,
            artifact: str = "", path: str | None = None, line: int | None = None,
            evidence: dict | None = None, confidence: Confidence = Confidence.MEDIUM,
            remediation: str = "", limitations: str = "") -> Finding:
    return Finding(
        check_id=info.check_id, title=info.title, description=description or info.description,
        category=info.category, severity=severity or (info.severity if status in (Status.FAIL, Status.WARN) else Severity.INFO),
        status=status, artifact=artifact, path=path, line=line, evidence=evidence or {},
        remediation=remediation or info.remediation, confidence=confidence,
        limitations=limitations or info.limitations,
    )


def passed(info: CheckInfo, description: str = "", **kw) -> Finding:
    return finding(info, Status.PASS, description, severity=Severity.INFO, **kw)


def not_run(info: CheckInfo, reason: str) -> Finding:
    return finding(info, Status.NOT_RUN, reason, severity=Severity.INFO, confidence=Confidence.HIGH)


def not_applicable(info: CheckInfo, reason: str) -> Finding:
    return finding(info, Status.NOT_APPLICABLE, reason, severity=Severity.INFO, confidence=Confidence.HIGH)
