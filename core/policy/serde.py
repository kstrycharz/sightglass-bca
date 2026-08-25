"""The gate verdict on the wire.

One schema, used in both directions: the API serialises a verdict with
:func:`verdict_to_dict`, the CLI rebuilds it with :func:`verdict_from_dict` and
renders it locally. Sharing the codec is what stops the two drifting into a
CI client that quietly mis-reports the decision it was given.

Round-tripping is tested, because a gate whose wire format loses a violation is
a gate that passes a build it should have failed.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from core.policy.model import (
    GateDecision,
    GateFinding,
    GateVerdict,
    Violation,
    ViolationKind,
    WaivedFinding,
)
from core.vocab import Severity


def verdict_to_dict(verdict: GateVerdict) -> dict[str, Any]:
    return {
        "decision": verdict.decision.value,
        "exit_code": verdict.exit_code,
        "policy_name": verdict.policy_name,
        "total_findings": verdict.total_findings,
        "counts_by_severity": dict(verdict.counts_by_severity),
        "new_counts_by_severity": dict(verdict.new_counts_by_severity),
        "degraded_stages": list(verdict.degraded_stages),
        "warnings": list(verdict.warnings),
        "violations": [
            {
                "kind": v.kind.value,
                "detail": v.detail,
                "finding_id": v.finding_id,
                "rule_id": v.rule_id,
                "severity": v.severity.value if v.severity is not None else None,
                "title": v.title,
                "artifact_path": v.artifact_path,
            }
            for v in verdict.violations
        ],
        "waived": [
            {
                "finding_id": w.finding_id,
                "title": w.title,
                "severity": w.severity.value,
                "owner": w.owner,
                "reason": w.reason,
                "expires": w.expires.isoformat(),
            }
            for w in verdict.waived
        ],
        "inherited": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "category": f.category,
                "title": f.title,
                "severity": f.severity.value,
                "status": f.status,
                "artifact_path": f.artifact_path,
            }
            for f in verdict.inherited
        ],
    }


def verdict_from_dict(payload: dict[str, Any]) -> GateVerdict:
    return GateVerdict(
        decision=GateDecision(str(payload["decision"])),
        policy_name=str(payload.get("policy_name", "unknown")),
        violations=tuple(
            Violation(
                kind=ViolationKind(str(v["kind"])),
                detail=str(v.get("detail", "")),
                finding_id=str(v.get("finding_id", "")),
                rule_id=str(v.get("rule_id", "")),
                severity=Severity(v["severity"]) if v.get("severity") else None,
                title=str(v.get("title", "")),
                artifact_path=str(v.get("artifact_path", "")),
            )
            for v in payload.get("violations", [])
        ),
        waived=tuple(
            WaivedFinding(
                finding_id=str(w["finding_id"]),
                title=str(w.get("title", "")),
                severity=Severity(str(w["severity"])),
                owner=str(w.get("owner", "")),
                reason=str(w.get("reason", "")),
                expires=date.fromisoformat(str(w["expires"])),
            )
            for w in payload.get("waived", [])
        ),
        inherited=tuple(
            GateFinding(
                id=str(f["id"]),
                rule_id=str(f.get("rule_id", "")),
                category=str(f.get("category", "")),
                title=str(f.get("title", "")),
                severity=Severity(str(f["severity"])),
                status=str(f.get("status", "open")),
                is_new=False,
                artifact_path=str(f.get("artifact_path", "")),
            )
            for f in payload.get("inherited", [])
        ),
        degraded_stages=tuple(payload.get("degraded_stages", [])),
        counts_by_severity=dict(payload.get("counts_by_severity", {})),
        new_counts_by_severity=dict(payload.get("new_counts_by_severity", {})),
        total_findings=int(payload.get("total_findings", 0)),
        warnings=tuple(payload.get("warnings", [])),
    )
