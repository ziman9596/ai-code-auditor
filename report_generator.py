"""
report_generator.py
~~~~~~~~~~~~~~~~~~~
Converts AI Code Auditor findings into two machine-readable formats:

  • SARIF 2.1.0  – Static Analysis Results Interchange Format
    (https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
    Compatible with GitHub Advanced Security, VS Code SARIF Viewer, Azure
    DevOps, and any SARIF-aware CI pipeline.

  • OSCAL Assessment Results  – NIST Open Security Controls Assessment Language
    component/assessment-results schema (OSCAL 1.1.x)
    (https://pages.nist.gov/OSCAL/reference/latest/assessment-results/)
    Machine-readable compliance evidence suitable for GRC tooling.

Public API
----------
to_sarif(all_results, tool_version="1.0.0") -> str
    Returns a pretty-printed SARIF 2.1.0 JSON string.

to_oscal(all_results, tool_version="1.0.0") -> str
    Returns a pretty-printed OSCAL assessment-results JSON string.
"""

from __future__ import annotations

import datetime
import json
import uuid
from typing import Any

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# Map our internal severity labels to SARIF notification levels.
_SEVERITY_TO_SARIF: dict[str, str] = {
    "error":   "error",
    "warning": "warning",
    "note":    "note",
    "info":    "note",
}

# Map severity labels to OSCAL risk-state / risk-metric.
_SEVERITY_TO_OSCAL_LEVEL: dict[str, str] = {
    "error":   "high",
    "warning": "medium",
    "note":    "low",
    "info":    "low",
}


def _utc_now() -> str:
    """ISO-8601 UTC timestamp string."""
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding_rule_id(finding: dict) -> str:
    """
    Derive a stable, slug-safe rule ID from the finding title.
    E.g. "Hardcoded secret – password" -> "hardcoded-secret-password"
    """
    title: str = finding.get("title", "unknown")
    slug = title.lower()
    # keep only alphanumerics and hyphens
    import re
    slug = re.sub(r"[^a-z0-9]+", "-", slug).strip("-")
    return slug[:80]  # SARIF rule IDs have a practical length cap


def _collect_rules(findings: list[dict]) -> list[dict]:
    """
    Build a deduplicated list of SARIF ``reportingDescriptor`` objects
    (one per unique rule ID derived from finding titles).
    """
    seen: dict[str, dict] = {}
    for f in findings:
        rid = _finding_rule_id(f)
        if rid not in seen:
            seen[rid] = {
                "id": rid,
                "name": f.get("title", "Unknown"),
                "shortDescription": {"text": f.get("title", "Unknown")},
                "fullDescription":  {"text": f.get("detail", f.get("title", ""))},
                "helpUri": "https://github.com/your-org/ai-code-auditor",
                "properties": {
                    "tags": ["security" if f.get("kind") == "security" else "quality"],
                },
            }
    return list(seen.values())


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------

def to_sarif(
    all_results: dict[str, dict],
    tool_version: str = "1.0.0",
) -> str:
    """
    Convert *all_results* (the dict returned by ``run_audit_on_file_map``) to
    a valid SARIF 2.1.0 JSON string.

    Parameters
    ----------
    all_results:
        Mapping of ``rel_path -> {security_findings, logic_findings, parse_errors}``.
    tool_version:
        Semver string embedded in the SARIF ``tool.driver.version`` field.

    Returns
    -------
    str
        Pretty-printed JSON.
    """
    all_security: list[dict] = []
    all_logic: list[dict] = []
    for file_results in all_results.values():
        all_security.extend(file_results.get("security_findings", []))
        all_logic.extend(file_results.get("logic_findings", []))

    all_findings = [
        {**f, "kind": "security"} for f in all_security
    ] + [
        {**f, "kind": "logic"} for f in all_logic
    ]

    rules = _collect_rules(all_findings)

    results: list[dict[str, Any]] = []
    for f in all_findings:
        rid = _finding_rule_id(f)
        level = _SEVERITY_TO_SARIF.get(f.get("severity", "warning"), "warning")
        rel_path = f.get("file", "unknown")
        lineno = f.get("lineno") or 1

        result_obj: dict[str, Any] = {
            "ruleId": rid,
            "level": level,
            "message": {
                "text": f"{f.get('detail', '')}  Suggestion: {f.get('suggestion', '')}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": rel_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": lineno,
                        },
                    }
                }
            ],
        }
        results.append(result_obj)

    sarif_doc: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI Code Auditor",
                        "version": tool_version,
                        "informationUri": "https://github.com/your-org/ai-code-auditor",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": _utc_now(),
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


# ---------------------------------------------------------------------------
# OSCAL Assessment Results 1.1.x
# ---------------------------------------------------------------------------

def to_oscal(
    all_results: dict[str, dict],
    tool_version: str = "1.0.0",
) -> str:
    """
    Convert *all_results* to an OSCAL ``assessment-results`` JSON document.

    The document follows the NIST OSCAL 1.1.x schema:
    https://pages.nist.gov/OSCAL/reference/latest/assessment-results/

    Parameters
    ----------
    all_results:
        Mapping of ``rel_path -> {security_findings, logic_findings, parse_errors}``.
    tool_version:
        Embedded in the metadata ``version`` field.

    Returns
    -------
    str
        Pretty-printed JSON.
    """
    now = _utc_now()
    doc_uuid = str(uuid.uuid4())
    assessment_uuid = str(uuid.uuid4())

    all_security: list[dict] = []
    all_logic: list[dict] = []
    for file_results in all_results.values():
        all_security.extend(file_results.get("security_findings", []))
        all_logic.extend(file_results.get("logic_findings", []))

    observations: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []

    for f in all_security + all_logic:
        obs_uuid = str(uuid.uuid4())
        risk_uuid = str(uuid.uuid4())
        rel_path = f.get("file", "unknown")
        lineno = f.get("lineno")
        location_text = (
            f"{rel_path}:{lineno}" if lineno else rel_path
        )
        level = _SEVERITY_TO_OSCAL_LEVEL.get(f.get("severity", "warning"), "medium")

        observations.append({
            "uuid": obs_uuid,
            "title": f.get("title", "Finding"),
            "description": f.get("detail", ""),
            "methods": ["AUTOMATED"],
            "subjects": [
                {
                    "subject-uuid": str(uuid.uuid4()),
                    "type": "component",
                    "title": rel_path,
                    "props": [
                        {"name": "source-file", "value": rel_path},
                        {"name": "line-number", "value": str(lineno or "")},
                    ],
                }
            ],
            "remarks": f"Suggestion: {f.get('suggestion', '')}",
            "relevant-evidence": [
                {
                    "description": f"Location: {location_text}",
                }
            ],
        })

        risks.append({
            "uuid": risk_uuid,
            "title": f.get("title", "Risk"),
            "description": f.get("detail", ""),
            "statement": f.get("suggestion", ""),
            "status": "open",
            "characterizations": [
                {
                    "facets": [
                        {
                            "name": "likelihood",
                            "system": "https://csrc.nist.gov/projects/risk-management",
                            "value": level,
                        },
                        {
                            "name": "impact",
                            "system": "https://csrc.nist.gov/projects/risk-management",
                            "value": level,
                        },
                    ]
                }
            ],
            "related-observations": [{"observation-uuid": obs_uuid}],
        })

    oscal_doc: dict[str, Any] = {
        "assessment-results": {
            "uuid": doc_uuid,
            "metadata": {
                "title": "AI Code Auditor — Assessment Results",
                "last-modified": now,
                "version": tool_version,
                "oscal-version": "1.1.2",
                "roles": [{"id": "tool", "title": "AI Code Auditor"}],
                "parties": [
                    {
                        "uuid": str(uuid.uuid4()),
                        "type": "tool",
                        "name": f"AI Code Auditor v{tool_version}",
                    }
                ],
            },
            "import-ap": {
                "href": "#",
                "remarks": "Assessment plan imported inline.",
            },
            "results": [
                {
                    "uuid": assessment_uuid,
                    "title": "Static Analysis Assessment",
                    "description": "Automated static analysis of Python source code.",
                    "start": now,
                    "end": now,
                    "observations": observations,
                    "risks": risks,
                    "findings": [
                        {
                            "uuid": str(uuid.uuid4()),
                            "title": "Static analysis complete",
                            "description": (
                                f"Identified {len(all_security)} security finding(s) "
                                f"and {len(all_logic)} logic finding(s)."
                            ),
                            "target": {
                                "type": "objective-id",
                                "target-id": "code-quality",
                                "status": {
                                    "state": (
                                        "not-satisfied"
                                        if (all_security or all_logic)
                                        else "satisfied"
                                    )
                                },
                            },
                            "related-observations": [
                                {"observation-uuid": o["uuid"]} for o in observations
                            ],
                            "associated-risks": [
                                {"risk-uuid": r["uuid"]} for r in risks
                            ],
                        }
                    ],
                }
            ],
        }
    }
    return json.dumps(oscal_doc, indent=2)
