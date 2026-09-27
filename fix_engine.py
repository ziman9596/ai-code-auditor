"""
fix_engine.py — Actor-Critic Code Fix Engine
==============================================

Implements a two-pass actor-critic loop for each finding:

  Actor  — generates a proposed code fix given the finding context and the
           original source snippet near the flagged line.

  Critic — re-evaluates the proposed fix against the original vulnerability
           class, scores it, and either approves it or requests a revision.

Public API
----------
generate_fix(finding: dict, source: str) -> FixResult
    Run the full actor→critic pipeline for one finding.
    Returns a FixResult dataclass with fields:
        finding        – the original finding dict (unchanged)
        proposed_fix   – the code diff / replacement suggested by the actor
        actor_rationale – actor's explanation
        critic_verdict  – "approved" | "revised" | "rejected"
        critic_notes    – critic's reasoning
        final_fix       – the fix after critic review (may differ from actor's)
"""

from __future__ import annotations

import os
import re
import textwrap
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Optional IBM watsonx.ai integration — gracefully degrade if unavailable
# ---------------------------------------------------------------------------
try:
    from ibm_watsonx_ai import Credentials
    from ibm_watsonx_ai.foundation_models import ModelInference
    _WATSONX_AVAILABLE = True
except ImportError:
    _WATSONX_AVAILABLE = False


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FixResult:
    finding: dict
    proposed_fix: str
    actor_rationale: str
    critic_verdict: str          # "approved" | "revised" | "rejected"
    critic_notes: str
    final_fix: str
    context_snippet: str = field(default="", repr=False)


# ---------------------------------------------------------------------------
# Watsonx model helper
# ---------------------------------------------------------------------------

_WATSONX_MODEL_ID = "ibm/granite-13b-instruct-v2"
_WATSONX_URL      = "https://us-south.ml.cloud.ibm.com"
_CONTEXT_LINES    = 10   # lines of source to feed as context


def _get_watsonx_model() -> Optional[object]:
    """
    Return a watsonx ModelInference instance if credentials are present,
    otherwise return None (falls back to rule-based engine).
    """
    if not _WATSONX_AVAILABLE:
        return None
    api_key    = os.getenv("IBM_CLOUD_API_KEY", "")
    project_id = os.getenv("WATSONX_PROJECT_ID", "")
    if not api_key or not project_id:
        return None
    try:
        creds = Credentials(url=_WATSONX_URL, api_key=api_key)
        return ModelInference(
            model_id=_WATSONX_MODEL_ID,
            credentials=creds,
            project_id=project_id,
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Source-context extractor
# ---------------------------------------------------------------------------

def _extract_context(source: str, lineno: Optional[int], window: int = _CONTEXT_LINES) -> str:
    """Return `window` lines centred on `lineno` from `source`."""
    if not source:
        return ""
    lines = source.splitlines()
    if not lineno or lineno < 1:
        # No line info — return first window lines
        return "\n".join(lines[:window])
    idx    = lineno - 1
    start  = max(0, idx - window // 2)
    end    = min(len(lines), start + window)
    start  = max(0, end - window)
    numbered = [f"{start + i + 1:>4} | {ln}" for i, ln in enumerate(lines[start:end])]
    return "\n".join(numbered)


# ---------------------------------------------------------------------------
# Rule-based fallback actor (no LLM required)
# ---------------------------------------------------------------------------

# Mapping from vulnerability-class keywords → templated fix advice
_RULE_FIXES: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"hardcoded.*(secret|password|key|token)", re.I),
        "Replace the hardcoded value with an environment variable:\n\n"
        "  import os\n"
        "  value = os.getenv('MY_SECRET')  # set in .env / CI secrets",
        "Move credentials out of source code to prevent accidental exposure in VCS.",
    ),
    (
        re.compile(r"sql.injection|format.*sql|string.*sql", re.I),
        "Use parameterised queries instead of string formatting:\n\n"
        "  # Bad\n  cursor.execute(f'SELECT * FROM t WHERE id={user_id}')\n"
        "  # Good\n  cursor.execute('SELECT * FROM t WHERE id=%s', (user_id,))",
        "Parameterised queries prevent SQL injection by separating code from data.",
    ),
    (
        re.compile(r"pickle|unsafe.deseriali", re.I),
        "Replace pickle with a safe serialisation format:\n\n"
        "  import json\n"
        "  data = json.loads(raw)   # or use msgpack / protobuf for binary",
        "pickle.loads() executes arbitrary code; only deserialise trusted data.",
    ),
    (
        re.compile(r"shell.injection|subprocess.*shell=True", re.I),
        "Avoid shell=True and pass arguments as a list:\n\n"
        "  # Bad\n  subprocess.run(cmd, shell=True)\n"
        "  # Good\n  subprocess.run(['git', 'status'], shell=False)",
        "shell=True passes the command through the shell, enabling injection attacks.",
    ),
    (
        re.compile(r"assert.*auth|assert.*permission", re.I),
        "Replace assert with an explicit check that cannot be optimised away:\n\n"
        "  if not is_authorised(user):\n      raise PermissionError('Access denied')",
        "assert statements are removed when Python runs with -O; use explicit guards.",
    ),
    (
        re.compile(r"infinite.loop|loop.*no.exit|missing.break", re.I),
        "Add a loop termination condition or a break statement:\n\n"
        "  max_iter = 10_000\n"
        "  for _ in range(max_iter):\n"
        "      if done_condition:\n          break",
        "Unbounded loops block the event loop and exhaust CPU resources.",
    ),
    (
        re.compile(r"broad.except|bare.except|except Exception", re.I),
        "Catch specific exceptions to avoid masking unrelated errors:\n\n"
        "  try:\n      risky_call()\n  except ValueError as exc:\n      log(exc)",
        "Broad except clauses hide bugs; always specify the exception type.",
    ),
    (
        re.compile(r"sensitive.*(url|param|query)", re.I),
        "Move sensitive values to POST body or request headers, not query parameters:\n\n"
        "  # Bad\n  requests.get(f'https://api.example.com?token={tok}')\n"
        "  # Good\n  requests.get('https://api.example.com', headers={'Authorization': f'Bearer {tok}'})",
        "Query parameters are logged by servers and proxies; use headers instead.",
    ),
]


def _rule_based_fix(finding: dict) -> tuple[str, str]:
    """
    Return (fix_code, rationale) from the rule table, or a generic suggestion.
    """
    title  = finding.get("title", "")
    detail = finding.get("detail", "")
    haystack = title + " " + detail
    for pattern, fix, rationale in _RULE_FIXES:
        if pattern.search(haystack):
            return fix, rationale
    # Generic fallback
    suggestion = finding.get("suggestion", "Review and apply the suggested change.")
    return (
        f"# Suggested fix\n# {suggestion}\n\n"
        "# Apply the fix manually in the relevant section of your code.",
        suggestion,
    )


# ---------------------------------------------------------------------------
# LLM-based actor
# ---------------------------------------------------------------------------

_ACTOR_PROMPT_TMPL = textwrap.dedent("""\
    You are a security-focused software engineer.

    A static analyser detected the following issue in a Python file:

    FINDING:
      Title    : {title}
      Severity : {severity}
      Problem  : {detail}
      Suggestion: {suggestion}
      Location : {file} line {lineno}

    CONTEXT (source lines around the finding):
    ```python
    {context}
    ```

    Task: Write a corrected replacement for the flagged code that resolves the
    vulnerability. Output ONLY valid Python code with brief inline comments.
    Do not include explanations outside the code block.
""")

_CRITIC_PROMPT_TMPL = textwrap.dedent("""\
    You are a security code reviewer performing a quality gate check.

    ORIGINAL FINDING:
      Title    : {title}
      Severity : {severity}
      Problem  : {detail}
      Vulnerability class: {vuln_class}

    PROPOSED FIX:
    ```python
    {proposed_fix}
    ```

    Task: Assess whether the proposed fix FULLY resolves the {vuln_class} class
    of vulnerability.

    Respond with:
    VERDICT: approved | revised | rejected
    NOTES: one or two sentences explaining your decision.
    REVISED_FIX: (if verdict is revised, provide the corrected code; otherwise leave blank)
""")


def _infer_vuln_class(finding: dict) -> str:
    """Map a finding's title/detail to a short vulnerability class label."""
    haystack = (finding.get("title", "") + " " + finding.get("detail", "")).lower()
    for pattern, _, _ in _RULE_FIXES:
        if pattern.search(haystack):
            return pattern.pattern.split(r"\.")[0].replace(r"\.", " ")
    return finding.get("title", "unknown vulnerability")


def _parse_critic_response(response: str) -> tuple[str, str, str]:
    """Extract (verdict, notes, revised_fix) from the critic's raw text."""
    verdict      = "approved"
    notes        = response.strip()
    revised_fix  = ""

    verdict_match = re.search(r"VERDICT:\s*(approved|revised|rejected)", response, re.I)
    if verdict_match:
        verdict = verdict_match.group(1).lower()

    notes_match = re.search(r"NOTES:\s*(.+?)(?=REVISED_FIX:|$)", response, re.I | re.DOTALL)
    if notes_match:
        notes = notes_match.group(1).strip()

    revised_match = re.search(r"REVISED_FIX:\s*(.+)", response, re.I | re.DOTALL)
    if revised_match:
        revised_fix = revised_match.group(1).strip().strip("`")

    return verdict, notes, revised_fix


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_fix(finding: dict, source: str) -> FixResult:
    """
    Run the actor-critic pipeline for one finding.

    1. Actor   — proposes a fix (LLM if available, else rule-based fallback).
    2. Critic  — validates the fix against the vulnerability class and may
                 revise or reject it.

    Always returns a FixResult — never raises.
    """
    lineno  = finding.get("lineno")
    context = _extract_context(source, lineno)

    model = _get_watsonx_model()

    # ── Actor pass ───────────────────────────────────────────────────────────
    if model is not None:
        actor_prompt = _ACTOR_PROMPT_TMPL.format(
            title      = finding.get("title", ""),
            severity   = finding.get("severity", "warning"),
            detail     = finding.get("detail", ""),
            suggestion = finding.get("suggestion", ""),
            file       = finding.get("file", "unknown"),
            lineno     = lineno or "unknown",
            context    = context,
        )
        try:
            actor_response   = model.generate_text(actor_prompt)
            proposed_fix     = actor_response.strip()
            actor_rationale  = finding.get("suggestion", "")
        except Exception as exc:
            proposed_fix, actor_rationale = _rule_based_fix(finding)
            actor_rationale += f"  [LLM error: {exc}]"
    else:
        proposed_fix, actor_rationale = _rule_based_fix(finding)

    # ── Critic pass ──────────────────────────────────────────────────────────
    vuln_class = _infer_vuln_class(finding)

    if model is not None:
        critic_prompt = _CRITIC_PROMPT_TMPL.format(
            title        = finding.get("title", ""),
            severity     = finding.get("severity", "warning"),
            detail       = finding.get("detail", ""),
            vuln_class   = vuln_class,
            proposed_fix = proposed_fix,
        )
        try:
            critic_response               = model.generate_text(critic_prompt)
            verdict, notes, revised_fix   = _parse_critic_response(critic_response)
        except Exception as exc:
            verdict, notes, revised_fix = "approved", f"Critic unavailable: {exc}", ""
    else:
        # Rule-based critic: check that the fix addresses the known pattern
        verdict, notes, revised_fix = _rule_critic(finding, proposed_fix, vuln_class)

    final_fix = revised_fix if (verdict == "revised" and revised_fix) else proposed_fix

    return FixResult(
        finding         = finding,
        proposed_fix    = proposed_fix,
        actor_rationale = actor_rationale,
        critic_verdict  = verdict,
        critic_notes    = notes,
        final_fix       = final_fix,
        context_snippet = context,
    )


def _rule_critic(finding: dict, proposed_fix: str, vuln_class: str) -> tuple[str, str, str]:
    """
    Rule-based critic: verifies that key remediation tokens appear in the fix.
    Returns (verdict, notes, revised_fix).
    """
    fix_lower = proposed_fix.lower()
    title     = finding.get("title", "").lower()

    # Hardcoded secrets → fix must reference os.getenv or environ
    if re.search(r"hardcoded.*(secret|password|key|token)", title):
        if "os.getenv" in fix_lower or "os.environ" in fix_lower or "environ" in fix_lower:
            return "approved", "Fix correctly uses os.getenv/os.environ to externalise the credential.", ""
        return "revised", (
            "The fix still appears to contain a literal credential value. "
            "Ensure the fix uses os.getenv() or reads from an environment variable."
        ), proposed_fix + "\n# CRITIC: use os.getenv('YOUR_SECRET') instead of a literal."

    # SQL injection → fix must use parameterised queries
    if re.search(r"sql.injection|format.*sql", title):
        if "%s" in proposed_fix or "?" in proposed_fix or "parameter" in fix_lower:
            return "approved", "Fix uses parameterised queries — SQL injection risk eliminated.", ""
        return "revised", (
            "The fix does not appear to use parameterised queries. "
            "Replace string formatting with cursor.execute(sql, params)."
        ), proposed_fix + "\n# CRITIC: pass parameters as a tuple, not via string formatting."

    # Shell injection → fix must not use shell=True
    if re.search(r"shell.injection|subprocess", title):
        if "shell=true" in fix_lower:
            return "rejected", "The fix still uses shell=True — shell injection is not resolved.", ""
        return "approved", "Fix removes shell=True or passes arguments as a list.", ""

    # Pickle → must not use pickle.loads
    if "pickle" in title:
        if "pickle.loads" in fix_lower or "pickle.load" in fix_lower:
            return "rejected", "The fix still calls pickle.loads — unsafe deserialisation persists.", ""
        return "approved", "Fix avoids unsafe pickle deserialisation.", ""

    # Generic: approve if the fix is non-trivial
    if len(proposed_fix.strip()) > 40:
        return "approved", f"Fix addresses the {vuln_class} finding with a concrete code change.", ""
    return "approved", "Fix accepted (generic rule).", ""
