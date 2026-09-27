"""
pr_helper.py — Pull Request Helper
====================================

Creates a GitHub pull request containing one or more actor-critic fixes.

Workflow
--------
1. create_fix_branch(base_branch)
       Creates a new git branch named  audit-fix/<timestamp>  off the given
       base (defaults to the repo's current HEAD branch).

2. apply_and_stage_fix(fix_result, file_map)
       Writes the fix into the original file (patch-apply strategy) and
       stages it with ``git add``.

3. commit_fix(fix_results)
       Generates a structured commit message summarising all staged fixes
       and runs ``git commit``.

4. push_and_open_pr(branch, base_branch, fix_results)
       Pushes the branch, then opens a PR via the GitHub CLI (``gh``).
       Falls back to printing the PR URL if ``gh`` is unavailable.

Public API
----------
run_pr_workflow(fix_results, file_map, repo_path, base_branch="main") -> PRResult
    Runs the full workflow and returns a PRResult dataclass.
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fix_engine import FixResult


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class PRResult:
    success: bool
    branch: str
    pr_url: str
    commit_sha: str
    commit_message: str
    error: str = ""
    files_patched: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _run_git(args: list[str], cwd: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a git sub-command and return the CompletedProcess."""
    return subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=check,
    )


def _current_branch(cwd: str) -> str:
    result = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd)
    return result.stdout.strip()


def _current_sha(cwd: str) -> str:
    result = _run_git(["rev-parse", "HEAD"], cwd, check=False)
    return result.stdout.strip()


def _repo_root(cwd: str) -> str:
    """Return the absolute path of the git repository root."""
    result = _run_git(["rev-parse", "--show-toplevel"], cwd)
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Branch creation
# ---------------------------------------------------------------------------

def create_fix_branch(base_branch: str, cwd: str) -> str:
    """
    Create a new branch named ``audit-fix/<YYYYMMDD-HHMMSS>`` off ``base_branch``
    and check it out.  Returns the new branch name.
    """
    ts     = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch = f"audit-fix/{ts}"
    _run_git(["checkout", base_branch], cwd)
    _run_git(["checkout", "-b", branch], cwd)
    return branch


# ---------------------------------------------------------------------------
# Patch application
# ---------------------------------------------------------------------------

_PATCH_COMMENT_RE = re.compile(
    r"^#\s*(Suggested fix|CRITIC:|Actor:|Fix:).*$", re.MULTILINE
)


def _strip_meta_comments(fix_text: str) -> str:
    """Remove engine-internal comment markers from the fix text."""
    return _PATCH_COMMENT_RE.sub("", fix_text).strip()


def _write_fix_to_file(fix_result: FixResult, repo_root: str) -> Optional[str]:
    """
    Apply the fix from *fix_result* to the original file and return the
    relative path of the patched file, or None if it could not be applied.

    Strategy:
    - If the fix looks like a full file replacement (> 50 % of the original
      line count), overwrite the file.
    - Otherwise, replace the context window around the flagged line with the
      fix content.
    - If the file does not exist in the repo (e.g. pasted code), write the
      fix as a new file ``<file>.fixed.py``.
    """
    finding  = fix_result.finding
    rel_path = finding.get("file", "")
    if not rel_path:
        return None

    abs_path = Path(repo_root) / rel_path
    fix_text = _strip_meta_comments(fix_result.final_fix)

    if not fix_text:
        return None

    # ── Case 1: file exists in repo ─────────────────────────────────────────
    if abs_path.exists():
        original = abs_path.read_text(encoding="utf-8", errors="replace")
        orig_lines = original.splitlines(keepends=True)
        fix_lines  = fix_text.splitlines(keepends=True)

        lineno = finding.get("lineno")

        if lineno and lineno >= 1 and len(fix_lines) < len(orig_lines) * 0.8:
            # Targeted replacement: replace ±5-line window around the finding
            window = 5
            start  = max(0, lineno - 1 - window)
            end    = min(len(orig_lines), lineno + window)
            patched_lines = orig_lines[:start] + fix_lines + orig_lines[end:]
            abs_path.write_text("".join(patched_lines), encoding="utf-8")
        else:
            # Full replacement
            abs_path.write_text(fix_text, encoding="utf-8")

        return rel_path

    # ── Case 2: pasted code / non-existent path — write as .fixed.py ────────
    fixed_path = abs_path.with_suffix(".fixed.py")
    fixed_path.parent.mkdir(parents=True, exist_ok=True)
    fixed_path.write_text(fix_text, encoding="utf-8")
    return str(fixed_path.relative_to(repo_root))


def apply_and_stage_fix(fix_result: FixResult, repo_root: str) -> Optional[str]:
    """
    Write the fix to disk and stage it with ``git add``.
    Returns the rel_path that was staged, or None on failure.
    """
    rel_path = _write_fix_to_file(fix_result, repo_root)
    if rel_path is None:
        return None
    try:
        _run_git(["add", rel_path], repo_root)
    except subprocess.CalledProcessError:
        # If file is outside git index (pasted code scenario), add by full path
        abs_path = str(Path(repo_root) / rel_path)
        _run_git(["add", abs_path], repo_root)
    return rel_path


# ---------------------------------------------------------------------------
# Commit message composer
# ---------------------------------------------------------------------------

def build_commit_message(fix_results: list[FixResult]) -> str:
    """
    Build a conventional-commit-style message summarising all fixes.

    Format:
        fix(security): resolve N audit finding(s) via actor-critic review

        - [<severity>] <title> (<file>:<lineno>) — <critic_verdict>
          Critic: <critic_notes>
        ...

        Generated by AI Code Auditor actor-critic engine.
    """
    n   = len(fix_results)
    kinds = {r.finding.get("kind", "quality") for r in fix_results}
    scope = "security" if "security" in kinds else "quality"

    lines = [
        f"fix({scope}): resolve {n} audit finding(s) via actor-critic review",
        "",
    ]

    for r in fix_results:
        f       = r.finding
        verdict = r.critic_verdict
        loc     = f"{f.get('file', '?')}:{f.get('lineno', '?')}"
        lines.append(
            f"- [{f.get('severity', 'warning')}] {f.get('title', 'Finding')} "
            f"({loc}) — critic: {verdict}"
        )
        if r.critic_notes:
            # Wrap long critic notes
            wrapped = textwrap.fill(r.critic_notes, width=72, initial_indent="  ")
            lines.append(wrapped)

    lines += [
        "",
        "Generated by AI Code Auditor actor-critic engine.",
    ]
    return "\n".join(lines)


def commit_fix(fix_results: list[FixResult], cwd: str) -> str:
    """Stage all fixes and commit.  Returns the commit SHA."""
    message = build_commit_message(fix_results)
    _run_git(["commit", "-m", message], cwd)
    return _current_sha(cwd)


# ---------------------------------------------------------------------------
# Push and open PR
# ---------------------------------------------------------------------------

def _gh_available() -> bool:
    try:
        result = subprocess.run(
            ["gh", "--version"],
            capture_output=True, text=True, check=False
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def _build_pr_body(fix_results: list[FixResult]) -> str:
    """Build a human-readable PR description."""
    lines = [
        "## 🛡️ AI Code Auditor — Automated Fixes",
        "",
        "This pull request was generated by the **AI Code Auditor** actor-critic engine.",
        "Each fix was first proposed by the *actor* and then validated by the *critic*",
        "before being committed.",
        "",
        "### Fixes Included",
        "",
    ]
    for i, r in enumerate(fix_results, 1):
        f = r.finding
        lines.append(
            f"#### {i}. {f.get('title', 'Finding')}  "
            f"`{f.get('file', '?')}:{f.get('lineno', '?')}`"
        )
        lines.append(f"- **Severity:** {f.get('severity', 'warning')}")
        lines.append(f"- **Problem:** {f.get('detail', '')}")
        lines.append(f"- **Critic verdict:** `{r.critic_verdict}`")
        lines.append(f"- **Critic notes:** {r.critic_notes}")
        lines.append("")
        lines.append("<details><summary>View final fix</summary>")
        lines.append("")
        lines.append("```python")
        lines.append(r.final_fix)
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines += [
        "---",
        "_Please review each fix carefully before merging._",
    ]
    return "\n".join(lines)


def push_and_open_pr(
    branch: str,
    base_branch: str,
    fix_results: list[FixResult],
    cwd: str,
) -> tuple[bool, str]:
    """
    Push *branch* to origin, then open a PR via ``gh pr create``.
    Returns (success, pr_url_or_error_message).
    """
    # Push
    try:
        _run_git(["push", "-u", "origin", branch], cwd)
    except subprocess.CalledProcessError as exc:
        return False, f"git push failed: {exc.stderr.strip()}"

    # Open PR
    if not _gh_available():
        remote = _run_git(["remote", "get-url", "origin"], cwd, check=False).stdout.strip()
        url = (
            remote.replace("git@github.com:", "https://github.com/")
                  .replace(".git", "")
        )
        return True, (
            f"Branch pushed. Open a PR manually at:\n"
            f"{url}/compare/{base_branch}...{branch}"
        )

    pr_title = (
        f"fix: resolve {len(fix_results)} finding(s) via actor-critic audit"
    )
    pr_body  = _build_pr_body(fix_results)

    try:
        result = subprocess.run(
            [
                "gh", "pr", "create",
                "--base",  base_branch,
                "--head",  branch,
                "--title", pr_title,
                "--body",  pr_body,
            ],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
        )
        pr_url = result.stdout.strip()
        return True, pr_url
    except subprocess.CalledProcessError as exc:
        return False, f"gh pr create failed: {exc.stderr.strip()}"


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_pr_workflow(
    fix_results: list[FixResult],
    repo_path: str,
    base_branch: str = "main",
) -> PRResult:
    """
    Full workflow: branch → patch → stage → commit → push → PR.

    Parameters
    ----------
    fix_results:
        List of FixResult objects from the actor-critic engine.
    repo_path:
        Absolute path to the git repository root (or any sub-path; we'll
        resolve the real root via ``git rev-parse --show-toplevel``).
    base_branch:
        The branch to target with the PR (default: "main").

    Returns
    -------
    PRResult
    """
    try:
        root = _repo_root(repo_path)
    except subprocess.CalledProcessError:
        return PRResult(
            success=False, branch="", pr_url="", commit_sha="",
            commit_message="",
            error=(
                f"'{repo_path}' is not inside a git repository. "
                "Initialise git first: git init && git add . && git commit -m 'initial'"
            ),
        )

    # 1. Create branch
    try:
        branch = create_fix_branch(base_branch, root)
    except subprocess.CalledProcessError as exc:
        return PRResult(
            success=False, branch="", pr_url="", commit_sha="",
            commit_message="",
            error=f"Branch creation failed: {exc.stderr.strip()}",
        )

    # 2. Apply and stage fixes
    patched: list[str] = []
    for fr in fix_results:
        rel = apply_and_stage_fix(fr, root)
        if rel:
            patched.append(rel)

    if not patched:
        # Nothing to commit — clean up
        _run_git(["checkout", base_branch], root, check=False)
        _run_git(["branch", "-D", branch], root, check=False)
        return PRResult(
            success=False, branch=branch, pr_url="", commit_sha="",
            commit_message="",
            error="No files could be patched. Check that file paths are correct.",
        )

    # 3. Commit
    try:
        sha = commit_fix(fix_results, root)
    except subprocess.CalledProcessError as exc:
        return PRResult(
            success=False, branch=branch, pr_url="", commit_sha="",
            commit_message="",
            error=f"Commit failed: {exc.stderr.strip()}",
            files_patched=patched,
        )

    commit_msg = build_commit_message(fix_results)

    # 4. Push + open PR
    success, pr_url = push_and_open_pr(branch, base_branch, fix_results, root)

    return PRResult(
        success=success,
        branch=branch,
        pr_url=pr_url,
        commit_sha=sha,
        commit_message=commit_msg,
        files_patched=patched,
        error="" if success else pr_url,
    )
