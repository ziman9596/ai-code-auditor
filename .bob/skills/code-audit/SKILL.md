---
name: code-audit
description: >
  Use when the user wants to run a full security and logic audit on a repository,
  directory, or ZIP archive. Walks through: ingest → parallel subagent analysis →
  SARIF/OSCAL report generation → actor-critic fix engine → remediation PR.
  Trigger phrases: "audit this repo", "run the audit", "scan for vulnerabilities",
  "audit workflow", "run code-audit", "/code-audit".
metadata:
  argument-hint: "[path/to/repo | path/to/archive.zip]"
---

# Code Audit Skill

Full pipeline: **ingest → parallel analysis → SARIF/OSCAL reports → fixes → PR**.

The audit toolchain lives in the `ai-code-auditor` workspace. The modules are:

| Module | Role |
|---|---|
| `ingestion.py` | Walk a local directory or unzip an archive into a `FileMap` |
| `app.py` | `run_audit_on_file_map(file_map)` — orchestrates parallel security + logic subagents |
| `report_generator.py` | `to_sarif(all_results)` / `to_oscal(all_results)` — emit machine-readable reports |
| `fix_engine.py` | `generate_fix(finding, source)` — actor-critic fix pipeline per finding |
| `pr_helper.py` | `run_pr_workflow(fix_results, repo_path)` — branch → patch → commit → PR |

---

## Step 1 — Resolve the Target

1. If the user supplied a path argument, use it directly.
2. If no path was given, ask with `ask_followup_question`:
   - **What is the path to audit?** (local directory, ZIP file, or "paste" for inline code)
   - **Should a remediation PR be created?** (yes / no / ask later)
3. Validate the path exists using `execute_command`:
   ```powershell
   Test-Path "<path>"
   ```
   If it returns `False`, tell the user and stop.

---

## Step 2 — Ingest the Repository

Run ingestion via `execute_command` in the workspace's `.venv`:

```powershell
& ".\.venv\Scripts\python.exe" -c "
import ingestion, json, sys
target = r'<RESOLVED_PATH>'
if target.lower().endswith('.zip'):
    fm = ingestion.ingest_zip(open(target,'rb').read(), target)
else:
    fm = ingestion.ingest_directory(target)
summary = {
    'root': fm['root'],
    'file_count': len(fm['files']),
    'py_files': [p for p in fm['files'] if p.endswith('.py')],
    'skipped_count': len(fm['skipped']),
    'python_deps': fm['dependencies']['python'],
    'node_deps': fm['dependencies']['node'],
}
print(json.dumps(summary, indent=2))
"
```

Report back to the user:
- Root label, total files ingested, count of `.py` files, skipped count, detected dependencies.
- If `file_count == 0`, tell the user the directory has no auditable files and stop.

---

## Step 3 — Run the Parallel Audit (Security + Logic Subagents)

Run both subagents together via `run_audit_on_file_map`:

```powershell
& ".\.venv\Scripts\python.exe" -c "
import ingestion, json, sys
sys.path.insert(0, '.')
from app import run_audit_on_file_map

target = r'<RESOLVED_PATH>'
if target.lower().endswith('.zip'):
    fm = ingestion.ingest_zip(open(target,'rb').read(), target)
else:
    fm = ingestion.ingest_directory(target)

results = run_audit_on_file_map(fm)

# Flatten for summary output
security = [f for v in results.values() for f in v.get('security_findings', [])]
logic    = [f for v in results.values() for f in v.get('logic_findings', [])]
errors   = [e for v in results.values() for e in v.get('parse_errors', [])]

summary = {
    'security_count': len(security),
    'logic_count':    len(logic),
    'parse_errors':   errors,
    'top_security':   security[:10],
    'top_logic':      logic[:10],
}
print(json.dumps(summary, indent=2))
" 2>&1
```

After receiving the output:
- Display a summary table of **security findings** (severity, title, file, line).
- Display a summary table of **logic findings** (severity, title, file, line).
- List any parse errors as warnings.
- If both lists are empty, tell the user the audit is clean and skip Steps 4–7.

---

## Step 4 — Generate SARIF and OSCAL Reports

```powershell
& ".\.venv\Scripts\python.exe" -c "
import ingestion, json, sys, pathlib
sys.path.insert(0, '.')
from app import run_audit_on_file_map
import report_generator

target = r'<RESOLVED_PATH>'
if target.lower().endswith('.zip'):
    fm = ingestion.ingest_zip(open(target,'rb').read(), target)
else:
    fm = ingestion.ingest_directory(target)

results = run_audit_on_file_map(fm)

sarif = report_generator.to_sarif(results)
oscal = report_generator.to_oscal(results)

out = pathlib.Path('bob_sessions')
out.mkdir(exist_ok=True)
(out / 'audit.sarif').write_text(sarif, encoding='utf-8')
(out / 'audit.oscal.json').write_text(oscal, encoding='utf-8')
print('SARIF written to bob_sessions/audit.sarif')
print('OSCAL written to bob_sessions/audit.oscal.json')
" 2>&1
```

Tell the user the report paths. Mention:
- `bob_sessions/audit.sarif` — upload to GitHub Advanced Security / VS Code SARIF Viewer.
- `bob_sessions/audit.oscal.json` — NIST OSCAL 1.1.x assessment-results; import into GRC tooling.

---

## Step 5 — Actor-Critic Fix Engine (per finding)

For **each `"error"`-severity finding** (security and logic), run the actor-critic engine.
Batch all `error` findings in one script to avoid repeated startup cost:

```powershell
& ".\.venv\Scripts\python.exe" -c "
import ingestion, json, sys
sys.path.insert(0, '.')
from app import run_audit_on_file_map
import fix_engine

target = r'<RESOLVED_PATH>'
if target.lower().endswith('.zip'):
    fm = ingestion.ingest_zip(open(target,'rb').read(), target)
else:
    fm = ingestion.ingest_directory(target)

results = run_audit_on_file_map(fm)

errors = []
for rel, v in results.items():
    src = fm['files'].get(rel, {}).get('source', '') or ''
    for f in v.get('security_findings', []) + v.get('logic_findings', []):
        if f.get('severity') == 'error':
            errors.append((f, src))

fix_summaries = []
for finding, src in errors:
    fr = fix_engine.generate_fix(finding, src)
    fix_summaries.append({
        'file':           fr.finding.get('file'),
        'lineno':         fr.finding.get('lineno'),
        'title':          fr.finding.get('title'),
        'critic_verdict': fr.critic_verdict,
        'critic_notes':   fr.critic_notes,
        'final_fix':      fr.final_fix[:400],  # truncated for readability
    })
print(json.dumps(fix_summaries, indent=2))
" 2>&1
```

Present each fix as an inline block:
- File + line, finding title, critic verdict (`approved` / `revised` / `rejected`), critic notes, and a truncated preview of the final fix.
- If `IBM_CLOUD_API_KEY` and `WATSONX_PROJECT_ID` are set, the engine uses IBM Granite; otherwise it falls back to the rule-based engine. Both paths are valid — tell the user which was used.

---

## Step 6 — Create Remediation PR (if requested)

Only proceed if the user confirmed they want a PR (Step 1) **and** the target is a git repository.

Check git status first:
```powershell
git -C "<RESOLVED_PATH>" rev-parse --show-toplevel 2>&1
```
If this fails, tell the user the path is not a git repository and skip this step.

Then run the full PR workflow:

```powershell
& ".\.venv\Scripts\python.exe" -c "
import ingestion, json, sys
sys.path.insert(0, '.')
from app import run_audit_on_file_map
import fix_engine, pr_helper

target      = r'<RESOLVED_PATH>'
base_branch = 'main'   # adjust if different

if target.lower().endswith('.zip'):
    fm = ingestion.ingest_zip(open(target,'rb').read(), target)
else:
    fm = ingestion.ingest_directory(target)

results = run_audit_on_file_map(fm)

fix_results = []
for rel, v in results.items():
    src = fm['files'].get(rel, {}).get('source', '') or ''
    for f in v.get('security_findings', []) + v.get('logic_findings', []):
        if f.get('severity') == 'error':
            fix_results.append(fix_engine.generate_fix(f, src))

pr = pr_helper.run_pr_workflow(fix_results, target, base_branch)
print(json.dumps({
    'success':       pr.success,
    'branch':        pr.branch,
    'pr_url':        pr.pr_url,
    'commit_sha':    pr.commit_sha,
    'files_patched': pr.files_patched,
    'error':         pr.error,
}, indent=2))
" 2>&1
```

Report back:
- On success: branch name, PR URL (or manual-open link if `gh` CLI is absent), files patched, commit SHA.
- On failure: surface the `error` field and suggest the manual steps (`git checkout`, `git add`, `git commit`, `git push`, open PR on GitHub).

---

## Step 7 — Final Summary

After all steps complete, present a clean summary:

```
✅ Audit complete for <root>
   • Files scanned : <N>
   • Security findings : <N error> / <N warning>
   • Logic findings    : <N error> / <N warning>
   • Fixes generated   : <N> (actor-critic)
   • Reports           : bob_sessions/audit.sarif · bob_sessions/audit.oscal.json
   • PR                : <url or "not created">
```

---

## Environment Variables (optional — for IBM Granite LLM fixes)

| Variable | Purpose |
|---|---|
| `IBM_CLOUD_API_KEY` | IBM Cloud API key for watsonx.ai |
| `WATSONX_PROJECT_ID` | watsonx.ai project UUID |

Without these, the fix engine falls back to rule-based templates — the full audit, reporting, and PR workflow still work.

---

## Error Handling Notes

- **Import errors** (`ModuleNotFoundError`): the `.venv` must be activated or the absolute interpreter path used. Always call `.\.venv\Scripts\python.exe` explicitly.
- **`git push` failures**: the repo must have a remote named `origin`. Suggest `git remote add origin <url>` if missing.
- **`gh` CLI absent**: `pr_helper` detects this and returns a manual PR URL. Relay it to the user.
- **`file_count == 0`**: either the path has no text files or everything was vendor-skipped. Tell the user and suggest checking the path.
- **ZIP with no `.py` files**: audit will run but produce zero findings. Inform the user.
