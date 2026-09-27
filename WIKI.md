# AI Code Auditor — Architecture Wiki
> IBM Bob 2.0 Hackathon · `ai-code-auditor` workspace  
> Initialised by `/init` · auto-generated from live codebase

---

## 1. Project Overview

A single-page **Streamlit** application that audits Python source code for
security vulnerabilities and logic flaws, then emits structured, actionable
refactoring suggestions.  It was built as a hackathon prototype demonstrating
an **orchestrator + subagent** pattern where each subagent is an independent
AST-analysis function rather than a remote LLM call.

---

## 2. Repository Layout

```
ai-code-auditor/
├── app.py              ← entire application (ingestion, subagents, UI, report)
├── README.md           ← IBM Hackathon template quickstart
├── SECURITY.MD         ← credential-handling guidelines
├── WIKI.md             ← this file
├── .gitignore          ← blocks secrets, venvs, IDE files
├── .bobignore          ← blocks Bob from logging credential patterns
├── bob_sessions/       ← exported Bob session artefacts (committed per rules)
│   └── iman_zainab_task01_logic_subagent_upgrade_summary.png
└── .venv/              ← local virtualenv (git-ignored)
```

No `requirements.txt`, `pyproject.toml`, `setup.cfg`, or `Dockerfile` exist
yet.  The dependency baseline is implicit in `.venv/`.

---

## 3. Runtime Dependencies

| Package | Version | Role |
|---|---|---|
| `streamlit` | 1.64.0 | UI framework / server |
| `python-dotenv` | 1.2.3 | `.env` loading |
| `pandas` | 3.0.6 | (bundled by Streamlit; unused by app logic) |
| `altair` | 6.3.0 | (bundled by Streamlit; unused by app logic) |
| `requests` | 2.34.2 | (available; unused by app logic) |
| `ast` | stdlib | AST parsing — **core engine** |
| `builtins` | stdlib | Reliable builtin-name lookup |

No external AI/LLM SDK, no database, no filesystem I/O beyond `.env` loading.

---

## 4. Pipeline Architecture

```
User pastes code
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│  Ingestion Engine  (app.py · UI section, line ~926)     │
│  st.text_area() → raw source string                     │
│  • Single code snippet only                             │
│  • No file upload, no repo clone, no multi-file scan    │
└────────────────────┬────────────────────────────────────┘
                     │  source: str
          ┌──────────┴──────────┐
          ▼                     ▼
┌─────────────────┐   ┌──────────────────────┐
│ Security        │   │ Logic & Bug          │
│ Subagent        │   │ Subagent             │
│ run_security_   │   │ run_logic_checks()   │
│ checks()        │   │ lines 76–587         │
│ lines 649–891   │   └──────────┬───────────┘
└────────┬────────┘              │
         │ security_findings[]   │ logic_findings[], parse_errors[]
         └──────────┬────────────┘
                    ▼
       ┌────────────────────────┐
       │  Report Generator      │
       │ _build_refactor_       │
       │  suggestions()         │
       │  lines 894–918         │
       └────────────┬───────────┘
                    ▼
       ┌────────────────────────┐
       │  Actionable Dashboard  │
       │  Streamlit 2-col UI    │
       │  lines 921–984         │
       │  • 🔴 errors (expanded)│
       │  • 🟡 warnings         │
       │  • st.code() report    │
       └────────────────────────┘
```

### Finding Schema (both subagents)

Every finding is a plain `dict` with four keys:

```python
{
    "severity":   "error" | "warning",   # triage tier
    "title":      str,                    # one-line label shown in expander header
    "detail":     str,                    # what is wrong and why it matters
    "suggestion": str,                    # concrete fix with code snippet
}
```

---

## 5. Security Subagent (`run_security_checks`)

**Location:** `app.py` lines 649–891  
**Input:** raw source string  
**Output:** `list[dict]`  
**Analysis engine:** `ast.parse()` + structural AST walk

| Check | Severity | Detection method |
|---|---|---|
| Unsafe deserialization (`yaml.load()` without SafeLoader) | error | Detects `yaml.load()` calls; inspects `Loader=` kwarg and 2nd positional arg against `{SafeLoader, CSafeLoader, BaseLoader}` |
| SQL Injection via string formatting in `execute()` | error | Flags f-string / `%`-format / `.format()` / `+`-concat as first arg to `execute`, `executemany`, `executescript` |
| Privilege escalation — `.get("role")` / `.get("is_admin")` | error | Matches `.get()` calls whose first arg is a string in `_PRIV_KEYS` |
| Privilege escalation — subscript `obj["role"]` | error | Matches `ast.Subscript` nodes whose slice is a string in `_PRIV_KEYS` |
| Privilege escalation — `setattr(obj, "role", ...)` | error | Matches `setattr()` calls whose second arg is a string in `_PRIV_KEYS` |
| Hardcoded secret (`api_key = "..."`) | error | Matches `ast.Assign` where target name is in `_SECRET_VARNAMES` and RHS is a non-empty string literal |
| Plain HTTP URL | warning | Matches `ast.Constant` strings starting with `http://` |

**Helper functions:** `_node_contains_format`, `_looks_like_sql`, `_call_name`  
**Key constants:** `_PRIV_KEYS`, `_SQL_KEYWORDS`, `_SECRET_VARNAMES`

---

## 6. Logic Subagent (`run_logic_checks`)

**Location:** `app.py` lines 76–587  
**Input:** raw source string  
**Output:** `(list[dict], list[str])` — findings + parse errors  
**Analysis engine:** `ast.parse()` + structural AST walk

### 6.1 Classic Checks

| Check | Severity | Detection method |
|---|---|---|
| Syntax / parse error | — (parse_errors list) | `SyntaxError` from `ast.parse()` |
| Unsafe built-ins `eval()` / `exec()` | error | Any `ast.Call` whose function name resolves to `eval` or `exec` |
| Infinite loop (`while True:` no break/return) | error | `ast.While` with literal-`True` test; `_has_break_or_return()` confirms absence of exit |
| Missing return on some paths | warning | `_function_always_returns()` heuristic; skips `__init__` and `-> None` annotations |
| Undefined module-level variable | warning | `_collect_assigned_names()` vs. `dir(builtins)`; walks only top-level statements to avoid false positives on function params |

### 6.2 Business Logic Flaw Checks (Pass A / B / C)

| Pass | Check | Severity | Detection method |
|---|---|---|---|
| A | Inverted conditional guard (e.g. `if not account.is_frozen: raise`) | error | Matches `ast.If` inside functions where a blocking/allowing boolean attr has wrong polarity relative to body language (`raise` / error-string `return`) |
| B | Unvalidated negative numeric input (e.g. `amount` in `balance -= amount` with no `<= 0` guard) | error | Intersects function param names with `_NUMERIC_PARAMS`; checks arithmetic usage then calls `_has_negative_guard()` |
| C | Off-by-one boundary error (`balance + 1 >= amount`) | error | Finds `ast.BinOp(Add\|Sub, domain_name, Constant(1))` inside `ast.Compare` nodes inside `If/While/Assert/Return` guards |

**Helper functions (module-level):** `_has_break_or_return`, `_collect_assigned_names`, `_function_always_returns`  
**Helper functions (local to `run_logic_checks`):** `_attr_name`, `_str_constants_in`, `_contains_blocking_language`, `_has_negative_guard`, `_is_obo_binop`, `_module_level_name_nodes`

---

## 7. Report Generator (`_build_refactor_suggestions`)

**Location:** `app.py` lines 894–918  
**Input:** `logic_findings: list`, `security_findings: list`  
**Output:** formatted multi-line string rendered via `st.code(..., language="python")`

Emits numbered `[Security #N]` and `[Logic #N]` comment blocks with
`Problem` and `Fix` sub-lines.  Clean runs emit a single `✅ No issues`
message with a documentation reminder.

---

## 8. Actionable Dashboard (UI)

**Location:** `app.py` lines 921–984  
**Framework:** Streamlit 1.64.0

| Element | Streamlit widget | Description |
|---|---|---|
| Code input | `st.text_area` (height=250) | Paste target code here |
| Trigger | `st.button("Run Security & Logic Audit")` | Runs both subagents synchronously |
| Security column | `st.expander` per finding | 🔴 errors expanded; 🟡 warnings collapsed |
| Logic column | `st.expander` per finding | same layout |
| Report panel | `st.code(..., language="python")` | Full refactor suggestion block |

---

## 9. Coding Conventions

| Convention | Detail |
|---|---|
| Finding shape | All findings are `dict` with `severity / title / detail / suggestion` — both subagents share this contract |
| Severity values | Exactly `"error"` or `"warning"` — UI filters on these strings |
| Helper naming | Private helpers prefixed `_`; module-level helpers live outside functions; check-specific helpers are defined as closures inside `run_logic_checks` |
| No mutation | Subagents return new lists; they do not mutate shared state |
| AST-first | All non-trivial analysis uses `ast.parse()` — no regex on source text except the plain-HTTP and secret-name checks which operate on AST string constants, not raw text |
| Error resilience | Both subagents catch `SyntaxError`; security checker returns `[]` on bad input; logic checker returns `([], [error_str])` |
| Constant sets | Domain vocabularies are `frozenset` constants (`_PRIV_KEYS`, `_BLOCK_POSITIVE`, `_NUMERIC_PARAMS`, etc.) for O(1) membership tests |
| UI / logic separation | All analysis code is above the `# UI` comment block; the UI section only calls the two public functions and renders their output |

---

## 10. ⚠️ Pipeline Limitations — Single-File-Paste vs. Repo-Level Analysis

This section documents the **current scope boundary** and what would be
needed to upgrade to true repository-level analysis.

### What the pipeline does today

| Capability | Status |
|---|---|
| Analyse arbitrary Python code | ✅ any valid (or invalid) snippet |
| Cross-function analysis within one paste | ✅ (AST walks the whole module) |
| Multi-file analysis | ❌ single paste only |
| File upload | ❌ no `st.file_uploader` |
| Repository clone / crawl | ❌ no git integration |
| Cross-module reference tracking | ❌ import graph not built |
| Type-aware analysis | ❌ no type inference; attribute types unknown |
| Inter-procedural data-flow | ❌ taint tracking not implemented |
| Non-Python files | ❌ Python AST only |
| Persistent results / history | ❌ results are ephemeral per session |
| Batch/CI mode (no UI) | ❌ Streamlit-only |

### What "repo-level" would require

1. **Ingestion Engine upgrade** — Replace `st.text_area` with one or more of:
   - `st.file_uploader(accept_multiple_files=True)` for local file sets
   - A text input + `git clone` subprocess for remote repos
   - A directory walker (`pathlib.Path.rglob("*.py")`) for mounted paths

2. **Multi-file orchestration** — The orchestrator would need to:
   - Parse each `.py` file independently into its own `ast.Module`
   - Build a cross-file symbol table (function definitions, class hierarchies,
     imported names) before running the per-file checks
   - Aggregate findings with `(file, line)` coordinates instead of `line` only

3. **Cross-module taint tracking** — The SQL-injection and privilege-escalation
   checks currently fire only when the dangerous pattern appears in the same
   expression.  Repo-level analysis requires tracking where a value originates
   (e.g. `request.json` in `views.py`) as it flows into a call in `db.py`.

4. **Import resolution** — `_collect_assigned_names` currently treats imports
   as "defined" without resolving them.  A repo-level pass would need to
   resolve `from utils import helper` to the actual symbol to detect, for
   example, an unsafe helper being called through an alias.

5. **Report persistence** — Results should be serialised (JSON/CSV) and
   optionally committed to `bob_sessions/` for review, matching the session
   artefact pattern already established in this repo.

6. **CI integration** — A `--headless` entry point (e.g. `python audit.py
   <path>`) that runs both subagents and exits non-zero on any `"error"`
   finding, suitable for a GitHub Actions step.

---

## 11. Security Posture of the Auditor Itself

| Control | Status |
|---|---|
| Secrets in env vars | ✅ `load_dotenv()` at startup |
| `.env` git-ignored | ✅ `.gitignore` |
| Bob session credential blocking | ✅ `.bobignore` |
| No `eval`/`exec` in app code | ✅ (the auditor would flag itself otherwise) |
| No outbound network calls | ✅ pure local AST analysis |
| No user input executed | ✅ input is parsed as text via `ast.parse()`, never `exec`'d |

---

*Generated by IBM Bob 2.0 · `ai-code-auditor` · `main` branch*
