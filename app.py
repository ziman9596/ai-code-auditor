import ast
import builtins
import concurrent.futures
import os
import pathlib
import re

import streamlit as st
from dotenv import load_dotenv

import fix_engine
import ingestion
import pr_helper
import report_generator


load_dotenv()

st.set_page_config(page_title="AI Code Auditor - IBM Bob 2.0", layout="wide")

st.title("🛡️ AI Code Auditor & Refactor Assistant")
st.caption("IBM Bob 2.0 Hackathon Submission")


# ---------------------------------------------------------------------------
# Logic subagent helpers
# ---------------------------------------------------------------------------

def _has_break_or_return(node):
    """Return True if a loop body contains a Break or Return at any depth."""
    for child in ast.walk(node):
        if isinstance(child, (ast.Break, ast.Return)):
            return True
    return False


def _collect_assigned_names(stmts):
    """Return the set of names assigned (or imported) in a list of statements."""
    assigned = set()
    for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned.add(target.id)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            target = node.target
            if isinstance(target, ast.Name):
                assigned.add(target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                assigned.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            assigned.add(node.name)
        elif isinstance(node, ast.For):
            if isinstance(node.target, ast.Name):
                assigned.add(node.target.id)
        elif isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name):
                assigned.add(node.target.id)
    return assigned


def _function_always_returns(func_node):
    """
    Heuristic: return False if the function body contains at least one
    execution path that reaches the end without a Return node.
    Only inspects the top-level statements of the function body.
    """
    def _stmts_always_return(stmts):
        for stmt in stmts:
            if isinstance(stmt, ast.Return):
                return True
            if isinstance(stmt, ast.If):
                if (stmt.orelse and
                        _stmts_always_return(stmt.body) and
                        _stmts_always_return(stmt.orelse)):
                    return True
            if isinstance(stmt, (ast.For, ast.While)):
                if stmt.orelse and _stmts_always_return(stmt.orelse):
                    return True
        return False

    return _stmts_always_return(func_node.body)


def run_logic_checks(source: str):
    """
    Parse *source* with the AST and return a list of finding dicts:
      { "severity": "error"|"warning", "title": str, "detail": str, "suggestion": str }
    Also returns the list of parse errors (strings) if the source is invalid.
    """
    findings = []
    parse_errors = []

    # --- syntax / parse check ---
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        parse_errors.append(f"SyntaxError on line {exc.lineno}: {exc.msg}")
        return findings, parse_errors

    # --- unsafe built-ins (eval / exec) ---
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name in ("eval", "exec"):
                findings.append({
                    "severity": "error",
                    "title": f"Unsafe built-in `{name}()` on line {node.lineno}",
                    "detail": (
                        f"`{name}()` executes arbitrary code and is a critical security "
                        "and logic risk. It makes code hard to audit, debug, and maintain."
                    ),
                    "suggestion": (
                        f"Replace `{name}()` with an explicit, typed operation. "
                        "If you need to evaluate a math expression, use a safe parser "
                        "such as `ast.literal_eval()` for literals, or the `simpleeval` "
                        "library for arithmetic. If you need dynamic dispatch, use a "
                        "dictionary of callables instead."
                    ),
                })

    # --- infinite loop detection ---
    for node in ast.walk(tree):
        if isinstance(node, ast.While):
            # while True: ... with no break or return inside
            test = node.test
            is_literal_true = (
                (isinstance(test, ast.Constant) and test.value is True) or
                (isinstance(test, ast.NameConstant) and test.value is True)  # py<3.8
            )
            if is_literal_true and not _has_break_or_return(node):
                findings.append({
                    "severity": "error",
                    "title": f"Potential infinite loop on line {node.lineno}",
                    "detail": (
                        "`while True:` loop has no `break` or `return` statement, "
                        "so it will run forever and hang the program."
                    ),
                    "suggestion": (
                        "Add a `break` or `return` inside the loop body when the "
                        "exit condition is met, or rewrite the loop with an explicit "
                        "condition: e.g. `while queue:` or `while attempts < max_retries:`."
                    ),
                })

    # --- missing return statement in non-trivial functions ---
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Skip __init__, property setters, and functions annotated -> None
            if node.name == "__init__":
                continue
            returns_annotation = getattr(node, "returns", None)
            if (isinstance(returns_annotation, ast.Constant) and
                    returns_annotation.value is None):
                continue
            if (isinstance(returns_annotation, ast.Name) and
                    returns_annotation.id == "None"):
                continue
            # Check whether any Return node exists at all
            has_any_return = any(
                isinstance(n, ast.Return) and n.value is not None
                for n in ast.walk(node)
            )
            if has_any_return and not _function_always_returns(node):
                findings.append({
                    "severity": "warning",
                    "title": f"Missing return in some paths of `{node.name}()` (line {node.lineno})",
                    "detail": (
                        f"Function `{node.name}` returns a value on some code paths "
                        "but falls off the end (returns `None` implicitly) on others. "
                        "This usually indicates a missing `else` branch or a `return` "
                        "at the bottom of the function."
                    ),
                    "suggestion": (
                        f"Ensure every branch in `{node.name}` ends with an explicit "
                        "`return` statement. Add a type annotation (e.g. `-> int`) to "
                        "let a type-checker catch missing returns automatically, and "
                        "consider adding a final `raise ValueError(...)` or "
                        "`return default_value` as a safety net."
                    ),
                })

    # --- undefined variable usage (module-level heuristic) ---
    module_assigned = _collect_assigned_names(tree.body)
    # Use the `builtins` module directly — reliable regardless of how the
    # script is imported (__builtins__ is a dict in modules, a module at top).
    builtin_names = set(dir(builtins))
    builtin_names.update({"__name__", "__file__", "__doc__", "__package__",
                           "__spec__", "__loader__", "__builtins__"})

    # Collect only the Name nodes that live at module scope — skip the bodies
    # of functions and classes to avoid false positives on parameters / locals.
    def _module_level_name_nodes(stmts):
        """Yield ast.Name (Load) nodes from top-level statements only."""
        for stmt in stmts:
            # Do not descend into function or class definitions
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for child in ast.walk(stmt):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    yield child

    seen_undef = set()  # avoid duplicate reports for the same name
    for name_node in _module_level_name_nodes(tree.body):
        name = name_node.id
        if name in module_assigned or name in builtin_names:
            continue
        # Ignore dunder names and single-underscore placeholders
        if name.startswith("_"):
            continue
        if name in seen_undef:
            continue
        seen_undef.add(name)
        findings.append({
            "severity": "warning",
            "title": f"Possibly undefined name `{name}` on line {name_node.lineno}",
            "detail": (
                f"`{name}` is used but no assignment, import, or definition for it "
                "was found at module scope. This will raise a `NameError` at runtime."
            ),
            "suggestion": (
                f"Make sure `{name}` is imported or assigned before it is used. "
                "If it is defined inside a conditional block or in a separate module, "
                "verify the import path and add a guard (e.g. `if {name} is not None:`) "
                "to avoid the `NameError`."
            ),
        })

    # -------------------------------------------------------------------------
    # --- business logic flaw detection ---------------------------------------
    # -------------------------------------------------------------------------

    # Attribute name fragments that represent a "blocking" state on an entity.
    # A guard that is TRUE for these should BLOCK the operation (raise/return error).
    _BLOCK_POSITIVE = frozenset({
        "frozen", "locked", "suspended", "banned", "blocked",
        "deactivated", "disabled", "deleted", "archived",
    })
    # Attribute name fragments that represent an "allowing" state.
    # A guard that is FALSE for these should BLOCK the operation.
    _ALLOW_POSITIVE = frozenset({
        "active", "enabled", "verified", "approved", "confirmed",
        "is_active", "is_enabled", "is_verified", "is_approved",
    })
    # Numeric parameter names that carry domain quantity semantics.
    _NUMERIC_PARAMS = frozenset({
        "amount", "quantity", "qty", "count", "batch_size", "batch",
        "limit", "size", "total", "value", "price", "fee", "transfer",
        "units", "num", "number", "n",
    })
    # Domain-quantity attribute/variable name fragments for off-by-one detection.
    _BOUNDARY_NAMES = frozenset({
        "balance", "amount", "quantity", "limit", "count", "total",
        "budget", "credit", "quota", "size", "capacity", "threshold",
        "price", "fee", "units",
    })

    # ── helpers local to business-logic checks ────────────────────────────────

    def _attr_name(node) -> str:
        """Extract the last component of an attribute or plain Name node."""
        if isinstance(node, ast.Attribute):
            return node.attr.lower()
        if isinstance(node, ast.Name):
            return node.id.lower()
        return ""

    def _str_constants_in(node) -> list:
        """Return all string constant values reachable under *node*."""
        return [
            n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        ]

    def _contains_blocking_language(stmts) -> bool:
        """True if any statement raises an exception or returns an error string."""
        for stmt in stmts:
            if isinstance(stmt, ast.Raise):
                return True
            if isinstance(stmt, ast.Return) and stmt.value is not None:
                for s in _str_constants_in(stmt.value):
                    sl = s.lower()
                    if any(w in sl for w in ("error", "denied", "forbidden",
                                             "locked", "frozen", "suspend",
                                             "not allowed", "invalid", "fail")):
                        return True
        return False

    def _has_negative_guard(func_node, param_name: str) -> bool:
        """
        Return True if *func_node* contains an explicit guard that rejects
        negative or zero values for *param_name*, e.g.:
            if amount <= 0: raise ...
            if amount < 0:  raise ...
            assert amount > 0
        """
        for n in ast.walk(func_node):
            # if <param> <= 0 / < 0 / == 0 : raise/return-error
            if isinstance(n, ast.If):
                test = n.test
                # Simple comparison: amount <= 0
                if isinstance(test, ast.Compare) and len(test.ops) == 1:
                    left_name = _attr_name(test.left)
                    op = test.ops[0]
                    comparator = test.comparators[0]
                    is_zero_or_neg = (
                        isinstance(comparator, ast.Constant) and
                        isinstance(comparator.value, (int, float)) and
                        comparator.value <= 0
                    )
                    is_param = left_name == param_name.lower()
                    is_block_op = isinstance(op, (ast.LtE, ast.Lt, ast.Eq))
                    if is_param and is_zero_or_neg and is_block_op:
                        if _contains_blocking_language(n.body):
                            return True
                # UnaryOp negation check: if not amount
                if (isinstance(test, ast.UnaryOp) and
                        isinstance(test.op, ast.Not) and
                        _attr_name(test.operand) == param_name.lower()):
                    if _contains_blocking_language(n.body):
                        return True
            # assert amount > 0  /  assert amount >= 1
            if isinstance(n, ast.Assert):
                test = n.test
                if isinstance(test, ast.Compare) and len(test.ops) == 1:
                    left_name = _attr_name(test.left)
                    op = test.ops[0]
                    comparator = test.comparators[0]
                    is_positive_assert = (
                        isinstance(comparator, ast.Constant) and
                        isinstance(comparator.value, (int, float)) and
                        comparator.value >= 0 and
                        isinstance(op, (ast.Gt, ast.GtE))
                    )
                    if left_name == param_name.lower() and is_positive_assert:
                        return True
        return False

    # ── Pass A: Inverted conditional checks ──────────────────────────────────
    #
    # Pattern: inside a function body, an `if` whose test is a bare attribute
    # access (or `not attr`) that semantically should BLOCK execution —
    # but the polarity is wrong.
    #
    # E.g.   if not account.is_frozen: raise AccountFrozenError()   ← inverted
    #        if account.is_active:     raise AccountLockedError()    ← inverted
    #
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for stmt in ast.walk(func):
            if not isinstance(stmt, ast.If):
                continue

            test = stmt.test
            is_negated = isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
            inner = test.operand if is_negated else test

            # We want a bare Name or Attribute (boolean-looking guard)
            if not isinstance(inner, (ast.Name, ast.Attribute)):
                continue

            attr = _attr_name(inner)

            # Determine expected polarity:
            #   BLOCK_POSITIVE attr (e.g. is_frozen) → guard should be `if attr` (not negated)
            #   ALLOW_POSITIVE attr (e.g. is_active) → guard should be `if not attr`
            is_block_attr = any(frag in attr for frag in _BLOCK_POSITIVE)
            is_allow_attr = any(frag in attr for frag in _ALLOW_POSITIVE)

            if not (is_block_attr or is_allow_attr):
                continue

            body_blocks = _contains_blocking_language(stmt.body)
            if not body_blocks:
                continue

            # Inverted if:
            #   block-positive attr + negated   → "if not is_frozen: raise" ← wrong
            #   allow-positive attr + not neg   → "if is_active: raise"     ← wrong
            inverted = (is_block_attr and is_negated) or (is_allow_attr and not is_negated)
            if not inverted:
                continue

            expected_guard = (
                f"`if {attr}:`"
                if is_block_attr
                else f"`if not {attr}:`"
            )
            wrong_guard = (
                f"`if not {attr}:`"
                if is_block_attr
                else f"`if {attr}:`"
            )

            findings.append({
                "severity": "error",
                "title": (
                    f"Inverted conditional guard `{wrong_guard}` "
                    f"in `{func.name}()` on line {stmt.lineno}"
                ),
                "detail": (
                    f"The condition {wrong_guard} has the wrong polarity for the "
                    f"attribute `{attr}`. "
                    + (
                        f"A '{attr}' flag is TRUE when the entity is blocked, so the "
                        f"guard should raise/return when `{attr}` IS true — not when it "
                        f"is false. As written, the blocking code runs for healthy entities "
                        f"and is silently skipped for blocked ones."
                        if is_block_attr else
                        f"A '{attr}' flag is TRUE when the entity is allowed through, so "
                        f"the guard should raise/return when `{attr}` is FALSE — not when "
                        f"it is true. As written, valid entities are blocked and "
                        f"invalid ones pass through."
                    )
                ),
                "suggestion": (
                    f"Flip the condition to {expected_guard}:\n"
                    f"    {expected_guard[1:-1]}:  # block operation when appropriate\n"
                    f"        raise <AppropriateError>(...)\n"
                    "Review every guard in this function that tests a boolean state "
                    "flag and verify its polarity matches the intended business rule."
                ),
            })

    # ── Pass B: Unvalidated negative numeric input ────────────────────────────
    #
    # Pattern: a function has a parameter whose name is in _NUMERIC_PARAMS and
    # it appears in an arithmetic augmented-assignment (+=, -=, *=) or BinOp
    # inside the function body, but there is no guard rejecting negative / zero
    # values anywhere in that function.
    #
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        param_names = {
            arg.arg.lower()
            for arg in func.args.args + func.args.posonlyargs + func.args.kwonlyargs
        }
        if func.args.vararg:
            param_names.add(func.args.vararg.arg.lower())
        if func.args.kwarg:
            param_names.add(func.args.kwarg.arg.lower())

        numeric_params = param_names & _NUMERIC_PARAMS

        for param in sorted(numeric_params):
            # Check whether the param is actually used arithmetically
            used_in_arithmetic = False
            for n in ast.walk(func):
                # augmented assignment: balance -= amount
                if isinstance(n, ast.AugAssign):
                    if _attr_name(n.value) == param:
                        used_in_arithmetic = True
                        break
                # binary op: balance - amount  /  total * amount
                if isinstance(n, ast.BinOp):
                    if isinstance(n.op, (ast.Sub, ast.Add, ast.Mult, ast.Div)):
                        if _attr_name(n.left) == param or _attr_name(n.right) == param:
                            used_in_arithmetic = True
                            break
                # regular assignment rhs containing the param
                if isinstance(n, ast.Assign):
                    for child in ast.walk(n.value):
                        if isinstance(child, ast.Name) and child.id.lower() == param:
                            used_in_arithmetic = True
                            break
                if used_in_arithmetic:
                    break

            if not used_in_arithmetic:
                continue

            if _has_negative_guard(func, param):
                continue

            findings.append({
                "severity": "error",
                "title": (
                    f"Unvalidated numeric parameter `{param}` in "
                    f"`{func.name}()` (line {func.lineno}) — negative values not rejected"
                ),
                "detail": (
                    f"`{func.name}()` uses `{param}` in arithmetic but never checks "
                    f"that `{param}` is positive before proceeding. A caller can pass "
                    f"`{param}=-500` (or any negative value) to silently reverse the "
                    "direction of the operation — e.g. turning a debit into a credit, "
                    "or a withdrawal into a deposit — bypassing business rules entirely."
                ),
                "suggestion": (
                    f"Add an explicit non-negative guard at the top of `{func.name}`:\n"
                    f"    if {param} <= 0:\n"
                    f"        raise ValueError(f\"`{param}` must be positive, got {{{param}}}\")\n"
                    "For batch transfers also enforce per-item validation so that a "
                    "single negative entry cannot offset legitimate transfers in the "
                    "same batch."
                ),
            })

    # ── Pass C: Off-by-one boundary errors ───────────────────────────────────
    #
    # Pattern: a comparison or assert uses `<domain_quantity> + 1` or
    # `<domain_quantity> - 1` as one of its operands, e.g.:
    #   if balance + 1 >= amount:   ← should be `balance >= amount`
    #   assert count - 1 > 0        ← should be `count > 0` or `count >= 1`
    #
    # We look for BinOp(Add|Sub, left=domain_name, right=Constant(1)) inside
    # Compare nodes that are themselves inside If / While / Assert / Return.
    #
    def _is_obo_binop(node) -> tuple:
        """
        If *node* is `<domain_name> +/- 1`, return (attr_name, op_symbol, lineno).
        Otherwise return (None, None, None).
        """
        if not isinstance(node, ast.BinOp):
            return None, None, None
        if not isinstance(node.op, (ast.Add, ast.Sub)):
            return None, None, None
        # right operand must be the literal 1
        if not (isinstance(node.right, ast.Constant) and node.right.value == 1):
            return None, None, None
        left_name = _attr_name(node.left)
        if not any(frag in left_name for frag in _BOUNDARY_NAMES):
            return None, None, None
        op_sym = "+" if isinstance(node.op, ast.Add) else "-"
        return left_name, op_sym, node.col_offset

    # Gather all Compare nodes inside guard-like contexts (If, While, Assert)
    seen_obo = set()
    for node in ast.walk(tree):
        is_guard = isinstance(node, (ast.If, ast.While, ast.Assert, ast.Return))
        if not is_guard:
            continue

        # Pull the comparison expression(s) out of the guard
        if isinstance(node, ast.Assert):
            comparisons = [node.test]
        elif isinstance(node, ast.Return):
            comparisons = [node.value] if node.value else []
        else:
            comparisons = [node.test]

        for cmp_root in comparisons:
            for cmp_node in ast.walk(cmp_root):
                if not isinstance(cmp_node, ast.Compare):
                    continue
                # Check left operand and each comparator for the OBO pattern
                candidates = [cmp_node.left] + list(cmp_node.comparators)
                for cand in candidates:
                    attr, op_sym, _ = _is_obo_binop(cand)
                    if attr is None:
                        continue
                    key = (attr, op_sym, node.lineno)
                    if key in seen_obo:
                        continue
                    seen_obo.add(key)

                    direction = "inflated" if op_sym == "+" else "deflated"
                    correct = (
                        f"`{attr}`"
                        if op_sym == "+"
                        else f"`{attr}` or `{attr} >= 1`"
                    )
                    findings.append({
                        "severity": "error",
                        "title": (
                            f"Off-by-one boundary error: `{attr} {op_sym} 1` "
                            f"used in guard on line {node.lineno}"
                        ),
                        "detail": (
                            f"The expression `{attr} {op_sym} 1` is used directly in a "
                            f"boundary comparison. This artificially {direction} the "
                            f"effective value of `{attr}` by 1, causing the guard to "
                            f"allow (or reject) one more (or fewer) unit than intended. "
                            "Common consequences include: allowing an overdraft by 1 unit, "
                            "processing one extra item beyond a quota, or incorrectly "
                            "rejecting a legitimately exact boundary value."
                        ),
                        "suggestion": (
                            f"Replace `{attr} {op_sym} 1` with the plain {correct} in the "
                            "comparison, unless the +1 or -1 is explicitly and intentionally "
                            "part of the business rule (e.g. a grace unit). If intentional, "
                            "extract it into a named constant to make the intent clear:\n"
                            f"    GRACE_UNIT = 1\n"
                            f"    if {attr} + GRACE_UNIT >= threshold:  # deliberate grace\n"
                            "and add a comment explaining the business rationale."
                        ),
                    })

    return findings, parse_errors


# ---------------------------------------------------------------------------
# Security subagent
# ---------------------------------------------------------------------------

# Keyword sets used by the privilege-escalation detector
_PRIV_KEYS = frozenset({
    "role", "is_admin", "admin", "is_superuser", "superuser",
    "permission", "permissions", "privilege", "privileges",
    "is_staff", "staff", "access_level", "clearance",
})

# SQL keyword fragments that suggest a raw query string
_SQL_KEYWORDS = frozenset({"select", "insert", "update", "delete", "drop", "alter", "exec"})

# Assignment value patterns that look like hard-coded secrets
_SECRET_VARNAMES = frozenset({
    "api_key", "apikey", "password", "passwd", "pwd", "secret",
    "token", "auth_token", "access_token", "private_key",
})


def _node_contains_format(node: ast.expr) -> bool:
    """Return True if *node* is an f-string, .format() call, or %-format."""
    # f-string
    if isinstance(node, ast.JoinedStr):
        return True
    # "..." % (...)  or  "..." % var
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            return True
    # "...".format(...)
    if (isinstance(node, ast.Call) and
            isinstance(node.func, ast.Attribute) and
            node.func.attr == "format"):
        return True
    # "..." + var  (simple concatenation)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    return False


def _looks_like_sql(value: str) -> bool:
    """Heuristic: does this string constant look like an SQL statement?"""
    low = value.lower()
    return any(kw in low for kw in _SQL_KEYWORDS)


def _call_name(call_node: ast.Call):
    """Return (module_alias, attr) for a Call node, or (None, name) for bare calls."""
    func = call_node.func
    if isinstance(func, ast.Attribute):
        obj = func.value
        module = obj.id if isinstance(obj, ast.Name) else None
        return module, func.attr
    if isinstance(func, ast.Name):
        return None, func.id
    return None, None


# ── Module-level helpers for check #8 (ASVS 8.3.1) ──────────────────────────

# Sensitive query-parameter names whose presence in a URL is a data-leak risk
_SENSITIVE_PARAMS = frozenset({
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_token", "auth", "authorization", "private_key", "credential",
    "ssn", "credit_card", "card_number", "cvv", "pin",
})

# Regex: matches ?name= or &name= separators inside URL templates
_SENSITIVE_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]*)=")


def _url_fstring_has_sensitive_param(node: ast.JoinedStr) -> str | None:
    """
    Inspect the constant fragments of an f-string.  Return the first
    sensitive query-parameter name found in a ``?name=`` / ``&name=``
    pattern, or ``None`` if none detected.
    """
    for part in node.values:
        if not isinstance(part, ast.Constant):
            continue
        text: str = part.value if isinstance(part.value, str) else ""
        for m in _SENSITIVE_PARAM_RE.finditer(text):
            if m.group(1).lower() in _SENSITIVE_PARAMS:
                return m.group(1)
    return None


def _format_string_has_sensitive_param(s: str) -> str | None:
    """Return the first sensitive query-parameter name found in *s*, or None."""
    for m in _SENSITIVE_PARAM_RE.finditer(s):
        if m.group(1).lower() in _SENSITIVE_PARAMS:
            return m.group(1)
    return None


def run_security_checks(source: str) -> list:
    """
    AST-based security scan.  Returns a list of finding dicts:
      { "severity": "error"|"warning", "title": str, "detail": str, "suggestion": str }
    Falls back to an empty list on unparseable input (syntax errors are
    reported by run_logic_checks instead).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    findings = []

    for node in ast.walk(tree):

        # ── 1. Unsafe deserialization: yaml.load() without SafeLoader ────────
        if isinstance(node, ast.Call):
            mod, attr = _call_name(node)
            if attr == "load" and mod in ("yaml", "YAML"):
                # Check whether any keyword or positional arg is a SafeLoader
                loader_arg = None
                # positional: yaml.load(data, SafeLoader)
                if len(node.args) >= 2:
                    loader_arg = node.args[1]
                # keyword: yaml.load(data, Loader=SafeLoader)
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        loader_arg = kw.value

                safe_loaders = {"SafeLoader", "CSafeLoader", "BaseLoader"}
                is_safe = False
                if loader_arg is not None:
                    # Could be a Name (SafeLoader) or Attribute (yaml.SafeLoader)
                    lname = None
                    if isinstance(loader_arg, ast.Name):
                        lname = loader_arg.id
                    elif isinstance(loader_arg, ast.Attribute):
                        lname = loader_arg.attr
                    if lname in safe_loaders:
                        is_safe = True

                if not is_safe:
                    findings.append({
                        "severity": "error",
                        "title": f"[CRITICAL] Unsafe Deserialization — `yaml.load()` without SafeLoader on line {node.lineno}",
                        "detail": (
                            "`yaml.load()` with an untrusted or missing Loader can deserialize "
                            "arbitrary Python objects from the YAML stream, allowing remote code "
                            "execution (RCE). This is listed in OWASP Top-10 (A08 – Software & "
                            "Data Integrity Failures)."
                        ),
                        "suggestion": (
                            "Replace with `yaml.safe_load(data)` for plain data, or pass an "
                            "explicit safe loader:\n"
                            "    yaml.load(data, Loader=yaml.SafeLoader)\n"
                            "Never use `yaml.FullLoader` or `yaml.UnsafeLoader` with "
                            "untrusted input."
                        ),
                    })

        # ── 2. SQL Injection via string formatting in query arguments ─────────
        if isinstance(node, ast.Call):
            mod, attr = _call_name(node)
            if attr in ("execute", "executemany", "executescript"):
                # First positional argument is the query string
                query_arg = node.args[0] if node.args else None
                if query_arg is not None and _node_contains_format(query_arg):
                    # Also check for SQL keywords to reduce false positives
                    # on non-database execute() calls
                    raw_sql = ""
                    if isinstance(query_arg, ast.Constant):
                        raw_sql = query_arg.value if isinstance(query_arg.value, str) else ""
                    # For f-strings, inspect the constant parts
                    if isinstance(query_arg, ast.JoinedStr):
                        raw_sql = " ".join(
                            p.value for p in query_arg.values
                            if isinstance(p, ast.Constant) and isinstance(p.value, str)
                        )
                    if not raw_sql or _looks_like_sql(raw_sql) or not isinstance(query_arg, ast.Constant):
                        findings.append({
                            "severity": "error",
                            "title": f"[CRITICAL] SQL Injection risk — dynamic query string in `{attr}()` on line {node.lineno}",
                            "detail": (
                                f"The query passed to `{attr}()` is built using string formatting "
                                "or concatenation. An attacker who controls any part of the "
                                "interpolated value can rewrite the SQL statement, bypassing "
                                "authentication, exfiltrating data, or destroying the database "
                                "(OWASP A03 – Injection)."
                            ),
                            "suggestion": (
                                "Use parameterised queries with the DB-API placeholder:\n"
                                '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
                                "or with named placeholders:\n"
                                '    cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})\n'
                                "Never interpolate user-supplied values directly into SQL strings."
                            ),
                        })

        # ── 3. Privilege Escalation — client-supplied override parameters ─────
        #
        # Patterns targeted:
        #   a) data.get("role") / request.json.get("is_admin")  (dict .get with priv key)
        #   b) request.args["role"] / body["is_admin"]          (subscript with priv key)
        #   c) setattr(user, "role", ...)                       (setattr with priv key)

        if isinstance(node, ast.Call):
            mod, attr = _call_name(node)

            # Pattern (a): <something>.get("role")
            if attr == "get" and node.args:
                key_arg = node.args[0]
                if (isinstance(key_arg, ast.Constant) and
                        isinstance(key_arg.value, str) and
                        key_arg.value.lower() in _PRIV_KEYS):
                    findings.append({
                        "severity": "error",
                        "title": (
                            f"[CRITICAL] Privilege Escalation — client-controlled "
                            f"`{key_arg.value}` read via `.get()` on line {node.lineno}"
                        ),
                        "detail": (
                            f"The privilege-sensitive key `{key_arg.value!r}` is being "
                            "read directly from a user-supplied dict (e.g. request body, "
                            "query-string, JSON payload). An attacker can include this "
                            "key in their request to elevate their own permissions "
                            "(OWASP A01 – Broken Access Control)."
                        ),
                        "suggestion": (
                            f"Never trust client input for `{key_arg.value}`. "
                            "Determine roles and permissions server-side, from your "
                            "authenticated session or database:\n"
                            "    user_role = db.get_role(session['user_id'])  # ✅\n"
                            "Strip or ignore privilege keys before processing any "
                            "user-supplied payload."
                        ),
                    })

            # Pattern (c): setattr(obj, "role", value)
            if attr == "setattr" and len(node.args) >= 2:
                key_arg = node.args[1]
                if (isinstance(key_arg, ast.Constant) and
                        isinstance(key_arg.value, str) and
                        key_arg.value.lower() in _PRIV_KEYS):
                    findings.append({
                        "severity": "error",
                        "title": (
                            f"[CRITICAL] Privilege Escalation — `setattr` writes "
                            f"client-supplied `{key_arg.value}` on line {node.lineno}"
                        ),
                        "detail": (
                            f"`setattr(obj, '{key_arg.value}', ...)` overwrites a "
                            "privilege-sensitive attribute. If the attribute name or "
                            "value originates from the request, an attacker can "
                            "silently promote themselves to a higher privilege level."
                        ),
                        "suggestion": (
                            "Use an explicit allow-list of fields that callers are "
                            "permitted to update, and never include privilege fields "
                            "in that list:\n"
                            "    ALLOWED_FIELDS = {'name', 'email'}  # no 'role'\n"
                            "    for field in ALLOWED_FIELDS & request_data.keys():\n"
                            "        setattr(user, field, request_data[field])"
                        ),
                    })

        # Pattern (b): obj["role"]  or  obj['is_admin']  — Subscript with priv key
        if isinstance(node, ast.Subscript):
            slice_node = node.slice
            # Python 3.9+: slice is the node directly; 3.8-: wrapped in ast.Index
            if isinstance(slice_node, ast.Index):          # py < 3.9
                slice_node = slice_node.value              # type: ignore[attr-defined]
            if (isinstance(slice_node, ast.Constant) and
                    isinstance(slice_node.value, str) and
                    slice_node.value.lower() in _PRIV_KEYS):
                findings.append({
                    "severity": "error",
                    "title": (
                        f"[CRITICAL] Privilege Escalation — subscript access to "
                        f"`{slice_node.value}` on line {node.lineno}"
                    ),
                    "detail": (
                        f"Direct subscript access `obj['{slice_node.value}']` on a "
                        "user-supplied mapping reads a privilege-sensitive key without "
                        "validation. Attackers can inject this key into the payload to "
                        "escalate privileges (OWASP A01 – Broken Access Control)."
                    ),
                    "suggestion": (
                        f"Read `{slice_node.value}` only from your server-side session "
                        "or database — never from an incoming request payload. "
                        "If you must accept it from input, validate it against an "
                        "explicit allow-list and re-verify server-side before use."
                    ),
                })

    # ── 4. Hardcoded secrets (AST: string literal assigned to a secret var) ──
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            rhs = node.value
            if not (isinstance(rhs, ast.Constant) and isinstance(rhs.value, str)):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if target.id.lower() in _SECRET_VARNAMES and rhs.value.strip():
                    findings.append({
                        "severity": "error",
                        "title": f"[CRITICAL] Hardcoded secret in variable `{target.id}` on line {node.lineno}",
                        "detail": (
                            f"`{target.id}` is assigned a hard-coded string literal. "
                            "Committing secrets to source control exposes them to "
                            "anyone with repository access and is flagged by tools "
                            "like GitHub Secret Scanning and truffleHog."
                        ),
                        "suggestion": (
                            f"Move `{target.id}` to an environment variable or a secrets "
                            "manager and load it at runtime:\n"
                            f"    import os\n"
                            f"    {target.id} = os.environ['{target.id.upper()}']\n"
                            "Add the value to `.env` (git-ignored) for local dev."
                        ),
                    })

    # ── 5. Plain HTTP URLs in string literals ─────────────────────────────────
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.startswith("http://"):
                findings.append({
                    "severity": "warning",
                    "title": f"Insecure HTTP URL on line {node.lineno}",
                    "detail": (
                        f"The URL `{node.value[:60]}{'...' if len(node.value) > 60 else ''}` "
                        "uses plain HTTP. Traffic is transmitted unencrypted, making it "
                        "vulnerable to man-in-the-middle attacks and credential theft."
                    ),
                    "suggestion": (
                        "Change the scheme to `https://`. If the remote server does not "
                        "support HTTPS, raise this as a dependency risk and request the "
                        "operator to enable TLS."
                    ),
                })

    # ── 6. [ASVS 5.5.2] Insecure deserialization ─────────────────────────────
    #
    # Dangerous deserialization APIs that can execute arbitrary code when fed
    # untrusted input:
    #   • pickle.loads / pickle.load / pickle.Unpickler
    #   • _pickle.loads  (C accelerator, same risk)
    #   • marshal.loads / marshal.load
    #   • shelve.open  (wraps pickle internally)
    #   • jsonpickle.decode
    #   • dill.loads / dill.load
    #
    # yaml.load() without SafeLoader is already covered by check #1 above.
    _UNSAFE_DESER: dict[str, set[str]] = {
        "pickle":     {"loads", "load", "Unpickler"},
        "_pickle":    {"loads", "load", "Unpickler"},
        "marshal":    {"loads", "load"},
        "shelve":     {"open"},
        "jsonpickle": {"decode"},
        "dill":       {"loads", "load"},
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        mod, attr = _call_name(node)
        if mod in _UNSAFE_DESER and attr in _UNSAFE_DESER[mod]:
            findings.append({
                "severity": "error",
                "title": (
                    f"[CRITICAL] Insecure Deserialization — `{mod}.{attr}()` "
                    f"on line {node.lineno} (ASVS 5.5.2)"
                ),
                "detail": (
                    f"`{mod}.{attr}()` can deserialize arbitrary Python objects "
                    "from a byte stream. When the input is attacker-controlled, "
                    "this allows Remote Code Execution (RCE) by embedding "
                    "malicious `__reduce__` hooks inside the payload. "
                    "This maps to OWASP A08 – Software & Data Integrity Failures."
                ),
                "suggestion": (
                    "Avoid deserializing untrusted data with pickle/marshal/shelve/dill.\n"
                    "Prefer safe, schema-validated formats instead:\n"
                    "    import json; data = json.loads(raw)          # ✅ safe\n"
                    "    import msgpack; data = msgpack.unpackb(raw)  # ✅ safe\n"
                    "If you must use pickle for trusted internal data, sign and verify "
                    "the payload with an HMAC before deserializing:\n"
                    "    import hmac, hashlib\n"
                    "    if not hmac.compare_digest(sig, expected_sig): raise ValueError\n"
                    "    data = pickle.loads(payload)"
                ),
            })

    # ── 7. [ASVS 5.3.4] Raw SQL strings built with concatenation / formatting ─
    #
    # Check #2 above only catches formatting *inside* a cursor.execute() call.
    # This check catches the common pattern of building the SQL string in a
    # separate assignment and then passing the variable to execute():
    #
    #   query = "SELECT * FROM users WHERE id = " + user_id   ← caught here
    #   cursor.execute(query)                                  ← would miss #2
    #
    # Strategy: walk all assignments where the RHS looks like SQL AND uses
    # string formatting / concatenation.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        rhs = node.value
        if not _node_contains_format(rhs):
            continue
        # Collect every string constant fragment inside the RHS expression
        raw_parts: list[str] = []
        for child in ast.walk(rhs):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                raw_parts.append(child.value)
        combined = " ".join(raw_parts)
        if not _looks_like_sql(combined):
            continue
        # Determine the variable name(s) being assigned for the report title
        target_names = []
        for t in node.targets:
            if isinstance(t, ast.Name):
                target_names.append(t.id)
        var_label = ", ".join(f"`{n}`" for n in target_names) if target_names else "a variable"
        findings.append({
            "severity": "error",
            "title": (
                f"[CRITICAL] SQL Injection risk — raw SQL string built with "
                f"formatting assigned to {var_label} on line {node.lineno} "
                f"(ASVS 5.3.4)"
            ),
            "detail": (
                f"The SQL string assigned to {var_label} is constructed using "
                "string formatting or concatenation before being passed to a "
                "database cursor. If any interpolated fragment originates from "
                "user input, the attacker can manipulate the query structure, "
                "leading to data exfiltration, authentication bypass, or "
                "destructive operations (OWASP A03 – Injection)."
            ),
            "suggestion": (
                "Build the query as a static template string and pass values as "
                "a separate parameter tuple — never interpolate them:\n"
                '    query = "SELECT * FROM users WHERE id = %s"  # ✅ static\n'
                '    cursor.execute(query, (user_id,))             # ✅ safe\n'
                "For ORMs (SQLAlchemy, Django ORM) use their query-builder APIs "
                "instead of raw `.execute()` with formatted strings."
            ),
        })

    # ── 8. [ASVS 8.3.1] Sensitive data appended to URLs ──────────────────────
    #
    # Detects patterns where sensitive parameter names (tokens, passwords, API
    # keys, etc.) are embedded into a URL string via:
    #   a) f-string:  f"https://host/path?token={tok}"
    #   b) % format: "https://host/path?password=%s" % pwd
    #   c) str.format: "https://host?api_key={}".format(key)
    #   d) concatenation: url + "?secret=" + value
    #
    # URLs get written to server logs, browser history, HTTP Referer headers,
    # and CDN/proxy access logs — all places an attacker or insider can read.

    for node in ast.walk(tree):
        sensitive_param: str | None = None
        node_line: int = getattr(node, "lineno", 0)
        snippet: str = ""

        # (a) f-string containing ?sensitive_param={...}
        if isinstance(node, ast.JoinedStr):
            sensitive_param = _url_fstring_has_sensitive_param(node)
            if sensitive_param:
                # Reconstruct a readable snippet from constant fragments
                snippet = "".join(
                    p.value for p in node.values
                    if isinstance(p, ast.Constant) and isinstance(p.value, str)
                )

        # (b) "...?name=%s" % value  or  (c)  "...?name={}".format(value)
        elif isinstance(node, ast.Call):
            _, attr = _call_name(node)
            if attr == "format" and isinstance(node.func, ast.Attribute):
                tmpl = node.func.value
                if isinstance(tmpl, ast.Constant) and isinstance(tmpl.value, str):
                    sensitive_param = _format_string_has_sensitive_param(tmpl.value)
                    snippet = tmpl.value
        elif (isinstance(node, ast.BinOp) and
              isinstance(node.op, ast.Mod) and
              isinstance(node.left, ast.Constant) and
              isinstance(node.left.value, str)):
            sensitive_param = _format_string_has_sensitive_param(node.left.value)
            snippet = node.left.value

        if sensitive_param:
            findings.append({
                "severity": "error",
                "title": (
                    f"[CRITICAL] Sensitive data in URL — `{sensitive_param}` "
                    f"appended as query parameter on line {node_line} "
                    f"(ASVS 8.3.1)"
                ),
                "detail": (
                    f"The sensitive parameter `{sensitive_param}` is being "
                    "embedded directly into a URL query string. URLs are routinely "
                    "captured in server access logs, browser history, HTTP Referer "
                    "headers, and CDN/proxy logs — any of which can be read by an "
                    "attacker or an insider. This violates OWASP A02 – Cryptographic "
                    "Failures and ASVS 8.3.1."
                    + (f"\n\nURL template fragment: `{snippet[:80]}{'…' if len(snippet) > 80 else ''}`"
                       if snippet else "")
                ),
                "suggestion": (
                    f"Move `{sensitive_param}` out of the URL and send it in the "
                    "HTTP request body (POST) or in a request header:\n"
                    "    # ✅ In Authorization header\n"
                    '    headers = {"Authorization": f"Bearer {token}"}\n'
                    "    requests.get(url, headers=headers)\n\n"
                    "    # ✅ In POST body\n"
                    '    requests.post(url, json={"token": token})\n\n'
                    "If a GET request is unavoidable, use a short-lived, "
                    "single-use token that is immediately invalidated after use."
                ),
            })

    return findings


def _build_refactor_suggestions(logic_findings: list, security_findings: list) -> str:
    """Compose a human-readable refactoring summary from all findings."""
    lines = []
    if not logic_findings and not security_findings:
        lines.append("# ✅ No issues detected — code looks clean!")
        lines.append("# Consider adding type annotations and docstrings for maintainability.")
        return "\n".join(lines)

    lines.append("# ── Refactoring Suggestions ──────────────────────────────────")
    lines.append("#")

    for i, f in enumerate(security_findings, 1):
        lines.append(f"# [Security #{i}] {f['title']}")
        lines.append(f"#   Problem  : {f['detail']}")
        lines.append(f"#   Fix      : {f['suggestion']}")
        lines.append("#")

    for i, f in enumerate(logic_findings, 1):
        lines.append(f"# [Logic #{i}] {f['title']}")
        lines.append(f"#   Problem  : {f['detail']}")
        lines.append(f"#   Fix      : {f['suggestion']}")
        lines.append("#")

    lines.append("# Run `bandit -r .` and `pylint`/`mypy` for deeper static analysis after applying fixes.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Subagent workers — run independently and in parallel
# ---------------------------------------------------------------------------

_LINENO_RE = re.compile(r"\bline[s]?\s+(\d+)\b", re.IGNORECASE)


def _extract_lineno(title: str) -> int | None:
    """
    Pull the first line number out of a finding title produced by the
    security / logic check functions (e.g. "… on line 42").
    Returns an int, or None when the title contains no line reference.
    """
    m = _LINENO_RE.search(title)
    return int(m.group(1)) if m else None


def _tag_findings(findings: list, rel_path: str) -> None:
    """
    Mutate *findings* in-place: stamp every entry with the originating
    ``file`` path and a ``lineno`` integer (extracted from the title,
    or ``None`` when absent).
    """
    for f in findings:
        f["file"] = rel_path
        if "lineno" not in f:
            f["lineno"] = _extract_lineno(f.get("title", ""))


def _security_subagent(rel: str, source: str) -> tuple[str, list]:
    """
    Security subagent: runs ``run_security_checks`` for a single file and
    returns ``(rel_path, tagged_findings)``.

    Designed to be dispatched by the orchestrator via a thread pool so that
    all files are scanned **in parallel** with the logic subagent.
    """
    findings = run_security_checks(source)
    _tag_findings(findings, rel)
    return rel, findings


def _logic_subagent(rel: str, source: str) -> tuple[str, list, list]:
    """
    Logic subagent: runs ``run_logic_checks`` for a single file and
    returns ``(rel_path, tagged_findings, parse_errors)``.

    Designed to be dispatched by the orchestrator via a thread pool so that
    all files are scanned **in parallel** with the security subagent.
    """
    findings, parse_errors = run_logic_checks(source)
    _tag_findings(findings, rel)
    return rel, findings, parse_errors


# ---------------------------------------------------------------------------
# Orchestrator — dispatches both subagents across all files in parallel
# ---------------------------------------------------------------------------

def run_audit_on_file_map(file_map: dict) -> dict:
    """
    Orchestrate security and logic checks across every Python file in
    *file_map*.  Both subagents run **in parallel** — all security checks
    are dispatched concurrently with all logic checks — then their findings
    are aggregated into one results dict keyed by relative file path.

    Each value:
      {
        "security_findings": list[dict],  # each entry has "file" + "lineno"
        "logic_findings":    list[dict],  # each entry has "file" + "lineno"
        "parse_errors":      list[str],
      }
    """
    py_files: dict = {
        rel: entry["source"]
        for rel, entry in file_map["files"].items()
        if pathlib.Path(rel).suffix.lower() == ".py" and entry["source"] is not None
    }

    # Pre-populate result slots so ordering is deterministic.
    results: dict = {
        rel: {"security_findings": [], "logic_findings": [], "parse_errors": []}
        for rel in py_files
    }

    # Fan out: submit every (file × check-type) pair to the thread pool.
    # Two independent subagents run across all files simultaneously.
    with concurrent.futures.ThreadPoolExecutor() as pool:
        sec_futures = {
            pool.submit(_security_subagent, rel, src): rel
            for rel, src in py_files.items()
        }
        logic_futures = {
            pool.submit(_logic_subagent, rel, src): rel
            for rel, src in py_files.items()
        }

        # Collect security subagent results
        for future in concurrent.futures.as_completed(sec_futures):
            rel, sec_findings = future.result()
            results[rel]["security_findings"] = sec_findings

        # Collect logic subagent results
        for future in concurrent.futures.as_completed(logic_futures):
            rel, logic_findings, parse_errors = future.result()
            results[rel]["logic_findings"] = logic_findings
            results[rel]["parse_errors"] = parse_errors

    return results


def _flatten(results: dict, key: str) -> list:
    """Merge findings lists from all files into one flat list."""
    out = []
    for file_results in results.values():
        out.extend(file_results[key])
    return out


def _render_finding_expander(f: dict, icon: str, expanded: bool, source: str = "") -> None:
    label = f"[`{f.get('file', '')}`] {f['title']}" if f.get("file") else f['title']
    # Unique key prefix based on finding identity (file + title + lineno)
    fkey = f"{f.get('file', 'x')}_{f.get('title', 'x')}_{f.get('lineno', 0)}"
    fkey = re.sub(r"[^A-Za-z0-9_]", "_", fkey)

    with st.expander(f"{icon} {label}", expanded=expanded):
        if f.get("file"):
            st.caption(f"📄 {f['file']}")
        st.markdown(f"**Problem:** {f['detail']}")
        st.markdown(f"**Suggestion:** {f['suggestion']}")

        # ── Generate Fix button ──────────────────────────────────────────────
        fix_state_key    = f"fix_result_{fkey}"
        fix_loading_key  = f"fix_loading_{fkey}"

        if st.button("🔧 Generate Fix", key=f"btn_fix_{fkey}"):
            st.session_state[fix_loading_key] = True

        if st.session_state.get(fix_loading_key):
            with st.spinner("Actor generating fix…"):
                result = fix_engine.generate_fix(f, source)
            st.session_state[fix_state_key]   = result
            st.session_state[fix_loading_key] = False

        result = st.session_state.get(fix_state_key)
        if result is not None:
            _render_fix_result(result, fkey)


def _render_fix_result(result: "fix_engine.FixResult", fkey: str) -> None:
    """Render the actor-critic fix result inline inside a finding expander."""
    verdict_icon = {"approved": "✅", "revised": "🔄", "rejected": "❌"}.get(
        result.critic_verdict, "❓"
    )
    st.markdown("---")
    st.markdown("#### 🎭 Actor-Critic Fix")

    col_actor, col_critic = st.columns([3, 2])

    with col_actor:
        st.markdown("**🎬 Actor — Proposed Fix**")
        st.code(result.proposed_fix, language="python")
        if result.actor_rationale:
            st.caption(f"Rationale: {result.actor_rationale}")

    with col_critic:
        st.markdown(f"**🧐 Critic — {verdict_icon} {result.critic_verdict.capitalize()}**")
        st.info(result.critic_notes)
        if result.critic_verdict == "revised":
            st.markdown("**Revised fix:**")
            st.code(result.final_fix, language="python")

    if result.critic_verdict != "rejected":
        st.markdown("**✅ Final Fix (ready to commit)**")
        st.code(result.final_fix, language="python")

        # Mark this finding's fix as "approved" for Create PR collection
        approved_key = "approved_fixes"
        approved: list = st.session_state.get(approved_key, [])
        # Avoid duplicates
        existing_fkeys = {
            re.sub(r"[^A-Za-z0-9_]", "_",
                   f"{r.finding.get('file','x')}_{r.finding.get('title','x')}_{r.finding.get('lineno',0)}")
            for r in approved
        }
        if fkey not in existing_fkeys:
            approved.append(result)
            st.session_state[approved_key] = approved

        st.caption(f"✔ Fix queued for PR creation ({len(st.session_state.get('approved_fixes', []))} fix(es) ready).")
    else:
        st.warning("Critic rejected this fix. Review the finding manually.")


def _render_dependency_panel(deps: dict) -> None:
    py_deps = deps.get("python", [])
    node_deps = deps.get("node", [])
    if not py_deps and not node_deps:
        return
    with st.expander("📦 Detected Dependencies", expanded=False):
        if py_deps:
            st.markdown("**Python (`requirements.txt`)**")
            st.code("\n".join(py_deps), language="text")
        if node_deps:
            st.markdown("**Node.js (`package.json`)**")
            st.code("\n".join(node_deps), language="text")


def _render_download_buttons(all_results: dict) -> None:
    """
    Render a collapsible 'Export Reports' section with download buttons for
    SARIF 2.1.0 and OSCAL assessment-results JSON.
    """
    st.markdown("---")
    with st.expander("📥 Export Machine-Readable Reports", expanded=False):
        st.markdown(
            "Download the audit findings as a **SARIF 2.1.0** file (GitHub Advanced "
            "Security, VS Code SARIF Viewer, Azure DevOps) or an "
            "**OSCAL Assessment Results** document (GRC / compliance tooling)."
        )
        col_sarif, col_oscal = st.columns(2)

        with col_sarif:
            sarif_bytes = report_generator.to_sarif(all_results).encode()
            st.download_button(
                label="⬇️ Download SARIF 2.1.0",
                data=sarif_bytes,
                file_name="audit-results.sarif.json",
                mime="application/json",
                use_container_width=True,
                key=f"dl_sarif_{id(all_results)}",
            )
            st.caption("Compatible with GitHub Code Scanning, VS Code, and most SAST dashboards.")

        with col_oscal:
            oscal_bytes = report_generator.to_oscal(all_results).encode()
            st.download_button(
                label="⬇️ Download OSCAL Assessment Results",
                data=oscal_bytes,
                file_name="audit-results.oscal.json",
                mime="application/json",
                use_container_width=True,
                key=f"dl_oscal_{id(all_results)}",
            )
            st.caption("NIST OSCAL 1.1.x format for GRC tools and compliance evidence.")




def _source_for_finding(f: dict, file_map: dict) -> str:
    """Return the source string for the file a finding references, or ''."""
    rel = f.get("file", "")
    return file_map.get("files", {}).get(rel, {}).get("source", "") or ""


def _render_create_pr_panel(file_map: dict) -> None:
    """
    Render the 'Create PR' panel below the findings section.
    Collects all actor-critic approved fixes from session state and opens a PR.
    """
    approved: list = st.session_state.get("approved_fixes", [])

    st.markdown("---")
    st.subheader("🚀 Create Pull Request")

    if not approved:
        st.info(
            "No fixes queued yet. Click **🔧 Generate Fix** on any finding above — "
            "once the critic approves the fix, it will appear here."
        )
        return

    n = len(approved)
    st.success(f"{n} fix(es) approved by the critic and ready to commit.")

    # Show a summary table
    rows = []
    for r in approved:
        f = r.finding
        rows.append({
            "File": f.get("file", "—"),
            "Line": f.get("lineno", "—"),
            "Finding": f.get("title", "—"),
            "Severity": f.get("severity", "—"),
            "Critic": r.critic_verdict,
        })
    import pandas as pd
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    # Repo path for git operations
    repo_root_candidate = file_map.get("root", "")
    # For directory / zip ingestion the root label may be a name, not a path;
    # allow the user to override it.
    repo_path_input = st.text_input(
        "Repository path for git operations:",
        value=str(pathlib.Path.cwd()),
        key="pr_repo_path",
        help="Must be inside a git repository. Defaults to the current working directory.",
    )
    base_branch_input = st.text_input(
        "Base branch (PR target):",
        value="main",
        key="pr_base_branch",
    )

    col_pr, col_clear = st.columns([3, 1])
    with col_pr:
        if st.button("🚀 Create PR", key="btn_create_pr", use_container_width=True):
            with st.spinner("Creating branch, applying fixes, and opening PR…"):
                result = pr_helper.run_pr_workflow(
                    fix_results  = approved,
                    repo_path    = repo_path_input.strip(),
                    base_branch  = base_branch_input.strip() or "main",
                )
            if result.success:
                st.success(f"✅ PR created successfully!")
                st.markdown(f"**Branch:** `{result.branch}`")
                st.markdown(f"**Commit:** `{result.commit_sha[:12] if result.commit_sha else '—'}`")
                if result.pr_url.startswith("http"):
                    st.markdown(f"**PR URL:** [{result.pr_url}]({result.pr_url})")
                else:
                    st.info(result.pr_url)
                with st.expander("📝 Commit message", expanded=False):
                    st.code(result.commit_message, language="text")
                if result.files_patched:
                    st.markdown("**Files patched:** " + ", ".join(f"`{p}`" for p in result.files_patched))
                # Clear the queue after a successful PR
                st.session_state["approved_fixes"] = []
            else:
                st.error(f"❌ PR workflow failed: {result.error}")

    with col_clear:
        if st.button("🗑️ Clear Queue", key="btn_clear_fixes", use_container_width=True):
            st.session_state["approved_fixes"] = []
            st.rerun()


def _render_results(all_results: dict, file_map: dict) -> None:
    """Render the full audit results panel."""
    all_security = _flatten(all_results, "security_findings")
    all_logic    = _flatten(all_results, "logic_findings")
    all_parse    = _flatten(all_results, "parse_errors")

    # ── Summary bar ─────────────────────────────────────────────────────────
    n_files = len(all_results)
    n_sec   = len(all_security)
    n_logic = len(all_logic)
    n_parse = len(all_parse)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Python files audited", n_files)
    m2.metric("Security findings",    n_sec,   delta=n_sec  or None, delta_color="inverse")
    m3.metric("Logic findings",       n_logic, delta=n_logic or None, delta_color="inverse")
    m4.metric("Parse errors",         n_parse, delta=n_parse or None, delta_color="inverse")

    st.markdown("---")

    # ── Dependencies ────────────────────────────────────────────────────────
    _render_dependency_panel(file_map.get("dependencies", {}))

    # ── Per-column findings ──────────────────────────────────────────────────
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🔒 Security Subagent Findings")
        if not all_security:
            st.success("✅ No security issues detected.")
        else:
            sec_errors   = [f for f in all_security if f["severity"] == "error"]
            sec_warnings = [f for f in all_security if f["severity"] == "warning"]
            for f in sec_errors:
                _render_finding_expander(f, "🔴", expanded=True,
                                         source=_source_for_finding(f, file_map))
            for f in sec_warnings:
                _render_finding_expander(f, "🟡", expanded=False,
                                         source=_source_for_finding(f, file_map))

    with col2:
        st.subheader("⚙️ Logic & Bug Subagent Findings")
        if all_parse:
            for err in all_parse:
                st.error(f"🔴 {err}")
        if not all_logic and not all_parse:
            st.success("✅ Logic check passed — no issues detected.")
        else:
            errors   = [f for f in all_logic if f["severity"] == "error"]
            warnings = [f for f in all_logic if f["severity"] == "warning"]
            for f in errors:
                _render_finding_expander(f, "🔴", expanded=True,
                                         source=_source_for_finding(f, file_map))
            for f in warnings:
                _render_finding_expander(f, "🟡", expanded=False,
                                         source=_source_for_finding(f, file_map))

    st.markdown("---")
    st.subheader("💡 Refactored Suggestion (Compiler Output)")
    refactor_text = _build_refactor_suggestions(all_logic, all_security)
    st.code(refactor_text, language="python")

    # ── Actor-Critic Create PR panel ─────────────────────────────────────────
    _render_create_pr_panel(file_map)

    # ── Report downloads ─────────────────────────────────────────────────────
    _render_download_buttons(all_results)

    # ── File map summary ─────────────────────────────────────────────────────
    if len(file_map["files"]) > 1:
        with st.expander(f"📂 File Map ({len(file_map['files'])} files ingested)", expanded=False):
            rows = []
            for rel, entry in sorted(file_map["files"].items()):
                ext  = pathlib.Path(rel).suffix.lower()
                rows.append({
                    "File": rel,
                    "Size (B)": entry["size_bytes"],
                    "Type": ext or "—",
                    "AST": "✅" if entry.get("ast_tree") else ("❌" if ext == ".py" else "—"),
                })
            import pandas as pd
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        if file_map.get("skipped"):
            with st.expander(f"⏭️ Skipped ({len(file_map['skipped'])} paths)", expanded=False):
                st.code("\n".join(file_map["skipped"]), language="text")


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

tab_paste, tab_repo, tab_zip = st.tabs([
    "📋 Paste Code",
    "📁 Repository Path",
    "🗜️ Upload ZIP",
])

# ── Tab 1: single-file text paste (original flow) ───────────────────────────
with tab_paste:
    st.markdown("Paste a single Python file for a quick audit.")
    code_input = st.text_area("Python code:", height=250, key="paste_code")

    if st.button("Run Audit", key="btn_paste"):
        if not code_input.strip():
            st.warning("Please paste some code first!")
        else:
            st.success("Analysing pasted code…")
            single_file_map = {
                "files": {
                    "pasted_code.py": {
                        "source": code_input,
                        "ast_tree": None,
                        "parse_error": None,
                        "size_bytes": len(code_input.encode()),
                    }
                },
                "dependencies": {"python": [], "node": []},
                "skipped": [],
                "root": "paste",
            }
            all_results = run_audit_on_file_map(single_file_map)
            _render_results(all_results, single_file_map)

# ── Tab 2: local repository path ────────────────────────────────────────────
with tab_repo:
    st.markdown(
        "Enter the absolute path to a local repository. "
        "The engine will walk all Python files, respect `.gitignore`, "
        "skip vendor/binary folders, and scan `requirements.txt` / `package.json`."
    )
    repo_path = st.text_input(
        "Repository path:",
        placeholder="/home/user/my-project  or  C:\\Users\\me\\my-project",
        key="repo_path",
    )

    if st.button("Ingest & Audit Repository", key="btn_repo"):
        if not repo_path.strip():
            st.warning("Please enter a repository path.")
        elif not os.path.isdir(repo_path.strip()):
            st.error(f"Directory not found: `{repo_path.strip()}`")
        else:
            with st.spinner("Walking repository…"):
                try:
                    file_map = ingestion.ingest_directory(repo_path.strip())
                except Exception as exc:
                    st.error(f"Ingestion error: {exc}")
                    st.stop()

            n_py = sum(
                1 for rel in file_map["files"]
                if pathlib.Path(rel).suffix.lower() == ".py"
            )
            if n_py == 0:
                st.warning(
                    f"No Python files found under `{repo_path.strip()}`. "
                    "Check the path or that the project contains `.py` files."
                )
            else:
                st.success(
                    f"Ingested **{len(file_map['files'])}** files "
                    f"({n_py} Python) from `{file_map['root']}`"
                )
                with st.spinner("Running audit across all Python files…"):
                    all_results = run_audit_on_file_map(file_map)
                _render_results(all_results, file_map)

# ── Tab 3: ZIP upload ────────────────────────────────────────────────────────
with tab_zip:
    st.markdown(
        "Upload a `.zip` archive of your project. "
        "The engine will extract it in-memory, walk Python files, "
        "and scan for dependencies — no files are written to disk."
    )
    uploaded = st.file_uploader("Upload ZIP archive:", type=["zip"], key="zip_upload")

    if st.button("Ingest & Audit ZIP", key="btn_zip"):
        if uploaded is None:
            st.warning("Please upload a ZIP file first.")
        else:
            with st.spinner("Extracting and scanning ZIP…"):
                try:
                    file_map = ingestion.ingest_zip(uploaded.read(), uploaded.name)
                except Exception as exc:
                    st.error(f"Ingestion error: {exc}")
                    st.stop()

            n_py = sum(
                1 for rel in file_map["files"]
                if pathlib.Path(rel).suffix.lower() == ".py"
            )
            if n_py == 0:
                st.warning("No Python files found in the uploaded archive.")
            else:
                st.success(
                    f"Extracted **{len(file_map['files'])}** files "
                    f"({n_py} Python) from `{file_map['root']}`"
                )
                with st.spinner("Running audit across all Python files…"):
                    all_results = run_audit_on_file_map(file_map)
                _render_results(all_results, file_map)