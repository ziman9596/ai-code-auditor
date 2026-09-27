"""
ingestion.py — Repository Ingestion Engine
===========================================
Accepts either:
  • A local filesystem path to a repository directory
  • A bytes payload of a .zip archive

Produces a structured FileMap:
  {
    "files": {
        "<rel_path>": {
            "source":   str | None,      # UTF-8 decoded source, None for binary
            "ast_tree": ast.AST | None,  # parsed AST for .py files, None otherwise
            "parse_error": str | None,   # syntax error message if AST parse failed
            "size_bytes": int,
        }
    },
    "dependencies": {                    # from requirements.txt / package.json
        "python": [...],                 # list of requirement strings
        "node":   [...],                 # list of package name strings
    },
    "skipped": [...],   # list of rel_paths skipped (binary / vendor / gitignored)
    "root": str,        # resolved root label (directory name or zip name)
  }
"""

from __future__ import annotations

import ast
import io
import json
import os
import pathlib
import re
import zipfile
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Directories always skipped regardless of .gitignore
_VENDOR_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    ".venv", "venv", "env", ".env",
    "node_modules", "bower_components",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
    "dist", "build", "target", "out", "bin", "obj",
    ".idea", ".vscode",
    "vendor", "third_party", "thirdparty",
    "Pods", "Carthage",
})

# File extensions that are always binary/non-auditable
_BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".pyc", ".pyo", ".pyd",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".pptx",
    ".ttf", ".woff", ".woff2", ".eot",
    ".lock",    # package-lock.json is text but too noisy; skip lockfiles
    ".sum",     # go.sum
})

# Hard cap on source file size to prevent memory issues (1 MB)
_MAX_FILE_BYTES: int = 1 * 1024 * 1024

# Hard cap on total files ingested per run
_MAX_FILES: int = 500


# ---------------------------------------------------------------------------
# .gitignore parser (minimal — covers the most common patterns)
# ---------------------------------------------------------------------------

def _compile_gitignore(root: pathlib.Path) -> list[re.Pattern]:
    """
    Parse all .gitignore files rooted at *root* and return compiled patterns.
    Supports glob-style patterns: *, **, ?, directory-trailing /, negation (!).
    Negation patterns are silently dropped (conservative: never un-ignore).

    .gitignore files found inside vendor/hidden directories (e.g. .venv, node_modules)
    are intentionally skipped — those directories are excluded wholesale anyway and
    their wildcard patterns (e.g. the bare ``*`` venv writes) must not leak upward.
    """
    patterns: list[re.Pattern] = []
    for gitignore_path in root.rglob(".gitignore"):
        # Skip .gitignore files whose path passes through a vendor/hidden dir
        relative_parts = gitignore_path.relative_to(root).parts
        if any(_should_skip_dir(part) for part in relative_parts[:-1]):
            continue
        try:
            text = gitignore_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            patterns.append(_gitignore_pattern_to_regex(line))
    return patterns


def _gitignore_pattern_to_regex(pattern: str) -> re.Pattern:
    """Convert a single gitignore glob pattern to a compiled regex."""
    # Strip trailing slash (directory marker — we match either)
    pattern = pattern.rstrip("/")
    # Escape regex special chars except * and ?
    escaped = re.escape(pattern).replace(r"\*\*", "**").replace(r"\*", "*").replace(r"\?", "?")
    # Convert glob wildcards to regex
    escaped = escaped.replace("**", "¶¶¶")   # temp placeholder
    escaped = escaped.replace("*", "[^/]*")
    escaped = escaped.replace("¶¶¶", ".*")
    escaped = escaped.replace("?", "[^/]")
    # If no slash in original, match at any path component
    if "/" not in pattern:
        regex = r"(^|.*/)(" + escaped + r")(/.+)?$"
    else:
        regex = r"(^|.*?/)" + escaped + r"(/.*)?$"
    return re.compile(regex)


def _is_gitignored(rel_path: str, patterns: list[re.Pattern]) -> bool:
    normalized = rel_path.replace("\\", "/")
    return any(p.match(normalized) for p in patterns)


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _should_skip_dir(name: str) -> bool:
    return name in _VENDOR_DIRS or name.startswith(".")


def _should_skip_file(name: str) -> bool:
    ext = pathlib.Path(name).suffix.lower()
    return ext in _BINARY_EXTENSIONS


def _read_text_safe(data: bytes) -> tuple[Optional[str], bool]:
    """
    Attempt UTF-8 decode. Returns (text, is_binary).
    Falls back to latin-1 sniff for true binary detection.
    """
    try:
        return data.decode("utf-8"), False
    except UnicodeDecodeError:
        pass
    # Heuristic: if > 30 % non-printable bytes, treat as binary
    non_printable = sum(1 for b in data[:2048] if b < 9 or (13 < b < 32) or b == 127)
    if len(data[:2048]) > 0 and non_printable / len(data[:2048]) > 0.30:
        return None, True
    return data.decode("latin-1", errors="replace"), False


def _parse_py(source: str, rel_path: str) -> tuple[Optional[ast.AST], Optional[str]]:
    try:
        return ast.parse(source, filename=rel_path), None
    except SyntaxError as exc:
        return None, f"SyntaxError on line {exc.lineno}: {exc.msg}"
    except Exception as exc:  # pragma: no cover
        return None, str(exc)


# ---------------------------------------------------------------------------
# Dependency file parsers
# ---------------------------------------------------------------------------

def _parse_requirements_txt(source: str) -> list[str]:
    """Return package specifiers from a requirements.txt string."""
    reqs = []
    for line in source.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip inline comments
        line = line.split("#")[0].strip()
        if line:
            reqs.append(line)
    return reqs


def _parse_package_json(source: str) -> list[str]:
    """Return package names from dependencies + devDependencies."""
    try:
        data = json.loads(source)
    except json.JSONDecodeError:
        return []
    pkgs: list[str] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        pkgs.extend(data.get(section, {}).keys())
    return pkgs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ingest_directory(path: str) -> dict:
    """
    Walk a local repository directory and return a FileMap.
    Respects .gitignore patterns and skips vendor/binary paths.
    """
    root = pathlib.Path(path).resolve()
    if not root.is_dir():
        raise ValueError(f"Path is not a directory: {path}")

    gitignore_patterns = _compile_gitignore(root)
    return _walk_root(root, root, gitignore_patterns, root.name)


def ingest_zip(data: bytes, zip_name: str = "upload.zip") -> dict:
    """
    Extract a zip archive in-memory and return a FileMap.
    Skips vendor/binary paths.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Invalid ZIP file: {exc}") from exc

    # Many zips have a single top-level folder — detect and strip it
    members = [m for m in zf.infolist() if not m.filename.endswith("/")]
    parts = [pathlib.PurePosixPath(m.filename).parts for m in zf.infolist()]
    top_dirs = {p[0] for p in parts if len(p) > 1}
    strip_prefix: str | None = top_dirs.pop() if len(top_dirs) == 1 else None

    return _walk_zip(zf, members, strip_prefix, zip_name)


# ---------------------------------------------------------------------------
# Internal walkers
# ---------------------------------------------------------------------------

def _walk_root(
    root: pathlib.Path,
    current: pathlib.Path,
    gitignore_patterns: list[re.Pattern],
    label: str,
) -> dict:
    file_map: dict = {
        "files": {},
        "dependencies": {"python": [], "node": []},
        "skipped": [],
        "root": label,
    }

    for dirpath, dirnames, filenames in os.walk(current):
        dp = pathlib.Path(dirpath)
        rel_dir = dp.relative_to(root).as_posix()

        # Prune vendor/hidden dirs in-place (modifies dirnames so os.walk skips them)
        dirnames[:] = [
            d for d in dirnames
            if not _should_skip_dir(d)
            and not _is_gitignored((rel_dir + "/" + d).lstrip("/"), gitignore_patterns)
        ]

        for fname in filenames:
            if len(file_map["files"]) >= _MAX_FILES:
                file_map["skipped"].append(f"(file limit {_MAX_FILES} reached)")
                return file_map

            rel = (rel_dir + "/" + fname).lstrip("/") if rel_dir != "." else fname
            rel = rel.lstrip("/")

            if _should_skip_file(fname):
                file_map["skipped"].append(rel)
                continue
            if _is_gitignored(rel, gitignore_patterns):
                file_map["skipped"].append(rel)
                continue

            fpath = dp / fname
            try:
                raw = fpath.read_bytes()
            except OSError:
                file_map["skipped"].append(rel)
                continue

            _process_file(rel, fname, raw, file_map)

    return file_map


def _walk_zip(
    zf: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    strip_prefix: Optional[str],
    label: str,
) -> dict:
    file_map: dict = {
        "files": {},
        "dependencies": {"python": [], "node": []},
        "skipped": [],
        "root": pathlib.Path(label).stem,
    }

    for info in members:
        if len(file_map["files"]) >= _MAX_FILES:
            file_map["skipped"].append(f"(file limit {_MAX_FILES} reached)")
            break

        rel = info.filename
        # Strip common top-level prefix
        if strip_prefix and rel.startswith(strip_prefix + "/"):
            rel = rel[len(strip_prefix) + 1:]

        rel = rel.lstrip("/")
        if not rel:
            continue

        parts = pathlib.PurePosixPath(rel).parts
        fname = parts[-1]

        # Skip if any ancestor directory is a vendor/hidden dir
        if any(_should_skip_dir(p) for p in parts[:-1]):
            file_map["skipped"].append(rel)
            continue
        if _should_skip_file(fname):
            file_map["skipped"].append(rel)
            continue

        try:
            raw = zf.read(info.filename)
        except Exception:
            file_map["skipped"].append(rel)
            continue

        _process_file(rel, fname, raw, file_map)

    return file_map


def _process_file(rel: str, fname: str, raw: bytes, file_map: dict) -> None:
    """Decode, parse, and register one file into *file_map*."""
    if len(raw) > _MAX_FILE_BYTES:
        file_map["skipped"].append(f"{rel} (>{_MAX_FILE_BYTES // 1024} KB)")
        return

    source, is_binary = _read_text_safe(raw)
    if is_binary:
        file_map["skipped"].append(f"{rel} (binary)")
        return

    entry: dict = {
        "source": source,
        "ast_tree": None,
        "parse_error": None,
        "size_bytes": len(raw),
    }

    ext = pathlib.Path(fname).suffix.lower()
    if ext == ".py" and source is not None:
        entry["ast_tree"], entry["parse_error"] = _parse_py(source, rel)

    file_map["files"][rel] = entry

    # --- dependency scanning ---
    if fname == "requirements.txt" and source:
        file_map["dependencies"]["python"].extend(_parse_requirements_txt(source))
    elif fname == "package.json" and source:
        file_map["dependencies"]["node"].extend(_parse_package_json(source))
