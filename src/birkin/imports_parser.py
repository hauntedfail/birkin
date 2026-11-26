"""Multi-language static import extractor for architectural fitness checks.

Supports Python (AST), Go, Rust, and TypeScript/JavaScript using only Python stdlib.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ImportEdge:
    """A single source-to-target import relationship."""

    source_file: str  # repo-relative POSIX path
    line: int
    raw: str
    resolved_path: str | None  # repo-relative POSIX path if resolved inside repo


_GO_SINGLE_IMPORT_RE = re.compile(r'^\s*import\s+(?:[A-Za-z0-9_.]+\s+)?"([^"]+)"')
_GO_BLOCK_START_RE = re.compile(r"^\s*import\s*\(\s*$")
_GO_BLOCK_ITEM_RE = re.compile(r'^\s*(?:[A-Za-z0-9_.]+\s+)?"([^"]+)"')

_RUST_USE_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+([^;]+);")
_RUST_MOD_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")

_TS_IMPORT_RE = re.compile(
    r"""(?:import|export)\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]"""
    r"""|import\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""|require\(\s*['"]([^'"]+)['"]\s*\)"""
)


def _strip_c_comments(text: str) -> str:
    """Replace // and /* */ comments with whitespace while preserving line numbers."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_str: str | None = None
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n:
                if text[i] == "\n":
                    out.append("\n")
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    i += 2
                    break
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _detect_go_module(repo_root: Path) -> str | None:
    gomod = repo_root / "go.mod"
    if not gomod.is_file():
        return None
    for line in gomod.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s.startswith("module "):
            return s.split(None, 1)[1].strip()
    return None


def _python_roots(repo_root: Path) -> list[Path]:
    roots: list[Path] = []
    if (repo_root / "src").is_dir():
        roots.append(repo_root / "src")
    roots.append(repo_root)
    return roots


def _resolve_python_module(module: str, repo_root: Path, roots: list[Path]) -> str | None:
    parts = [p for p in module.split(".") if p]
    if not parts:
        return None
    for root in roots:
        # Check full module path and progressively shorter prefixes (for `from pkg.mod import symbol`)
        for length in range(len(parts), 0, -1):
            sub = parts[:length]
            py_file = root.joinpath(*sub).with_suffix(".py")
            if py_file.is_file():
                return py_file.relative_to(repo_root).as_posix()
            pkg_init = root.joinpath(*sub, "__init__.py")
            if pkg_init.is_file():
                return pkg_init.relative_to(repo_root).as_posix()
    return None


def extract_python_imports(file_path: Path, repo_root: Path) -> list[ImportEdge]:
    rel = file_path.relative_to(repo_root).as_posix()
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=rel)
    except (OSError, SyntaxError):
        return []

    roots = _python_roots(repo_root)
    edges: list[ImportEdge] = []

    # Compute current package parts for relative imports
    cur_pkg_parts: list[str] = []
    for root in roots:
        try:
            sub_rel = file_path.relative_to(root)
            parts = list(sub_rel.with_suffix("").parts)
            if parts and parts[-1] == "__init__":
                parts = parts[:-1]
            else:
                parts = parts[:-1]
            cur_pkg_parts = parts
            break
        except ValueError:
            continue

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                resolved = _resolve_python_module(alias.name, repo_root, roots)
                edges.append(ImportEdge(source_file=rel, line=node.lineno, raw=alias.name, resolved_path=resolved))
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if node.level > 0:
                base_len = max(0, len(cur_pkg_parts) - (node.level - 1))
                prefix = cur_pkg_parts[:base_len]
                full_mod = ".".join([*prefix, *([mod] if mod else [])])
                raw = ("." * node.level) + mod
            else:
                full_mod = mod
                raw = mod

            # Try resolving `from pkg import submodule` first, else `full_mod`
            if node.names and any(alias.name != "*" for alias in node.names):
                emitted = False
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    candidate = f"{full_mod}.{alias.name}" if full_mod else alias.name
                    res_sub = _resolve_python_module(candidate, repo_root, roots)
                    if res_sub is not None:
                        edges.append(
                            ImportEdge(
                                source_file=rel,
                                line=node.lineno,
                                raw=f"{raw}.{alias.name}" if raw else alias.name,
                                resolved_path=res_sub,
                            )
                        )
                        emitted = True
                if not emitted and full_mod:
                    resolved = _resolve_python_module(full_mod, repo_root, roots)
                    edges.append(ImportEdge(source_file=rel, line=node.lineno, raw=raw, resolved_path=resolved))
            elif full_mod:
                resolved = _resolve_python_module(full_mod, repo_root, roots)
                edges.append(ImportEdge(source_file=rel, line=node.lineno, raw=raw, resolved_path=resolved))
    return edges


def extract_go_imports(file_path: Path, repo_root: Path, go_module: str | None = None) -> list[ImportEdge]:
    rel = file_path.relative_to(repo_root).as_posix()
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    mod = go_module if go_module is not None else _detect_go_module(repo_root)
    cleaned = _strip_c_comments(text)
    edges: list[ImportEdge] = []
    in_block = False
    for idx, line in enumerate(cleaned.splitlines(), start=1):
        stripped = line.strip()
        if not in_block:
            if _GO_BLOCK_START_RE.match(line):
                in_block = True
                continue
            m = _GO_SINGLE_IMPORT_RE.match(line)
            if m:
                pkg = m.group(1)
                resolved = _resolve_go_import(pkg, mod, repo_root)
                edges.append(ImportEdge(source_file=rel, line=idx, raw=pkg, resolved_path=resolved))
        else:
            if stripped.startswith(")"):
                in_block = False
                continue
            m = _GO_BLOCK_ITEM_RE.match(line)
            if m:
                pkg = m.group(1)
                resolved = _resolve_go_import(pkg, mod, repo_root)
                edges.append(ImportEdge(source_file=rel, line=idx, raw=pkg, resolved_path=resolved))
    return edges


def _resolve_go_import(pkg: str, go_module: str | None, repo_root: Path) -> str | None:
    if not go_module or not pkg.startswith(go_module):
        return None
    sub = pkg[len(go_module) :].lstrip("/")
    if not sub:
        return "."
    target_dir = repo_root / sub
    if target_dir.is_dir():
        return sub
    return None


def _resolve_rust_path(parts: list[str], repo_root: Path, crate_src: Path) -> str | None:
    for length in range(len(parts), 0, -1):
        sub = parts[:length]
        rs_file = crate_src.joinpath(*sub).with_suffix(".rs")
        if rs_file.is_file():
            return rs_file.relative_to(repo_root).as_posix()
        mod_rs = crate_src.joinpath(*sub, "mod.rs")
        if mod_rs.is_file():
            return mod_rs.relative_to(repo_root).as_posix()
    return None


def extract_rust_imports(file_path: Path, repo_root: Path) -> list[ImportEdge]:
    rel = file_path.relative_to(repo_root).as_posix()
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_c_comments(text)
    crate_src = repo_root / "src"
    edges: list[ImportEdge] = []

    for idx, line in enumerate(cleaned.splitlines(), start=1):
        m_use = _RUST_USE_RE.match(line)
        if m_use:
            raw_expr = m_use.group(1).strip()
            # Normalize grouped use `crate::foo::{a, b}` -> inspect prefix `crate::foo`
            base_expr = raw_expr.split("{", 1)[0].rstrip(":")
            base_expr = base_expr.split(" as ", 1)[0].strip()
            parts = [p for p in base_expr.split("::") if p]
            resolved: str | None = None
            if parts and parts[0] == "crate" and crate_src.is_dir():
                resolved = _resolve_rust_path(parts[1:], repo_root, crate_src)
            elif parts and parts[0] == "super":
                parent_dir = file_path.parent
                ups = 0
                while ups < len(parts) and parts[ups] == "super":
                    parent_dir = parent_dir.parent
                    ups += 1
                rem = parts[ups:]
                if rem:
                    resolved = _resolve_rust_path(rem, repo_root, parent_dir)
            edges.append(ImportEdge(source_file=rel, line=idx, raw=raw_expr, resolved_path=resolved))
            continue

        m_mod = _RUST_MOD_RE.match(line)
        if m_mod:
            mod_name = m_mod.group(1)
            resolved = _resolve_rust_path([mod_name], repo_root, file_path.parent)
            edges.append(ImportEdge(source_file=rel, line=idx, raw=f"mod {mod_name}", resolved_path=resolved))
    return edges


_TS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")


def _resolve_ts_import(specifier: str, file_path: Path, repo_root: Path) -> str | None:
    if not specifier.startswith("."):
        return None
    base = (file_path.parent / specifier).resolve()
    try:
        base.relative_to(repo_root.resolve())
    except ValueError:
        return None

    candidates = [base]
    # Handle ESM .js -> .ts mapping
    if base.suffix in (".js", ".mjs", ".cjs"):
        candidates.append(base.with_suffix(".ts"))
        candidates.append(base.with_suffix(".tsx"))
    for ext in _TS_EXTENSIONS:
        candidates.append(Path(str(base) + ext))
    for ext in _TS_EXTENSIONS:
        candidates.append(base / f"index{ext}")

    for cand in candidates:
        if cand.is_file():
            return cand.resolve().relative_to(repo_root.resolve()).as_posix()
    return None


def extract_ts_imports(file_path: Path, repo_root: Path) -> list[ImportEdge]:
    rel = file_path.relative_to(repo_root).as_posix()
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_c_comments(text)
    edges: list[ImportEdge] = []
    for match in _TS_IMPORT_RE.finditer(cleaned):
        specifier = match.group(1) or match.group(2) or match.group(3)
        if not specifier:
            continue
        line_no = cleaned.count("\n", 0, match.start()) + 1
        resolved = _resolve_ts_import(specifier, file_path, repo_root)
        edges.append(ImportEdge(source_file=rel, line=line_no, raw=specifier, resolved_path=resolved))
    return edges


def extract_imports_for_file(file_path: Path, repo_root: Path, *, go_module: str | None = None) -> list[ImportEdge]:
    """Dispatch import extraction by file suffix."""
    suffix = file_path.suffix.lower()
    if suffix == ".py":
        return extract_python_imports(file_path, repo_root)
    if suffix == ".go":
        return extract_go_imports(file_path, repo_root, go_module=go_module)
    if suffix == ".rs":
        return extract_rust_imports(file_path, repo_root)
    if suffix in _TS_EXTENSIONS:
        return extract_ts_imports(file_path, repo_root)
    return []
