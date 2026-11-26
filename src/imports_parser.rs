//! Multi-language static import extractor for architectural fitness checks.
//!
//! Supports Python, Go, Rust, Lean 4, and TypeScript/JavaScript natively with zero external runtimes.

use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEdge {
    pub source_file: String,
    pub line: usize,
    pub raw: String,
    pub resolved_path: Option<String>,
}

impl ImportEdge {
    fn new(source_file: &str, line: usize, raw: impl Into<String>, resolved_path: Option<String>) -> Self {
        Self {
            source_file: source_file.to_string(),
            line,
            raw: raw.into(),
            resolved_path,
        }
    }
}

const TS_EXTENSIONS: &[&str] = &[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];

fn rel_posix(path: &Path, root: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    Some(rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/"))
}

/// Strip `//` and `/* ... */` comments while preserving line numbers and string literals.
fn strip_c_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_str: Option<char> = None;

    while i < n {
        let ch = chars[i];
        if let Some(q) = in_str {
            out.push(ch);
            if ch == '\\' && i + 1 < n {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if ch == q {
                in_str = None;
            }
            i += 1;
            continue;
        }
        if ch == '"' || ch == '\'' || ch == '`' {
            in_str = Some(ch);
            out.push(ch);
            i += 1;
            continue;
        }
        if ch == '/' && i + 1 < n && chars[i + 1] == '/' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '/' && i + 1 < n && chars[i + 1] == '*' {
            i += 2;
            while i < n {
                if chars[i] == '\n' {
                    out.push('\n');
                }
                if chars[i] == '*' && i + 1 < n && chars[i + 1] == '/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }
        out.push(ch);
        i += 1;
    }
    out
}

/// Detect the Go module path declared in `go.mod`, if present.
pub fn detect_go_module(repo_root: &Path) -> Option<String> {
    let text = fs::read_to_string(repo_root.join("go.mod")).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("module ") {
            let mod_name = rest.trim();
            if !mod_name.is_empty() {
                return Some(mod_name.to_string());
            }
        }
    }
    None
}

fn python_roots(repo_root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let src = repo_root.join("src");
    if src.is_dir() {
        roots.push(src);
    }
    roots.push(repo_root.to_path_buf());
    roots
}

fn resolve_python_module(module: &str, repo_root: &Path, roots: &[PathBuf]) -> Option<String> {
    let parts: Vec<&str> = module.split('.').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    for root in roots {
        for len in (1..=parts.len()).rev() {
            let mut candidate = root.clone();
            for p in &parts[..len] {
                candidate.push(p);
            }
            let py_file = candidate.with_extension("py");
            if py_file.is_file() {
                return rel_posix(&py_file, repo_root);
            }
            let pkg_init = candidate.join("__init__.py");
            if pkg_init.is_file() {
                return rel_posix(&pkg_init, repo_root);
            }
        }
    }
    None
}

/// Extract Python `import` and `from ... import` edges, skipping triple-quoted strings and comments.
pub fn extract_python_imports(file_path: &Path, repo_root: &Path) -> Vec<ImportEdge> {
    let Some(rel) = rel_posix(file_path, repo_root) else {
        return Vec::new();
    };
    let Ok(source) = fs::read_to_string(file_path) else {
        return Vec::new();
    };
    let roots = python_roots(repo_root);
    let mut cur_pkg_parts: Vec<String> = Vec::new();
    for root in &roots {
        if let Ok(sub_rel) = file_path.strip_prefix(root) {
            let mut parts: Vec<String> = sub_rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            if !parts.is_empty() {
                parts.pop();
            }
            cur_pkg_parts = parts;
            break;
        }
    }

    let import_re = Regex::new(r"^\s*import\s+(.+)$").unwrap();
    let from_re = Regex::new(r"^\s*from\s+(\.*(?:[A-Za-z_][A-Za-z0-9_.]*)?)\s+import\s+(.+)$").unwrap();
    let mut edges = Vec::new();
    let mut in_triple: Option<&str> = None;
    let lines: Vec<&str> = source.lines().collect();
    let mut idx = 0;

    while idx < lines.len() {
        let line_no = idx + 1;
        let line = lines[idx];
        let trimmed = line.trim();

        // Track triple-quoted multiline docstrings / string literals
        if let Some(delim) = in_triple {
            if trimmed.contains(delim) {
                in_triple = None;
            }
            idx += 1;
            continue;
        }
        for delim in ["\"\"\"", "'''"] {
            let count = trimmed.matches(delim).count();
            if count % 2 == 1 {
                in_triple = Some(delim);
            }
        }
        if in_triple.is_some() || trimmed.is_empty() || trimmed.starts_with('#') {
            idx += 1;
            continue;
        }

        // Strip trailing inline comment
        let code = line.split('#').next().unwrap_or(line);

        if let Some(caps) = import_re.captures(code) {
            let targets = caps[1].trim();
            for part in targets.split(',') {
                let mod_name = part
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim();
                if mod_name.is_empty() {
                    continue;
                }
                let resolved = resolve_python_module(mod_name, repo_root, &roots);
                edges.push(ImportEdge::new(&rel, line_no, mod_name, resolved));
            }
            idx += 1;
            continue;
        }

        if let Some(caps) = from_re.captures(code) {
            let raw_mod = caps[1].trim();
            let mut names_str = caps[2].trim().to_string();
            // Handle parenthesized multi-line `from x import (\n a, b\n)`
            if names_str.starts_with('(') && !names_str.contains(')') {
                while idx + 1 < lines.len() {
                    idx += 1;
                    let next_code = lines[idx].split('#').next().unwrap_or("");
                    names_str.push(' ');
                    names_str.push_str(next_code.trim());
                    if next_code.contains(')') {
                        break;
                    }
                }
            }
            let level = raw_mod.chars().take_while(|&c| c == '.').count();
            let mod_tail = &raw_mod[level..];
            let full_mod = if level > 0 {
                let base_len = cur_pkg_parts.len().saturating_sub(level - 1);
                let mut prefix = cur_pkg_parts[..base_len].to_vec();
                if !mod_tail.is_empty() {
                    prefix.push(mod_tail.to_string());
                }
                prefix.join(".")
            } else {
                mod_tail.to_string()
            };

            let cleaned_names = names_str.trim_matches(|c| c == '(' || c == ')');
            let aliases: Vec<&str> = cleaned_names
                .split(',')
                .filter_map(|item| {
                    let sym = item.split_whitespace().next().unwrap_or("").trim();
                    if sym.is_empty() || sym == "*" {
                        None
                    } else {
                        Some(sym)
                    }
                })
                .collect();

            let mut emitted = false;
            for sym in &aliases {
                let candidate = if full_mod.is_empty() {
                    (*sym).to_string()
                } else {
                    format!("{full_mod}.{sym}")
                };
                if let Some(res_sub) = resolve_python_module(&candidate, repo_root, &roots) {
                    let raw = if raw_mod.is_empty() { (*sym).to_string() } else { format!("{raw_mod}.{sym}") };
                    edges.push(ImportEdge::new(&rel, line_no, raw, Some(res_sub)));
                    emitted = true;
                }
            }
            if !emitted && !full_mod.is_empty() {
                let resolved = resolve_python_module(&full_mod, repo_root, &roots);
                edges.push(ImportEdge::new(&rel, line_no, raw_mod, resolved));
            }
        }
        idx += 1;
    }

    edges
}

fn resolve_go_import(pkg: &str, go_module: Option<&str>, repo_root: &Path) -> Option<String> {
    let gm = go_module?;
    if !pkg.starts_with(gm) {
        return None;
    }
    let sub = pkg[gm.len()..].trim_start_matches('/');
    if sub.is_empty() {
        return Some(".".to_string());
    }
    if repo_root.join(sub).is_dir() {
        return Some(sub.to_string());
    }
    None
}

pub fn extract_go_imports(
    file_path: &Path,
    repo_root: &Path,
    go_module: Option<&str>,
) -> Vec<ImportEdge> {
    let Some(rel) = rel_posix(file_path, repo_root) else {
        return Vec::new();
    };
    let Ok(text) = fs::read_to_string(file_path) else {
        return Vec::new();
    };
    let detected;
    let effective_mod = match go_module {
        Some(m) => Some(m),
        None => {
            detected = detect_go_module(repo_root);
            detected.as_deref()
        }
    };
    let cleaned = strip_c_comments(&text);
    let single_re = Regex::new(r#"^\s*import\s+(?:[A-Za-z0-9_.]+\s+)?"([^"]+)""#).unwrap();
    let block_start_re = Regex::new(r"^\s*import\s*\(\s*$").unwrap();
    let block_item_re = Regex::new(r#"^\s*(?:[A-Za-z0-9_.]+\s+)?"([^"]+)""#).unwrap();

    let mut edges = Vec::new();
    let mut in_block = false;
    for (idx, line) in cleaned.lines().enumerate() {
        let line_no = idx + 1;
        let stripped = line.trim();
        if !in_block {
            if block_start_re.is_match(line) {
                in_block = true;
                continue;
            }
            if let Some(caps) = single_re.captures(line) {
                let pkg = &caps[1];
                edges.push(ImportEdge::new(&rel, line_no, pkg, resolve_go_import(pkg, effective_mod, repo_root)));
            }
        } else {
            if stripped.starts_with(')') {
                in_block = false;
                continue;
            }
            if let Some(caps) = block_item_re.captures(line) {
                let pkg = &caps[1];
                edges.push(ImportEdge::new(&rel, line_no, pkg, resolve_go_import(pkg, effective_mod, repo_root)));
            }
        }
    }
    edges
}

fn resolve_rust_path(parts: &[&str], repo_root: &Path, base_dir: &Path) -> Option<String> {
    for len in (1..=parts.len()).rev() {
        let mut candidate = base_dir.to_path_buf();
        for p in &parts[..len] {
            candidate.push(p);
        }
        let rs_file = candidate.with_extension("rs");
        if rs_file.is_file() {
            return rel_posix(&rs_file, repo_root);
        }
        let mod_rs = candidate.join("mod.rs");
        if mod_rs.is_file() {
            return rel_posix(&mod_rs, repo_root);
        }
    }
    None
}

pub fn extract_rust_imports(file_path: &Path, repo_root: &Path) -> Vec<ImportEdge> {
    let Some(rel) = rel_posix(file_path, repo_root) else {
        return Vec::new();
    };
    let Ok(text) = fs::read_to_string(file_path) else {
        return Vec::new();
    };
    let cleaned = strip_c_comments(&text);
    let crate_src = repo_root.join("src");
    let use_re = Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+([^;]+);").unwrap();
    let mod_re = Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;").unwrap();

    let mut edges = Vec::new();
    let lines: Vec<&str> = cleaned.lines().collect();
    let mut idx = 0;
    while idx < lines.len() {
        let line_no = idx + 1;
        let line = lines[idx];

        // Handle multi-line `use crate::foo::{\n ...\n};`
        let trimmed = line.trim();
        let mut stmt = line.to_string();
        if (trimmed.starts_with("use ") || trimmed.starts_with("pub use ") || trimmed.starts_with("pub("))
            && trimmed.contains("use ")
            && !trimmed.contains(';')
        {
            while idx + 1 < lines.len() {
                idx += 1;
                stmt.push(' ');
                stmt.push_str(lines[idx].trim());
                if lines[idx].contains(';') {
                    break;
                }
            }
        }

        if let Some(caps) = use_re.captures(&stmt) {
            let raw_expr = caps[1].trim();
            let base_expr = raw_expr
                .split('{')
                .next()
                .unwrap_or(raw_expr)
                .trim_end_matches(':')
                .split(" as ")
                .next()
                .unwrap_or("")
                .trim();
            let parts: Vec<&str> = base_expr.split("::").filter(|p| !p.is_empty()).collect();
            let mut resolved = None;
            if parts.first() == Some(&"crate") && crate_src.is_dir() {
                resolved = resolve_rust_path(&parts[1..], repo_root, &crate_src);
            } else if parts.first() == Some(&"super") {
                let mut parent_dir = file_path.parent().unwrap_or(repo_root).to_path_buf();
                let mut ups = 0;
                while ups < parts.len() && parts[ups] == "super" {
                    if let Some(p) = parent_dir.parent() {
                        parent_dir = p.to_path_buf();
                    }
                    ups += 1;
                }
                if ups < parts.len() {
                    resolved = resolve_rust_path(&parts[ups..], repo_root, &parent_dir);
                }
            }
            edges.push(ImportEdge::new(&rel, line_no, raw_expr, resolved));
            idx += 1;
            continue;
        }

        if let Some(caps) = mod_re.captures(line) {
            let mod_name = &caps[1];
            let base_dir = file_path.parent().unwrap_or(repo_root);
            let resolved = resolve_rust_path(&[mod_name], repo_root, base_dir);
            edges.push(ImportEdge::new(&rel, line_no, format!("mod {mod_name}"), resolved));
        }
        idx += 1;
    }
    edges
}

fn resolve_ts_import(specifier: &str, file_path: &Path, repo_root: &Path) -> Option<String> {
    if !specifier.starts_with('.') {
        return None;
    }
    let parent = file_path.parent()?;
    let joined = parent.join(specifier);
    let mut candidates = vec![joined.clone()];
    if let Some(ext) = joined.extension().and_then(|e| e.to_str()) {
        if matches!(ext, "js" | "mjs" | "cjs") {
            candidates.push(joined.with_extension("ts"));
            candidates.push(joined.with_extension("tsx"));
        }
    }
    for ext in TS_EXTENSIONS {
        candidates.push(PathBuf::from(format!("{}{ext}", joined.display())));
    }
    for ext in TS_EXTENSIONS {
        candidates.push(joined.join(format!("index{ext}")));
    }
    let resolved_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    for cand in candidates {
        if cand.is_file() {
            let canon = fs::canonicalize(&cand).unwrap_or(cand);
            if let Some(r) = rel_posix(&canon, &resolved_root) {
                return Some(r);
            }
        }
    }
    None
}

pub fn extract_ts_imports(file_path: &Path, repo_root: &Path) -> Vec<ImportEdge> {
    let Some(rel) = rel_posix(file_path, repo_root) else {
        return Vec::new();
    };
    let Ok(text) = fs::read_to_string(file_path) else {
        return Vec::new();
    };
    let cleaned = strip_c_comments(&text);
    let ts_re = Regex::new(
        r#"(?:import|export)\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)|require\(\s*['"]([^'"]+)['"]\s*\)"#,
    )
    .unwrap();

    let mut edges = Vec::new();
    for caps in ts_re.captures_iter(&cleaned) {
        let m = caps.get(0).unwrap();
        let specifier = caps
            .get(1)
            .or_else(|| caps.get(2))
            .or_else(|| caps.get(3))
            .map(|x| x.as_str())
            .unwrap_or("");
        if specifier.is_empty() {
            continue;
        }
        let line_no = cleaned[..m.start()].bytes().filter(|&b| b == b'\n').count() + 1;
        let resolved = resolve_ts_import(specifier, file_path, repo_root);
        edges.push(ImportEdge::new(&rel, line_no, specifier, resolved));
    }
    edges
}

fn strip_lean_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let (n, mut i, mut depth, mut in_str) = (chars.len(), 0usize, 0usize, false);
    let mut out = String::with_capacity(text.len());
    while i < n {
        let ch = chars[i];
        if depth > 0 {
            if ch == '/' && i + 1 < n && chars[i + 1] == '-' { depth += 1; i += 2; continue; }
            if ch == '-' && i + 1 < n && chars[i + 1] == '/' { depth -= 1; i += 2; continue; }
            if ch == '\n' { out.push('\n'); }
            i += 1;
            continue;
        }
        if in_str {
            out.push(ch);
            if ch == '\\' && i + 1 < n { out.push(chars[i + 1]); i += 2; continue; }
            if ch == '"' { in_str = false; }
            i += 1;
            continue;
        }
        if ch == '"' { in_str = true; out.push(ch); i += 1; continue; }
        if ch == '-' && i + 1 < n && chars[i + 1] == '-' {
            while i < n && chars[i] != '\n' { i += 1; }
            continue;
        }
        if ch == '/' && i + 1 < n && chars[i + 1] == '-' { depth = 1; i += 2; continue; }
        out.push(ch);
        i += 1;
    }
    out
}

fn resolve_lean_import(module: &str, file_path: &Path, repo_root: &Path) -> Option<String> {
    let mut rel_mod = module.split('.').filter(|s| !s.is_empty()).collect::<PathBuf>();
    rel_mod.set_extension("lean");
    let resolved_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut cur = file_path.parent();
    while let Some(dir) = cur {
        if dir.join("lakefile.toml").is_file() || dir.join("lakefile.lean").is_file() {
            roots.push(dir.to_path_buf());
        }
        if dir == repo_root || dir == resolved_root { break; }
        cur = dir.parent();
    }
    roots.extend([resolved_root.join("lean"), resolved_root.clone()]);
    for root in roots {
        let cand = root.join(&rel_mod);
        if cand.is_file() {
            let canon = fs::canonicalize(&cand).unwrap_or(cand);
            if let Some(r) = rel_posix(&canon, &resolved_root) { return Some(r); }
        }
    }
    None
}

/// Extract Lean 4 `import` statements, skipping `--` and nested `/- ... -/` comments.
pub fn extract_lean_imports(file_path: &Path, repo_root: &Path) -> Vec<ImportEdge> {
    let (Some(rel), Ok(text)) = (rel_posix(file_path, repo_root), fs::read_to_string(file_path)) else {
        return Vec::new();
    };
    let cleaned = strip_lean_comments(&text);
    let imp_re = Regex::new(
        r"^\s*(?:(?:public|private|meta)\s+)*import\s+(?:all\s+)?([A-Za-z_][A-Za-z0-9_'.]*)",
    )
    .unwrap();
    cleaned
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let module = imp_re.captures(line)?[1].to_string();
            let resolved = resolve_lean_import(&module, file_path, repo_root);
            Some(ImportEdge::new(&rel, idx + 1, module, resolved))
        })
        .collect()
}

/// Dispatch import extraction by file suffix.
pub fn extract_imports_for_file(file_path: &Path, repo_root: &Path, go_module: Option<&str>) -> Vec<ImportEdge> {
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| format!(".{}", s.to_lowercase()))
        .unwrap_or_default();
    match ext.as_str() {
        ".py" => extract_python_imports(file_path, repo_root),
        ".go" => extract_go_imports(file_path, repo_root, go_module),
        ".rs" => extract_rust_imports(file_path, repo_root),
        ".lean" => extract_lean_imports(file_path, repo_root),
        s if TS_EXTENSIONS.contains(&s) => extract_ts_imports(file_path, repo_root),
        _ => Vec::new(),
    }
}
