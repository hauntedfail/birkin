//! Deterministic POSIX glob and fnmatch utilities supporting recursive `**` segments.

use regex::Regex;

/// Match a single string against an fnmatch-style wildcard pattern (`*`, `?`, `[...]`).
pub fn fnmatch(text: &str, pattern: &str) -> bool {
    let mut regex_str = String::from("^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => regex_str.push_str(".*"),
            '?' => regex_str.push('.'),
            '[' => {
                if let Some(end) = chars[i + 1..].iter().position(|&c| c == ']') {
                    let inner: String = chars[i + 1..i + 1 + end].iter().collect();
                    if let Some(rest) = inner.strip_prefix('!') {
                        regex_str.push_str("[^");
                        regex_str.push_str(&escape_char_class(rest));
                        regex_str.push(']');
                    } else {
                        regex_str.push('[');
                        regex_str.push_str(&escape_char_class(&inner));
                        regex_str.push(']');
                    }
                    i += end + 2;
                    continue;
                } else {
                    regex_str.push_str("\\[");
                }
            }
            c => regex_str.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    regex_str.push('$');
    Regex::new(&regex_str)
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

/// Case-insensitive fnmatch helper used for policy pattern matching.
pub fn fnmatch_ci(text: &str, pattern: &str) -> bool {
    fnmatch(&text.to_lowercase(), &pattern.to_lowercase())
}

/// Match a repo-relative POSIX path against a glob supporting `**` recursive segments.
pub fn match_glob(rel_posix: &str, pattern: &str) -> bool {
    let pat = pattern.trim().trim_start_matches("./");
    if pat.is_empty() {
        return false;
    }
    if !pat.contains("**") {
        return fnmatch(rel_posix, pat);
    }
    let bytes = pat.as_bytes();
    let mut regex_parts = String::from("^");
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        if pat[i..].starts_with("**/") {
            regex_parts.push_str("(?:.*/)?");
            i += 3;
        } else if pat[i..].starts_with("**") {
            regex_parts.push_str(".*");
            i += 2;
        } else {
            let ch = pat[i..].chars().next().unwrap();
            match ch {
                '*' => regex_parts.push_str("[^/]*"),
                '?' => regex_parts.push_str("[^/]"),
                c => regex_parts.push_str(&regex::escape(&c.to_string())),
            }
            i += ch.len_utf8();
        }
    }
    regex_parts.push('$');
    Regex::new(&regex_parts)
        .map(|re| re.is_match(rel_posix))
        .unwrap_or(false)
}

/// Return true if `rel_posix` matches any glob in `patterns`.
pub fn matches_any(rel_posix: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pat| match_glob(rel_posix, pat))
}

fn escape_char_class(inner: &str) -> String {
    let mut out = String::new();
    for ch in inner.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ']' => out.push_str("\\]"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_recursive() {
        assert!(match_glob("src/birkin/cli.rs", "src/**/*.rs"));
        assert!(match_glob("src/cli.rs", "src/**/*.rs"));
        assert!(!match_glob("tests/cli.rs", "src/**/*.rs"));
        assert!(match_glob(".git/HEAD", ".git/**"));
        assert!(fnmatch_ci("anthropic/claude-opus-4", "*opus*"));
    }
}
