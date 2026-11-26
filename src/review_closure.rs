//! Closure of canonical review items before resolving threads or requesting re-review.

use crate::workflow_models::{ReviewClassification, ReviewStateDocument};
use std::collections::HashSet;

fn has_reply_url(url: Option<&str>) -> bool {
    let Some(url) = url else { return false };
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !host.is_empty() && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

pub fn verify_review_closure(state: &ReviewStateDocument) -> Result<(), String> {
    let mut seen = HashSet::new();
    for item in &state.canonical_review_items {
        let key = item.item_key.trim();
        if key.is_empty() || !seen.insert(key) {
            return Err(format!("Missing or duplicate canonical review key '{key}'"));
        }
        if item.classification == ReviewClassification::Unclassified {
            return Err(format!("Unclassified review item {key}"));
        }
        if !item.replied || (item.resolved && !has_reply_url(item.reply_url.as_deref())) {
            return Err(format!(
                "Review item {key} requires a reply and resolved threads require its URL"
            ));
        }
        if item.classification == ReviewClassification::MustFix && !item.fix_verified {
            return Err(format!("Unverified fix for {key}"));
        }
        if state.request_re_review
            && item.classification == ReviewClassification::NeedsClarification
        {
            return Err(format!("Clarification required for {key} before re-review"));
        }
    }
    Ok(())
}
