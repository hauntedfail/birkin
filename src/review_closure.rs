//! Closure of canonical review items before resolving threads or requesting re-review.
//!
//! Rust validates reply URL syntax and non-empty item keys; all uniqueness, classification,
//! reply/resolution, fix-verification, and re-review closure verdicts are computed directly
//! by the Lean 4 decision kernel (`BirkinSpec.ReviewClosure`).

use crate::lean_kernel::{
    eval_review_closure, KernelReviewClosureRequest, KernelReviewItem, KernelVerdict,
};
use crate::workflow_models::{ReviewClassification, ReviewStateDocument};

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

fn classification_wire(c: ReviewClassification) -> &'static str {
    match c {
        ReviewClassification::Unclassified => "unclassified",
        ReviewClassification::MustFix => "must_fix",
        ReviewClassification::AlreadyFixed => "already_fixed",
        ReviewClassification::NotValid => "not_valid",
        ReviewClassification::OutOfScope => "out_of_scope",
        ReviewClassification::NeedsClarification => "needs_clarification",
    }
}

/// Extract normalized review-closure facts for Lean 4 kernel evaluation and certification.
pub fn build_review_closure_kernel_request(
    state: &ReviewStateDocument,
) -> (KernelReviewClosureRequest, Vec<String>) {
    let mut syntax_errors = Vec::new();
    let mut items = Vec::with_capacity(state.canonical_review_items.len());
    for item in &state.canonical_review_items {
        let key = item.item_key.trim().to_string();
        if key.is_empty() {
            syntax_errors.push("Missing canonical review key ''".to_string());
        }
        // Resolved threads require a valid HTTP(S) reply URL in addition to replied=true.
        let effective_replied =
            item.replied && (!item.resolved || has_reply_url(item.reply_url.as_deref()));
        items.push(KernelReviewItem {
            item_key: key,
            classification: classification_wire(item.classification).into(),
            replied: effective_replied,
            resolved: item.resolved,
            fix_verified: item.fix_verified,
        });
    }
    (
        KernelReviewClosureRequest {
            request_re_review: state.request_re_review,
            items,
        },
        syntax_errors,
    )
}

/// Evaluate review closure via the Lean 4 decision kernel, separating kernel/tool
/// errors (`Err`) from contract verdicts (`Ok((request, verdict))`).
pub fn verify_review_closure_checked(
    state: &ReviewStateDocument,
) -> Result<(KernelReviewClosureRequest, KernelVerdict), String> {
    let (kreq, syntax_errors) = build_review_closure_kernel_request(state);
    let mut verdict = eval_review_closure(&kreq)?;
    if !syntax_errors.is_empty() {
        verdict.admitted = false;
        let mut combined = syntax_errors;
        combined.extend(verdict.reasons);
        verdict.reasons = combined;
    }
    Ok((kreq, verdict))
}

pub fn verify_review_closure(state: &ReviewStateDocument) -> Result<(), String> {
    let (_, verdict) = verify_review_closure_checked(state)?;
    if verdict.admitted {
        Ok(())
    } else {
        Err(verdict.reasons.join("; "))
    }
}
