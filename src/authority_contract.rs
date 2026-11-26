//! Admission for a single delegated unit and its independently supplied model policy.

use crate::glob::fnmatch_ci;
use crate::workflow_models::{AgentRole, ApprovalTier, DispatchManifest};

fn identity(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn differs(a: &Option<String>, b: &Option<String>) -> bool {
    matches!((identity(a), identity(b)), (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b))
}

pub fn verify_dispatch(req: &DispatchManifest, policy_denylist: &[String]) -> Result<(), String> {
    for pattern in policy_denylist.iter().chain(&req.forbidden_model_patterns) {
        let model = identity(&req.model).ok_or("Model identity required by denylist")?;
        if fnmatch_ci(model, pattern) {
            return Err(format!("Model {model} matches forbidden pattern {pattern}"));
        }
    }
    let ceiling = req.role.max_default_tier();
    if req.requested_tier == ApprovalTier::F {
        if !req.explicit_f_auth || ceiling == ApprovalTier::R {
            return Err(
                "Tier F requires a write-capable role and explicit unit authorization".into(),
            );
        }
    } else if req.requested_tier.rank() > ceiling.rank() {
        return Err("Requested tier exceeds role authority".into());
    }
    if req.is_refusal_retry && req.requested_tier.rank() > req.prev_tier.rank() {
        return Err("A refusal retry cannot escalate authority".into());
    }
    if req.retries_after_first > 2 {
        return Err("Retry limit exceeded".into());
    }
    if req.role == AgentRole::Review
        && !(differs(&req.runtime, &req.implementer_runtime)
            || differs(&req.model, &req.implementer_model))
    {
        return Err("Reviewer independence requires a distinct known model or runtime".into());
    }
    Ok(())
}
