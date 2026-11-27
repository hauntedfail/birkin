//! Admission for a single delegated unit and its independently supplied model policy.
//!
//! Rust extracts glob-denylist and identity facts only; all authority lattice, role-ceiling,
//! reviewer-independence, refusal non-escalation, and retry-bound verdicts are computed
//! directly by the Lean 4 decision kernel (`BirkinSpec.AuthorityContract`).

use crate::glob::fnmatch_ci;
use crate::lean_kernel::{eval_authority, KernelAuthorityRequest, KernelVerdict};
use crate::workflow_models::{AgentRole, ApprovalTier, DispatchManifest};

fn identity(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn differs(a: &Option<String>, b: &Option<String>) -> bool {
    matches!((identity(a), identity(b)), (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b))
}

fn role_wire(role: AgentRole) -> &'static str {
    match role {
        AgentRole::Scope => "scope",
        AgentRole::Review => "review",
        AgentRole::Research => "research",
        AgentRole::Docs => "docs",
        AgentRole::Investigate => "investigate",
        AgentRole::Implement => "implement",
        AgentRole::Finalize => "finalize",
    }
}

fn tier_wire(tier: ApprovalTier) -> &'static str {
    match tier {
        ApprovalTier::R => "R",
        ApprovalTier::W => "W",
        ApprovalTier::F => "F",
    }
}

/// Extract normalized authority facts for Lean 4 kernel evaluation and certification.
pub fn build_authority_kernel_request(
    req: &DispatchManifest,
    policy_denylist: &[String],
) -> Result<KernelAuthorityRequest, String> {
    let mut forbidden_model = false;
    for pattern in policy_denylist.iter().chain(&req.forbidden_model_patterns) {
        let model = identity(&req.model).ok_or("Model identity required by denylist")?;
        if fnmatch_ci(model, pattern) {
            forbidden_model = true;
            break;
        }
    }

    Ok(KernelAuthorityRequest {
        role: role_wire(req.role).into(),
        requested_tier: tier_wire(req.requested_tier).into(),
        explicit_f_auth: req.explicit_f_auth,
        is_refusal_retry: req.is_refusal_retry,
        prev_tier: tier_wire(req.prev_tier).into(),
        retries_after_first: req.retries_after_first,
        forbidden_model,
        same_impl_runtime: !differs(&req.runtime, &req.implementer_runtime),
        same_impl_model: !differs(&req.model, &req.implementer_model),
    })
}

/// Evaluate dispatch admission via the Lean 4 decision kernel, separating kernel/tool
/// errors (`Err`) from contract verdicts (`Ok(KernelVerdict)`).
pub fn verify_dispatch_checked(
    req: &DispatchManifest,
    policy_denylist: &[String],
) -> Result<(KernelAuthorityRequest, KernelVerdict), String> {
    let kernel_req = match build_authority_kernel_request(req, policy_denylist) {
        Ok(kreq) => kreq,
        Err(reason) => {
            // Missing model identity under a non-empty denylist is a contract violation;
            // still route through the Lean kernel with forbidden_model=true so the kernel
            // remains reachable and fail-closed.
            let kreq = KernelAuthorityRequest {
                role: role_wire(req.role).into(),
                requested_tier: tier_wire(req.requested_tier).into(),
                explicit_f_auth: req.explicit_f_auth,
                is_refusal_retry: req.is_refusal_retry,
                prev_tier: tier_wire(req.prev_tier).into(),
                retries_after_first: req.retries_after_first,
                forbidden_model: true,
                same_impl_runtime: !differs(&req.runtime, &req.implementer_runtime),
                same_impl_model: !differs(&req.model, &req.implementer_model),
            };
            let mut verdict = eval_authority(&kreq)?;
            verdict.admitted = false;
            verdict.reasons.insert(0, reason);
            return Ok((kreq, verdict));
        }
    };
    let verdict = eval_authority(&kernel_req)?;
    Ok((kernel_req, verdict))
}

pub fn verify_dispatch(req: &DispatchManifest, policy_denylist: &[String]) -> Result<(), String> {
    let (_, verdict) = verify_dispatch_checked(req, policy_denylist)?;
    if verdict.admitted {
        Ok(())
    } else {
        Err(verdict.reasons.join("; "))
    }
}
