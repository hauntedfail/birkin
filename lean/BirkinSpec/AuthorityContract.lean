/-
  BirkinSpec.AuthorityContract — Formally verified approval tier, role ceiling,
  reviewer independence, refusal non-escalation, and retry-bound invariants.

  Proves fail-closed properties for delegated worker dispatch (`9-ops` / `xo`):
  1. Tiers form a strict total order `R < W < F`.
  2. Forbidden models are always rejected regardless of role or tier.
  3. Tier `F` requires explicit per-unit authorization and a write-capable role.
  4. Read-only roles (`scope`, `review`, `research`, `docs`, `investigate`) reject tier `W`.
  5. Review role requires independence from the implementer (runtime or model differs).
  6. Refusal retries can never escalate approval tier above `prevTier`.
  7. Retries after the first attempt are bounded by `maxRetriesAfterFirst = 2`.
-/

namespace BirkinSpec

inductive ApprovalTier where
  | R
  | W
  | F
  deriving DecidableEq, Repr

namespace ApprovalTier

def rank : ApprovalTier → Nat
  | .R => 0
  | .W => 1
  | .F => 2

def le (a b : ApprovalTier) : Bool :=
  decide (a.rank ≤ b.rank)

theorem le_refl (a : ApprovalTier) : le a a = true := by
  cases a <;> decide

theorem le_trans {a b c : ApprovalTier} (hab : le a b = true) (hbc : le b c = true) :
    le a c = true := by
  cases a <;> cases b <;> cases c <;> first | rfl | contradiction

theorem le_antisymm {a b : ApprovalTier} (hab : le a b = true) (hba : le b a = true) :
    a = b := by
  cases a <;> cases b <;> first | rfl | contradiction

end ApprovalTier

inductive AgentRole where
  | scope
  | review
  | research
  | docs
  | investigate
  | implement
  | finalize
  deriving DecidableEq, Repr

def AgentRole.maxDefaultTier : AgentRole → ApprovalTier
  | .scope       => .R
  | .review      => .R
  | .research    => .R
  | .docs        => .R
  | .investigate => .R
  | .implement   => .W
  | .finalize    => .W

def maxRetriesAfterFirst : Nat := 2

structure DispatchRequest where
  role              : AgentRole
  requestedTier     : ApprovalTier
  explicitFAuth     : Bool
  isRefusalRetry    : Bool
  prevTier          : ApprovalTier
  retriesAfterFirst : Nat
  forbiddenModel    : Bool
  sameImplRuntime   : Bool
  sameImplModel     : Bool
  deriving DecidableEq, Repr

def tierWithinAuthority (req : DispatchRequest) : Bool :=
  if req.requestedTier == .F then
    req.explicitFAuth && ApprovalTier.le .W req.role.maxDefaultTier
  else
    ApprovalTier.le req.requestedTier req.role.maxDefaultTier

def refusalNoEscalation (req : DispatchRequest) : Bool :=
  if req.isRefusalRetry then
    ApprovalTier.le req.requestedTier req.prevTier
  else
    true

def reviewerIndependent (req : DispatchRequest) : Bool :=
  if req.role == .review then
    !(req.sameImplRuntime && req.sameImplModel)
  else
    true

def dispatchAdmitted (req : DispatchRequest) : Bool :=
  (!req.forbiddenModel)
  && tierWithinAuthority req
  && refusalNoEscalation req
  && reviewerIndependent req
  && decide (req.retriesAfterFirst ≤ maxRetriesAfterFirst)

theorem dispatchAdmitted_forbiddenModel_false (req : DispatchRequest)
    (h : req.forbiddenModel = true) :
    dispatchAdmitted req = false := by
  simp [dispatchAdmitted, h]

theorem dispatchAdmitted_F_requires_explicit (req : DispatchRequest)
    (hf : req.requestedTier = .F) (hno : req.explicitFAuth = false) :
    dispatchAdmitted req = false := by
  simp [dispatchAdmitted, tierWithinAuthority, hf, hno]

theorem dispatchAdmitted_readonly_role_rejects_W (req : DispatchRequest)
    (hro : req.role.maxDefaultTier = .R) (hw : req.requestedTier = .W) :
    dispatchAdmitted req = false := by
  simp [dispatchAdmitted, tierWithinAuthority, hro, hw, ApprovalTier.le, ApprovalTier.rank]

theorem dispatchAdmitted_readonly_role_requires_R (req : DispatchRequest)
    (hro : req.role.maxDefaultTier = .R) (h : dispatchAdmitted req = true) :
    req.requestedTier = .R := by
  cases ht : req.requestedTier with
  | R => rfl
  | W =>
    simp [dispatchAdmitted, tierWithinAuthority, hro, ht, ApprovalTier.le, ApprovalTier.rank] at h
  | F =>
    simp [dispatchAdmitted, tierWithinAuthority, hro, ht, ApprovalTier.le, ApprovalTier.rank] at h

theorem dispatchAdmitted_review_requires_independence (req : DispatchRequest)
    (hr : req.role = .review) (hsr : req.sameImplRuntime = true) (hsm : req.sameImplModel = true) :
    dispatchAdmitted req = false := by
  simp [dispatchAdmitted, reviewerIndependent, hr, hsr, hsm]

theorem dispatchAdmitted_refusal_no_escalation (req : DispatchRequest)
    (href : req.isRefusalRetry = true)
    (hesc : req.prevTier.rank < req.requestedTier.rank) :
    dispatchAdmitted req = false := by
  have hle : ApprovalTier.le req.requestedTier req.prevTier = false := by
    unfold ApprovalTier.le
    exact decide_eq_false (Nat.not_le_of_gt hesc)
  simp [dispatchAdmitted, refusalNoEscalation, href, hle]

theorem dispatchAdmitted_retry_bounded (req : DispatchRequest)
    (hgt : maxRetriesAfterFirst < req.retriesAfterFirst) :
    dispatchAdmitted req = false := by
  have hle : decide (req.retriesAfterFirst ≤ maxRetriesAfterFirst) = false :=
    decide_eq_false (Nat.not_le_of_gt hgt)
  simp [dispatchAdmitted, hle]

end BirkinSpec
