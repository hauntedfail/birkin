/-
  BirkinSpec.Policy — Formally verified fail-closed Hermes runtime policy invariants.

  Proves:
  1. Forbidden denylist ALWAYS dominates the allowlist (`fallbackAllowed_forbidden_rejected`).
  2. Unapproved fallback entries are rejected (`fallbackAllowed_unapproved_rejected`).
  3. Compression ratio invariants enforce `thresholdMin ≤ threshold ≤ thresholdMax`
     and `0 < targetRatio < threshold` when enabled.
-/

namespace BirkinSpec

/-- Fail-closed fallback decision: forbidden patterns dominate even explicit allowlist entries. -/
def fallbackAllowed (isForbidden inAllowlist : Bool) : Bool :=
  (!isForbidden) && inAllowlist

/-- Compression parameters represented in basis points (10000 = 1.0) for exact arithmetic. -/
structure CompressionBounds where
  thresholdMinBp : Nat
  thresholdMaxBp : Nat
  requireTargetLt : Bool
  deriving DecidableEq, Repr

def compressionValid (bounds : CompressionBounds) (thresholdBp targetRatioBp : Nat) : Bool :=
  let thOk := decide (bounds.thresholdMinBp ≤ thresholdBp ∧ thresholdBp ≤ bounds.thresholdMaxBp)
  let ratioOk :=
    if bounds.requireTargetLt then
      decide (0 < targetRatioBp ∧ targetRatioBp < thresholdBp)
    else
      true
  thOk && ratioOk

theorem fallbackAllowed_forbidden_rejected (inAllowlist : Bool) :
    fallbackAllowed true inAllowlist = false := by
  simp [fallbackAllowed]

theorem fallbackAllowed_unapproved_rejected (isForbidden : Bool) :
    fallbackAllowed isForbidden false = false := by
  cases isForbidden <;> rfl

theorem fallbackAllowed_iff (isForbidden inAllowlist : Bool) :
    fallbackAllowed isForbidden inAllowlist = true ↔
      isForbidden = false ∧ inAllowlist = true := by
  cases isForbidden <;> cases inAllowlist <;> decide

theorem compressionValid_threshold_bounds
    {bounds : CompressionBounds} {th tr : Nat}
    (h : compressionValid bounds th tr = true) :
    bounds.thresholdMinBp ≤ th ∧ th ≤ bounds.thresholdMaxBp := by
  unfold compressionValid at h
  have h1 := (Bool.and_eq_true _ _ |>.mp h).1
  exact of_decide_eq_true h1

theorem compressionValid_target_lt
    {bounds : CompressionBounds} {th tr : Nat}
    (hreq : bounds.requireTargetLt = true)
    (h : compressionValid bounds th tr = true) :
    0 < tr ∧ tr < th := by
  unfold compressionValid at h
  have h2 := (Bool.and_eq_true _ _ |>.mp h).2
  simp [hreq] at h2
  exact h2

end BirkinSpec
