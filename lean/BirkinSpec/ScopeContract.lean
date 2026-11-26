/-
  BirkinSpec.ScopeContract — Formally verified path scope & write-disjointness invariants.

  Proves fail-closed properties for unit file boundaries (`fly-face` / `two-hand` / `9-ops`):
  1. Paths escaping checkout root (including via symlinks) are always rejected.
  2. `forbidden_paths` strictly dominates `allowed_paths` and `verification_output_paths`.
  3. `verification_output_paths` never grants editable source authority.
  4. Concurrent active mutating units on the same checkout must have disjoint write sets.
-/

namespace BirkinSpec

inductive PathAuthority where
  | sourceEdit
  | verificationOutput
  deriving DecidableEq, Repr

structure PathDecision where
  insideRoot          : Bool
  matchedAllowed      : Bool
  matchedForbidden    : Bool
  matchedVerifyOutput : Bool
  deriving DecidableEq, Repr

def pathAdmitted (auth : PathAuthority) (d : PathDecision) : Bool :=
  if !d.insideRoot || d.matchedForbidden then
    false
  else
    match auth with
    | .sourceEdit         => d.matchedAllowed
    | .verificationOutput => d.matchedAllowed || d.matchedVerifyOutput

def allPathsAdmitted (auth : PathAuthority) (ds : List PathDecision) : Bool :=
  ds.all (pathAdmitted auth)

def disjointWriteSets (writesA writesB : List String) : Bool :=
  writesA.all (fun p => !writesB.contains p)

def scopeAdmitted (auth : PathAuthority) (ds : List PathDecision)
    (myWrites otherActiveWrites : List String) : Bool :=
  allPathsAdmitted auth ds && disjointWriteSets myWrites otherActiveWrites

theorem pathAdmitted_outside_root_false (auth : PathAuthority) (d : PathDecision)
    (hout : d.insideRoot = false) :
    pathAdmitted auth d = false := by
  simp [pathAdmitted, hout]

theorem pathAdmitted_forbidden_dominates (auth : PathAuthority) (d : PathDecision)
    (hforb : d.matchedForbidden = true) :
    pathAdmitted auth d = false := by
  simp [pathAdmitted, hforb]

theorem pathAdmitted_verifyOutput_no_source_edit (d : PathDecision)
    (hnoallow : d.matchedAllowed = false) :
    pathAdmitted .sourceEdit d = false := by
  unfold pathAdmitted
  split
  · rfl
  · exact hnoallow

theorem disjointWriteSets_overlap_false {writesA writesB : List String} {p : String}
    (ha : p ∈ writesA) (hb : p ∈ writesB) :
    disjointWriteSets writesA writesB = false := by
  unfold disjointWriteSets
  cases h : writesA.all (fun x => !writesB.contains x) with
  | false => rfl
  | true =>
    have hp := List.all_eq_true.mp h p ha
    simp at hp
    exact False.elim (hp hb)

theorem scopeAdmitted_implies_all_in_scope {auth : PathAuthority} {ds : List PathDecision}
    {myWrites otherWrites : List String}
    (h : scopeAdmitted auth ds myWrites otherWrites = true) :
    (∀ d ∈ ds, pathAdmitted auth d = true) ∧ (∀ p ∈ myWrites, p ∉ otherWrites) := by
  unfold scopeAdmitted allPathsAdmitted disjointWriteSets at h
  have ⟨hpaths, hdisj⟩ := Bool.and_eq_true _ _ |>.mp h
  refine ⟨fun d hd => List.all_eq_true.mp hpaths d hd, fun p hp hmem => ?_⟩
  have hnot := List.all_eq_true.mp hdisj p hp
  simp at hnot
  exact hnot hmem

end BirkinSpec
