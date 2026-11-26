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

/-- The oracle receives resolved checkout-relative paths. A final slash may mark a directory. -/
def writeComponents (p : String) : List String :=
  (p.dropEndWhile '/').toString.splitOn "/"

def writePathsOverlap (p q : String) : Bool :=
  (writeComponents p).isPrefixOf (writeComponents q) ||
    (writeComponents q).isPrefixOf (writeComponents p)

def disjointWriteSets (writesA writesB : List String) : Bool :=
  writesA.all fun p => writesB.all fun q => !writePathsOverlap p q

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

theorem disjointWriteSets_conflict_false {writesA writesB : List String} {p q : String}
    (ha : p ∈ writesA) (hb : q ∈ writesB) (hconflict : writePathsOverlap p q = true) :
    disjointWriteSets writesA writesB = false := by
  apply Bool.eq_false_iff.mpr
  intro h
  have hpair := List.all_eq_true.mp (List.all_eq_true.mp h p ha) q hb
  simp [hconflict] at hpair

theorem disjointWriteSets_overlap_false {writesA writesB : List String} {p : String}
    (ha : p ∈ writesA) (hb : p ∈ writesB) :
    disjointWriteSets writesA writesB = false := by
  apply disjointWriteSets_conflict_false ha hb
  simp [writePathsOverlap, List.isPrefixOf_iff_prefix]

theorem scopeAdmitted_implies_all_in_scope {auth : PathAuthority} {ds : List PathDecision}
    {myWrites otherWrites : List String}
    (h : scopeAdmitted auth ds myWrites otherWrites = true) :
    (∀ d ∈ ds, pathAdmitted auth d = true) ∧
    (∀ p ∈ myWrites, ∀ q ∈ otherWrites, writePathsOverlap p q = false) := by
  obtain ⟨hpaths, hdisj⟩ := Bool.and_eq_true_iff.mp h
  refine ⟨List.all_eq_true.mp hpaths, fun p hp q hq => ?_⟩
  exact (Bool.not_eq_true' _).mp (List.all_eq_true.mp (List.all_eq_true.mp hdisj p hp) q hq)

end BirkinSpec
