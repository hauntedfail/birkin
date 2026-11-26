/-
  BirkinSpec.StageAdmission — Formally verified lifecycle stage separation,
  nonzero test coverage, toolchain pin binding, and Sawyer Git finalization closure.

  Proves fail-closed properties (`two-hand` / `verification-loop` / `sawyer`):
  1. Zero discovered tests can never admit `verified` or any later stage.
  2. Partial test execution (`executedTests < discoveredTests`) fails closed.
  3. `committed` requires Sawyer exact staging, clean exclusion whitelist, and valid GPG signature when required.
  4. `pushed` requires `committed` plus `remoteHeadMatches`.
  5. `released` requires `ciPassed` plus explicit `releaseAuthorized`.
-/

namespace BirkinSpec

inductive LifecycleStage where
  | implemented
  | verified
  | reviewed
  | committed
  | pushed
  | ciPassed
  | released
  deriving DecidableEq, Repr

def LifecycleStage.rank : LifecycleStage → Nat
  | .implemented => 0
  | .verified    => 1
  | .reviewed    => 2
  | .committed   => 3
  | .pushed      => 4
  | .ciPassed    => 5
  | .released    => 6

structure StageEvidence where
  discoveredTests     : Nat
  executedTests       : Nat
  toolchainMatched    : Bool
  receiptChainOk      : Bool
  treeBoundOk         : Bool
  reviewPassed        : Bool
  sawyerStagedExact   : Bool
  sawyerExcludedClean : Bool
  gpgSignRequired     : Bool
  gpgSigValid         : Bool
  remoteHeadMatches   : Bool
  ciPassed            : Bool
  releaseAuthorized   : Bool
  deriving DecidableEq, Repr

def testsComplete (ev : StageEvidence) : Bool :=
  decide (0 < ev.discoveredTests ∧ ev.discoveredTests ≤ ev.executedTests)

def sawyerCommitValid (ev : StageEvidence) : Bool :=
  ev.sawyerStagedExact
  && ev.sawyerExcludedClean
  && (!ev.gpgSignRequired || ev.gpgSigValid)

def verifiedOk (ev : StageEvidence) : Bool :=
  ev.treeBoundOk && ev.receiptChainOk && ev.toolchainMatched && testsComplete ev

def reviewedOk (ev : StageEvidence) : Bool :=
  verifiedOk ev && ev.reviewPassed

def committedOk (ev : StageEvidence) : Bool :=
  reviewedOk ev && sawyerCommitValid ev

def pushedOk (ev : StageEvidence) : Bool :=
  committedOk ev && ev.remoteHeadMatches

def ciPassedOk (ev : StageEvidence) : Bool :=
  pushedOk ev && ev.ciPassed

def stageAdmitted : LifecycleStage → StageEvidence → Bool
  | .implemented, ev => ev.treeBoundOk
  | .verified, ev    => verifiedOk ev
  | .reviewed, ev    => reviewedOk ev
  | .committed, ev   => committedOk ev
  | .pushed, ev      => pushedOk ev
  | .ciPassed, ev    => ciPassedOk ev
  | .released, ev    => ciPassedOk ev && ev.releaseAuthorized

theorem stageAdmitted_zero_discovered_tests_false (ev : StageEvidence)
    (hz : ev.discoveredTests = 0) :
    stageAdmitted .verified ev = false := by
  simp [stageAdmitted, verifiedOk, testsComplete, hz]

theorem stageAdmitted_partial_tests_false (ev : StageEvidence)
    (hlt : ev.executedTests < ev.discoveredTests) :
    stageAdmitted .verified ev = false := by
  have hnot : ¬(0 < ev.discoveredTests ∧ ev.discoveredTests ≤ ev.executedTests) := by
    intro ⟨_, hle⟩
    exact Nat.not_le_of_gt hlt hle
  have ht : testsComplete ev = false := decide_eq_false hnot
  simp [stageAdmitted, verifiedOk, ht]

theorem stageAdmitted_committed_requires_reviewed (ev : StageEvidence)
    (h : stageAdmitted .committed ev = true) : stageAdmitted .reviewed ev = true :=
  (Bool.and_eq_true _ _ |>.mp h).1

theorem stageAdmitted_committed_requires_sawyer (ev : StageEvidence)
    (h : stageAdmitted .committed ev = true) :
    ev.sawyerStagedExact = true
    ∧ ev.sawyerExcludedClean = true
    ∧ (ev.gpgSignRequired = true → ev.gpgSigValid = true) := by
  unfold stageAdmitted committedOk sawyerCommitValid at h
  have hs := (Bool.and_eq_true _ _ |>.mp h).2
  have h1 := (Bool.and_eq_true _ _ |>.mp hs).1
  have hsig := (Bool.and_eq_true _ _ |>.mp hs).2
  have ⟨hexact, hclean⟩ := Bool.and_eq_true _ _ |>.mp h1
  refine ⟨hexact, hclean, fun hreq => ?_⟩
  simp [hreq] at hsig
  exact hsig

theorem stageAdmitted_pushed_requires_remote_match (ev : StageEvidence)
    (h : stageAdmitted .pushed ev = true) :
    ev.remoteHeadMatches = true := by
  unfold stageAdmitted pushedOk at h
  exact (Bool.and_eq_true _ _ |>.mp h).2

theorem stageAdmitted_released_requires_all (ev : StageEvidence)
    (h : stageAdmitted .released ev = true) :
    ev.ciPassed = true ∧ ev.releaseAuthorized = true ∧ ev.remoteHeadMatches = true := by
  unfold stageAdmitted ciPassedOk pushedOk at h
  have ⟨hci_stage, hrel⟩ := Bool.and_eq_true _ _ |>.mp h
  have ⟨hpush_stage, hci⟩ := Bool.and_eq_true _ _ |>.mp hci_stage
  have hrem := (Bool.and_eq_true _ _ |>.mp hpush_stage).2
  exact ⟨hci, hrel, hrem⟩

end BirkinSpec
