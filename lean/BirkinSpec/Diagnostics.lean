/-
  BirkinSpec.Diagnostics — Proved diagnostic evaluators for all five workflow contracts.

  Each evaluator returns both a boolean `admitted` decision and structured human-readable
  denial reasons, accompanied by machine-checked equivalence theorems proving:
    1. `(evalX ...).admitted = <provedPredicate> ...`
    2. Rejection never succeeds silently: `(evalX ...).admitted = false -> (evalX ...).reasons ≠ []`
-/

import BirkinSpec.PlanContract
import BirkinSpec.ScopeContract
import BirkinSpec.AuthorityContract
import BirkinSpec.StageAdmission
import BirkinSpec.ReviewClosure

namespace BirkinSpec

structure Verdict where
  admitted : Bool
  reasons  : List String
  deriving DecidableEq, Repr

private def finalizeVerdict (admitted : Bool) (reasons : List String) (fallback : String) : Verdict :=
  if admitted then
    { admitted := true, reasons := [] }
  else
    { admitted := false, reasons := if reasons.isEmpty then [fallback] else reasons }

theorem finalizeVerdict_admitted (a : Bool) (rs : List String) (fb : String) :
    (finalizeVerdict a rs fb).admitted = a := by
  cases a <;> rfl

theorem finalizeVerdict_rejected_nonempty (rs : List String) (fb : String) :
    (finalizeVerdict false rs fb).reasons ≠ [] := by
  unfold finalizeVerdict
  cases rs with
  | nil => simp
  | cons r rest => simp

/-! ## 1. Plan Contract Diagnostics -/

private def planOrderReasonsAux (seen : List String) : List PlanTask → List String
  | [] => []
  | t :: rest =>
    let dup := if seen.contains t.id then [s!"[PLAN_DUPLICATE_ID] duplicate task ID '{t.id}'"] else []
    let badDeps := t.dependsOn.filterMap fun d =>
      if seen.contains d then none
      else some s!"[PLAN_DAG_ORDER] task '{t.id}': dependency '{d}' must appear earlier in dependency order"
    dup ++ badDeps ++ planOrderReasonsAux (t.id :: seen) rest

private def planTaskReasons (tasks : List PlanTask) (questions : List BlockingQuestion)
    (t : PlanTask) : List String :=
  let r1 := if t.allowedPathsNonempty then [] else [s!"[PLAN_SCOPE_PATH] task '{t.id}': allowed_paths must be nonempty"]
  let r2 := if t.verificationNonempty then [] else [s!"[PLAN_VERIFICATION] task '{t.id}': verification must be nonempty"]
  let r3 :=
    if t.status == .done && !t.hasCompletionEvidence then
      [s!"[PLAN_DONE_EVIDENCE] task '{t.id}': done status requires nonempty completion_evidence"]
    else []
  let r4 :=
    if (t.status == .inProgress || t.status == .done) && !allPrereqsDone tasks t then
      [s!"[PLAN_PREREQ_UNMET] task '{t.id}': status '{reprStr t.status}' requires all dependencies to be done"]
    else []
  let r5 :=
    if (isQuestionBlocked questions t.id || hasBlockedPrereq tasks t)
        && !(t.status == .blocked || t.status == .superseded) then
      [s!"[PLAN_BLOCK_PROPAGATION] task '{t.id}': blocked dependency or blocking question requires blocked/superseded status"]
    else []
  r1 ++ r2 ++ r3 ++ r4 ++ r5

private def planQuestionReasons (tasks : List PlanTask) (questions : List BlockingQuestion) : List String :=
  questions.foldr (fun q acc =>
    let qr := q.blocks.filterMap fun tid =>
      match taskById tasks tid with
      | none => some s!"[PLAN_QUESTION_TARGET] question '{q.id}' references unknown task '{tid}'"
      | some t =>
        if t.status == .blocked then none
        else some s!"[PLAN_QUESTION_TARGET] question '{q.id}' blocks task '{tid}', which must have status 'blocked'"
    qr ++ acc) []

def evalPlan (tasks : List PlanTask) (questions : List BlockingQuestion) : Verdict :=
  let ok := planValid tasks questions
  let reasons :=
    (if tasks.isEmpty then ["[PLAN_TASKS_EMPTY] tasks must be a nonempty list"] else [])
    ++ planOrderReasonsAux [] tasks
    ++ (tasks.foldr (fun t acc => planTaskReasons tasks questions t ++ acc) [])
    ++ planQuestionReasons tasks questions
  finalizeVerdict ok reasons "[PLAN_KERNEL_CONTRACT] Plan failed BirkinSpec.planValid"

theorem evalPlan_admitted_eq (tasks : List PlanTask) (questions : List BlockingQuestion) :
    (evalPlan tasks questions).admitted = planValid tasks questions :=
  finalizeVerdict_admitted _ _ _

theorem evalPlan_rejected_nonempty {tasks : List PlanTask} {questions : List BlockingQuestion}
    (h : planValid tasks questions = false) :
    (evalPlan tasks questions).reasons ≠ [] := by
  unfold evalPlan
  rw [h]
  exact finalizeVerdict_rejected_nonempty _ _

def evalPlanDispatch (intent : PlanIntent) (tasks : List PlanTask)
    (questions : List BlockingQuestion) (tid : String) : Verdict :=
  let ok := canDispatchMutating intent tasks questions tid
  let intentReasons :=
    if intent == .implement then [] else ["Plan intent is 'plan-only', which forbids mutating dispatch"]
  let pv := evalPlan tasks questions
  let taskReasons :=
    match taskById tasks tid with
    | none => [s!"Task '{tid}' not found in plan"]
    | some t =>
      (if t.status == .ready then [] else [s!"Task '{tid}' has status '{reprStr t.status}', not 'ready'"])
      ++ (if isQuestionBlocked questions tid then [s!"Task '{tid}' is blocked by an open question"] else [])
      ++ (if hasBlockedPrereq tasks t then [s!"Task '{tid}' has a blocked dependency"] else [])
      ++ (if allPrereqsDone tasks t then [] else [s!"Task '{tid}' has unfinished dependencies"])
  finalizeVerdict ok (intentReasons ++ pv.reasons ++ taskReasons)
    s!"Task '{tid}' failed BirkinSpec.canDispatchMutating"

theorem evalPlanDispatch_admitted_eq (intent : PlanIntent) (tasks : List PlanTask)
    (questions : List BlockingQuestion) (tid : String) :
    (evalPlanDispatch intent tasks questions tid).admitted =
      canDispatchMutating intent tasks questions tid :=
  finalizeVerdict_admitted _ _ _

/-! ## 2. Scope Contract Diagnostics -/

def overlappingWritesList (myWrites otherWrites : List String) : List String :=
  myWrites.filter fun p => otherWrites.any fun q => writePathsOverlap p q

def evalScope (auth : PathAuthority) (ds : List PathDecision)
    (myWrites otherWrites : List String) : Verdict :=
  let ok := scopeAdmitted auth ds myWrites otherWrites
  let pathReasons := (ds.zipIdx).filterMap fun (d, idx) =>
    if pathAdmitted auth d then none
    else if !d.insideRoot then
      some s!"path[{idx}]: escapes checkout root or fails realpath containment"
    else if d.matchedForbidden then
      some s!"path[{idx}]: matches forbidden_paths"
    else
      some s!"path[{idx}]: outside allowed_paths for requested authority"
  let overlapReasons := (overlappingWritesList myWrites otherWrites).map fun p =>
    s!"write path '{p}' overlaps an active concurrent unit on the same checkout"
  finalizeVerdict ok (pathReasons ++ overlapReasons) "Scope failed BirkinSpec.scopeAdmitted"

theorem evalScope_admitted_eq (auth : PathAuthority) (ds : List PathDecision)
    (myWrites otherWrites : List String) :
    (evalScope auth ds myWrites otherWrites).admitted =
      scopeAdmitted auth ds myWrites otherWrites :=
  finalizeVerdict_admitted _ _ _

/-! ## 3. Authority Contract Diagnostics -/

def evalAuthority (req : DispatchRequest) : Verdict :=
  let ok := dispatchAdmitted req
  let r1 := if req.forbiddenModel then ["Model matches forbidden denylist pattern"] else []
  let r2 :=
    if tierWithinAuthority req then []
    else if req.requestedTier == .F then
      ["Tier F requires a write-capable role and explicit unit authorization"]
    else
      ["Requested tier exceeds role authority"]
  let r3 :=
    if refusalNoEscalation req then []
    else ["A refusal retry cannot escalate authority"]
  let r4 :=
    if decide (req.retriesAfterFirst ≤ maxRetriesAfterFirst) then []
    else ["Retry limit exceeded"]
  let r5 :=
    if reviewerIndependent req then []
    else ["Reviewer independence requires a distinct known model or runtime"]
  finalizeVerdict ok (r1 ++ r2 ++ r3 ++ r4 ++ r5) "Dispatch failed BirkinSpec.dispatchAdmitted"

theorem evalAuthority_admitted_eq (req : DispatchRequest) :
    (evalAuthority req).admitted = dispatchAdmitted req :=
  finalizeVerdict_admitted _ _ _

/-! ## 4. Stage & Sawyer Contract Diagnostics -/

def evalStage (stage : LifecycleStage) (ev : StageEvidence) : Verdict :=
  let ok := stageAdmitted stage ev
  let req (minRank : Nat) (cond : Bool) (msg : String) : List String :=
    if stage.rank ≥ minRank && !cond then [msg] else []
  let reasons :=
    req 0 ev.treeBoundOk "Working tree does not match verified tree digest"
    ++ req 1 ev.receiptChainOk "Receipt ledger chain verification failed"
    ++ req 1 ev.toolchainMatched "Toolchain pin manifest mismatch"
    ++ req 1 (decide (0 < ev.discoveredTests)) "Zero discovered tests cannot admit verified stage"
    ++ req 1 (decide (ev.discoveredTests ≤ ev.executedTests)) "Partial test execution (executed < discovered)"
    ++ req 2 ev.reviewPassed "Independent review evidence is missing or failed"
    ++ req 3 ev.sawyerStagedExact "Sawyer exact staging verification failed"
    ++ req 3 ev.sawyerExcludedClean "Sawyer exclusion whitelist verification failed"
    ++ req 3 (!ev.gpgSignRequired || ev.gpgSigValid) "Required GPG commit signature verification failed"
    ++ req 4 ev.remoteHeadMatches "Remote head does not match pushed commit"
    ++ req 5 ev.ciPassed "CI pass evidence is missing or failed"
    ++ req 6 ev.releaseAuthorized "Explicit release authorization evidence is missing"
  finalizeVerdict ok reasons "Stage failed BirkinSpec.stageAdmitted"

theorem evalStage_admitted_eq (stage : LifecycleStage) (ev : StageEvidence) :
    (evalStage stage ev).admitted = stageAdmitted stage ev :=
  finalizeVerdict_admitted _ _ _

/-! ## 5. Review Closure Diagnostics -/

private def duplicateKeyReasonsAux (seen : List String) : List CanonicalReviewItem → List String
  | [] => []
  | it :: rest =>
    let dup := if seen.contains it.itemKey then [s!"Duplicate canonical review key '{it.itemKey}'"] else []
    dup ++ duplicateKeyReasonsAux (it.itemKey :: seen) rest

def evalReviewClosure (requestReReview : Bool) (items : List CanonicalReviewItem) : Verdict :=
  let ok := if requestReReview then canRequestReReview items else reviewClosureValid items
  let dupReasons := duplicateKeyReasonsAux [] items
  let itemReasons := items.foldr (fun it acc =>
    let r1 := if it.classification == .unclassified then [s!"Unclassified review item '{it.itemKey}'"] else []
    let r2 :=
      if !it.replied then
        [s!"Review item '{it.itemKey}' requires a reply and resolved threads require its URL"]
      else []
    let r3 :=
      if it.classification == .mustFix && !it.fixVerified then
        [s!"Unverified fix for '{it.itemKey}'"]
      else []
    let r4 :=
      if requestReReview && it.classification == .needsClarification then
        [s!"Clarification required for '{it.itemKey}' before re-review"]
      else []
    r1 ++ r2 ++ r3 ++ r4 ++ acc) []
  finalizeVerdict ok (dupReasons ++ itemReasons) "Review state failed BirkinSpec.ReviewClosure"

theorem evalReviewClosure_admitted_eq (requestReReview : Bool) (items : List CanonicalReviewItem) :
    (evalReviewClosure requestReReview items).admitted =
      (if requestReReview then canRequestReReview items else reviewClosureValid items) :=
  finalizeVerdict_admitted _ _ _

end BirkinSpec
