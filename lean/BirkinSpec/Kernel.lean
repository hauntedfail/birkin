/-
  BirkinSpec.Kernel — Production Lean 4 decision kernel executable (`birkin-kernel`).

  Accepts a single RFC 8259 JSON request object on stdin and writes a single JSON response
  object to stdout. Every contract verdict is computed directly by the formally proved
  `BirkinSpec` evaluators with zero hand-written Rust mirrors.
-/

import BirkinSpec

open BirkinSpec

namespace BirkinSpec.Kernel

def kernelVersion : String := "0.5.0"
def contractVersion : Nat := 1

private def reqField (obj : JVal) (key : String) : Except String JVal :=
  match obj.getField? key with
  | some v => .ok v
  | none => .error s!"missing required field '{key}'"

private def reqStr (obj : JVal) (key : String) : Except String String := do
  let v ← reqField obj key
  match v.asStr? with
  | some s => .ok s
  | none => .error s!"field '{key}' must be a string"

private def reqBool (obj : JVal) (key : String) : Except String Bool := do
  let v ← reqField obj key
  match v.asBool? with
  | some b => .ok b
  | none => .error s!"field '{key}' must be a boolean"

private def reqNat (obj : JVal) (key : String) : Except String Nat := do
  let v ← reqField obj key
  match v.asNat? with
  | some n => .ok n
  | none => .error s!"field '{key}' must be a non-negative integer"

private def reqArr (obj : JVal) (key : String) : Except String (List JVal) := do
  let v ← reqField obj key
  match v.asArr? with
  | some xs => .ok xs
  | none => .error s!"field '{key}' must be an array"

private def reqStrList (obj : JVal) (key : String) : Except String (List String) := do
  let v ← reqField obj key
  match v.asStrList? with
  | some xs => .ok xs
  | none => .error s!"field '{key}' must be an array of strings"

private def decodePlanIntent : String → Except String PlanIntent
  | "plan-only" => .ok .planOnly
  | "implement" => .ok .implement
  | other       => .error s!"invalid plan intent '{other}'"

private def decodeTaskStatus : String → Except String TaskStatus
  | "ready"       => .ok .ready
  | "blocked"     => .ok .blocked
  | "in_progress" => .ok .inProgress
  | "done"        => .ok .done
  | "superseded"  => .ok .superseded
  | other         => .error s!"invalid task status '{other}'"

private def decodePlanTask (v : JVal) : Except String PlanTask := do
  let id ← reqStr v "id"
  let statusS ← reqStr v "status"
  let status ← decodeTaskStatus statusS
  let deps ← reqStrList v "depends_on"
  let ev ← reqBool v "has_completion_evidence"
  let allow ← reqBool v "allowed_paths_nonempty"
  let verif ← reqBool v "verification_nonempty"
  pure { id, status, dependsOn := deps, hasCompletionEvidence := ev,
         allowedPathsNonempty := allow, verificationNonempty := verif }

private def decodeBlockingQuestion (v : JVal) : Except String BlockingQuestion := do
  let id ← reqStr v "id"
  let blocks ← reqStrList v "blocks"
  pure { id, blocks }

private def decodePathAuthority : String → Except String PathAuthority
  | "source" | "source_edit" => .ok .sourceEdit
  | "verification_output"    => .ok .verificationOutput
  | other                    => .error s!"invalid path authority '{other}'"

private def decodePathDecision (v : JVal) : Except String PathDecision := do
  let insideRoot ← reqBool v "inside_root"
  let matchedAllowed ← reqBool v "matched_allowed"
  let matchedForbidden ← reqBool v "matched_forbidden"
  let matchedVerifyOutput ← reqBool v "matched_verify_output"
  pure { insideRoot, matchedAllowed, matchedForbidden, matchedVerifyOutput }

private def decodeTier : String → Except String ApprovalTier
  | "R" => .ok .R
  | "W" => .ok .W
  | "F" => .ok .F
  | other => .error s!"invalid approval tier '{other}'"

private def decodeRole : String → Except String AgentRole
  | "scope"       => .ok .scope
  | "review"      => .ok .review
  | "research"    => .ok .research
  | "docs"        => .ok .docs
  | "investigate" => .ok .investigate
  | "implement"   => .ok .implement
  | "finalize"    => .ok .finalize
  | other         => .error s!"invalid agent role '{other}'"

private def decodeStage : String → Except String LifecycleStage
  | "implemented" => .ok .implemented
  | "verified"    => .ok .verified
  | "reviewed"    => .ok .reviewed
  | "committed"   => .ok .committed
  | "pushed"      => .ok .pushed
  | "ci_passed"   => .ok .ciPassed
  | "released"    => .ok .released
  | other         => .error s!"invalid lifecycle stage '{other}'"

private def decodeReviewClassification : String → Except String ReviewClassification
  | "unclassified"        => .ok .unclassified
  | "must_fix"            => .ok .mustFix
  | "already_fixed"       => .ok .alreadyFixed
  | "not_valid"           => .ok .notValid
  | "out_of_scope"        => .ok .outOfScope
  | "needs_clarification" => .ok .needsClarification
  | other                 => .error s!"invalid review classification '{other}'"

private def decodeReviewItem (v : JVal) : Except String CanonicalReviewItem := do
  let itemKey ← reqStr v "item_key"
  let clsS ← reqStr v "classification"
  let classification ← decodeReviewClassification clsS
  let replied ← reqBool v "replied"
  let resolved ← reqBool v "resolved"
  let fixVerified ← reqBool v "fix_verified"
  pure { itemKey, classification, replied, resolved, fixVerified }

private def verdictJson (verdict : Verdict) (extra : List (String × JVal) := []) : JVal :=
  .obj ([
    ("ok", .bool true),
    ("kernel", .str "birkin-kernel"),
    ("kernel_version", .str kernelVersion),
    ("contract_version", .nat contractVersion),
    ("admitted", .bool verdict.admitted),
    ("reasons", .arr (verdict.reasons.map JVal.str))
  ] ++ extra)

def handleRequest (req : JVal) : Except String JVal := do
  let op ← reqStr req "op"
  match op with
  | "info" =>
    pure (.obj [
      ("ok", .bool true),
      ("kernel", .str "birkin-kernel"),
      ("kernel_version", .str kernelVersion),
      ("contract_version", .nat contractVersion)
    ])
  | "plan_valid" =>
    let taskVals ← reqArr req "tasks"
    let qVals ← reqArr req "questions"
    let tasks ← taskVals.mapM decodePlanTask
    let questions ← qVals.mapM decodeBlockingQuestion
    let v := evalPlan tasks questions
    let ready := (tasks.filter (fun t => t.status == .ready)).map (fun t => JVal.str t.id)
    let blocked := (tasks.filter (fun t => t.status == .blocked)).map (fun t => JVal.str t.id)
    let done := (tasks.filter (fun t => t.status == .done)).map (fun t => JVal.str t.id)
    pure (verdictJson v [
      ("ready_tasks", .arr ready),
      ("blocked_tasks", .arr blocked),
      ("done_tasks", .arr done)
    ])
  | "plan_dispatch" =>
    let intentS ← reqStr req "intent"
    let intent ← decodePlanIntent intentS
    let tid ← reqStr req "task_id"
    let taskVals ← reqArr req "tasks"
    let qVals ← reqArr req "questions"
    let tasks ← taskVals.mapM decodePlanTask
    let questions ← qVals.mapM decodeBlockingQuestion
    pure (verdictJson (evalPlanDispatch intent tasks questions tid))
  | "scope_admit" =>
    let authS ← reqStr req "authority"
    let auth ← decodePathAuthority authS
    let decVals ← reqArr req "decisions"
    let decs ← decVals.mapM decodePathDecision
    let myWrites ← reqStrList req "my_writes"
    let otherWrites ← reqStrList req "other_active_writes"
    let v := evalScope auth decs myWrites otherWrites
    let perPath := decs.map (fun d => JVal.bool (pathAdmitted auth d))
    let overlaps := (overlappingWritesList myWrites otherWrites).map JVal.str
    pure (verdictJson v [
      ("path_admitted", .arr perPath),
      ("overlapping_writes", .arr overlaps)
    ])
  | "authority_admit" =>
    let role ← decodeRole (← reqStr req "role")
    let requestedTier ← decodeTier (← reqStr req "requested_tier")
    let explicitFAuth ← reqBool req "explicit_f_auth"
    let isRefusalRetry ← reqBool req "is_refusal_retry"
    let prevTier ← decodeTier (← reqStr req "prev_tier")
    let retriesAfterFirst ← reqNat req "retries_after_first"
    let forbiddenModel ← reqBool req "forbidden_model"
    let sameImplRuntime ← reqBool req "same_impl_runtime"
    let sameImplModel ← reqBool req "same_impl_model"
    let dreq : DispatchRequest := {
      role, requestedTier, explicitFAuth, isRefusalRetry, prevTier,
      retriesAfterFirst, forbiddenModel, sameImplRuntime, sameImplModel
    }
    pure (verdictJson (evalAuthority dreq))
  | "stage_admit" =>
    let stage ← decodeStage (← reqStr req "stage")
    let ev : StageEvidence := {
      discoveredTests := ← reqNat req "discovered_tests",
      executedTests := ← reqNat req "executed_tests",
      toolchainMatched := ← reqBool req "toolchain_matched",
      receiptChainOk := ← reqBool req "receipt_chain_ok",
      treeBoundOk := ← reqBool req "tree_bound_ok",
      reviewPassed := ← reqBool req "review_passed",
      sawyerStagedExact := ← reqBool req "sawyer_staged_exact",
      sawyerExcludedClean := ← reqBool req "sawyer_excluded_clean",
      gpgSignRequired := ← reqBool req "gpg_sign_required",
      gpgSigValid := ← reqBool req "gpg_sig_valid",
      remoteHeadMatches := ← reqBool req "remote_head_matches",
      ciPassed := ← reqBool req "ci_passed",
      releaseAuthorized := ← reqBool req "release_authorized"
    }
    pure (verdictJson (evalStage stage ev))
  | "review_closure" =>
    let requestReReview ← reqBool req "request_re_review"
    let itemVals ← reqArr req "items"
    let items ← itemVals.mapM decodeReviewItem
    pure (verdictJson (evalReviewClosure requestReReview items))
  | other =>
    .error s!"unknown kernel operation '{other}'"

end BirkinSpec.Kernel

def evalSingleJson (raw : String) : (Bool × String) :=
  match BirkinSpec.JVal.parse raw with
  | .error err =>
    (false, (BirkinSpec.JVal.obj [("ok", .bool false), ("error", .str err)]).encode)
  | .ok req =>
    match BirkinSpec.Kernel.handleRequest req with
    | .error err =>
      (false, (BirkinSpec.JVal.obj [("ok", .bool false), ("error", .str err)]).encode)
    | .ok resp =>
      (true, resp.encode)

partial def serveLoop (stdin stdout : IO.FS.Stream) : IO UInt32 := do
  let line ← stdin.getLine
  if line.isEmpty then
    return 0
  let trimmed := line.trimAscii.toString
  if !trimmed.isEmpty then
    let (_, encoded) := evalSingleJson trimmed
    stdout.putStrLn encoded
    stdout.flush
  serveLoop stdin stdout

def main (args : List String) : IO UInt32 := do
  if args == ["--version"] then
    IO.println s!"birkin-kernel {BirkinSpec.Kernel.kernelVersion} contract_version={BirkinSpec.Kernel.contractVersion}"
    return 0
  if args == ["--serve"] then
    let stdin ← IO.getStdin
    let stdout ← IO.getStdout
    return (← serveLoop stdin stdout)
  let stdin ← IO.getStdin
  let raw ← stdin.readToEnd
  let (ok, encoded) := evalSingleJson raw
  IO.println encoded
  return if ok then 0 else 2
