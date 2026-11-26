/-
  BirkinSpec.Oracle — Executable Lean 4 reference oracle for differential testing against Rust.

  Reads line-oriented queries on stdin and writes exact Lean-verified verdicts to stdout:
    combine <n1> <n2> ...                                             -> combined exit code nat
    layer_edge <src> <dst>                                            -> true | false
    fallback <forb:0|1> <allow:0|1>                                   -> true | false
    compression <min> <max> <reqLt:0|1> <th> <tr_bp>                  -> true | false
    receipt_chain [entry1 entry2 ...]                                 -> true | false
    receipt_admission <reqs> <head> <tree> <spec> <clean> <dirty> [e] -> true | false
    plan_valid <tasks_semi> <questions_semi>                          -> true | false
    plan_dispatch <intent> <tid> <tasks_semi> <questions_semi>        -> true | false
    scope_admit <auth> <decisions_semi> <my_pipe> <other_pipe>        -> true | false
    authority_admit <role> <tier> <expF> <ref> <prev> <ret> <fm> <sr> <sm> -> true | false
    stage_admit <stage> <disc> <exec> <tc> <ch> <tr> <rv> <se> <ec> <gr> <gv> <rm> <ci> <ra> -> true | false
    review_closure <mode:valid|rereview> <items_semi>                 -> true | false
-/

import BirkinSpec

open BirkinSpec

def parseBool01 (s : String) : Bool :=
  s == "1" || s == "true"

def parseOptStr (s : String) : Option String :=
  if s == "-" then none else some s

def parsePipeList (s : String) : List String :=
  if s == "-" || s.isEmpty then [] else (s.splitOn "|").filter (fun x => !x.isEmpty)

def parseSemiList (s : String) : List String :=
  if s == "-" || s.isEmpty then [] else (s.splitOn ";").filter (fun x => !x.isEmpty)

/-- Decode a compact 10-field comma-separated ReceiptEntry:
    corrupt,command,outcomePass,exitCode,gitHead,treeDigest,specSha,prevHash,actualHash,computedHash -/
def parseReceiptEntry (tok : String) : Option ReceiptEntry :=
  match tok.splitOn "," with
  | [corruptS, cmd, passS, exitS, headS, treeS, specSha, prevH, actH, compH] =>
    match exitS.toNat? with
    | some exitCode =>
      some
        { corrupt := parseBool01 corruptS
        , command := cmd
        , outcomePass := parseBool01 passS
        , exitCode := exitCode
        , gitHead := parseOptStr headS
        , treeDigest := parseOptStr treeS
        , specSha256 := specSha
        , prevHash := prevH
        , actualHash := actH
        , computedHash := compH
        }
    | none => none
  | _ => none

def parsePlanIntent : String → Option PlanIntent
  | "plan-only" => some .planOnly
  | "implement" => some .implement
  | _           => none

def parseTaskStatus : String → Option TaskStatus
  | "ready"       => some .ready
  | "blocked"     => some .blocked
  | "in_progress" => some .inProgress
  | "done"        => some .done
  | "superseded"  => some .superseded
  | _             => none

def parsePlanTask (tok : String) : Option PlanTask :=
  match tok.splitOn "," with
  | [id, statusS, depsS, evS, allowS, verifS] =>
    match parseTaskStatus statusS with
    | some st =>
      some
        { id := id
        , status := st
        , dependsOn := parsePipeList depsS
        , hasCompletionEvidence := parseBool01 evS
        , allowedPathsNonempty := parseBool01 allowS
        , verificationNonempty := parseBool01 verifS
        }
    | none => none
  | _ => none

def parseBlockingQuestion (tok : String) : Option BlockingQuestion :=
  match tok.splitOn "," with
  | [id, blocksS] => some { id := id, blocks := parsePipeList blocksS }
  | _             => none

def parsePathAuthority : String → Option PathAuthority
  | "source"              => some .sourceEdit
  | "verification_output" => some .verificationOutput
  | _                     => none

def parsePathDecision (tok : String) : Option PathDecision :=
  match tok.splitOn "," with
  | [inR, allow, forb, vout] =>
    some
      { insideRoot := parseBool01 inR
      , matchedAllowed := parseBool01 allow
      , matchedForbidden := parseBool01 forb
      , matchedVerifyOutput := parseBool01 vout
      }
  | _ => none

def parseTier : String → Option ApprovalTier
  | "R" => some .R
  | "W" => some .W
  | "F" => some .F
  | _   => none

def parseRole : String → Option AgentRole
  | "scope"       => some .scope
  | "review"      => some .review
  | "research"    => some .research
  | "docs"        => some .docs
  | "investigate" => some .investigate
  | "implement"   => some .implement
  | "finalize"    => some .finalize
  | _             => none

def parseStage : String → Option LifecycleStage
  | "implemented" => some .implemented
  | "verified"    => some .verified
  | "reviewed"    => some .reviewed
  | "committed"   => some .committed
  | "pushed"      => some .pushed
  | "ci_passed"   => some .ciPassed
  | "released"    => some .released
  | _             => none

def parseReviewClassification : String → Option ReviewClassification
  | "unclassified"        => some .unclassified
  | "must_fix"            => some .mustFix
  | "already_fixed"       => some .alreadyFixed
  | "not_valid"           => some .notValid
  | "out_of_scope"        => some .outOfScope
  | "needs_clarification" => some .needsClarification
  | _                     => none

def parseReviewItem (tok : String) : Option CanonicalReviewItem :=
  match tok.splitOn "," with
  | [key, clsS, repS, resS, fixS] =>
    match parseReviewClassification clsS with
    | some cls =>
      some
        { itemKey := key
        , classification := cls
        , replied := parseBool01 repS
        , resolved := parseBool01 resS
        , fixVerified := parseBool01 fixS
        }
    | none => none
  | _ => none

def evalLine (line : String) : String :=
  let tokens := line.trimAscii.toString.splitOn " " |>.filter (fun s => !s.isEmpty)
  match tokens with
  | [] => ""
  | "combine" :: rest =>
    let codes := rest.filterMap (fun s => s.toNat? >>= ExitCode.fromNat?)
    toString (ExitCode.toNat (ExitCode.combineAll codes))
  | ["layer_edge", src, dst] =>
    toString (edgeAllowed birkinSixLayers src dst)
  | ["fallback", forb, allow] =>
    toString (fallbackAllowed (parseBool01 forb) (parseBool01 allow))
  | ["compression", minS, maxS, reqS, thS, trS] =>
    match minS.toNat?, maxS.toNat?, thS.toNat?, trS.toNat? with
    | some minBp, some maxBp, some thBp, some trBp =>
      let b : CompressionBounds :=
        { thresholdMinBp := minBp, thresholdMaxBp := maxBp, requireTargetLt := parseBool01 reqS }
      toString (compressionValid b thBp trBp)
    | _, _, _, _ => "error"
  | "receipt_chain" :: rest =>
    match rest.mapM parseReceiptEntry with
    | some entries => toString (verifyChain entries)
    | none => "error"
  | "receipt_admission" :: reqCsv :: headS :: treeS :: specSha :: reqCleanS :: dirtyS :: rest =>
    let reqCmds :=
      if reqCsv == "-" then []
      else (reqCsv.splitOn ",").filter (fun s => !s.isEmpty)
    match rest.mapM parseReceiptEntry with
    | some entries =>
      toString (verifyAdmission entries reqCmds (parseOptStr headS) (parseOptStr treeS)
        specSha (parseBool01 reqCleanS) (parseBool01 dirtyS))
    | none => "error"
  | ["plan_valid", tasksS, qsS] =>
    match (parseSemiList tasksS).mapM parsePlanTask,
          (parseSemiList qsS).mapM parseBlockingQuestion with
    | some tasks, some qs => toString (planValid tasks qs)
    | _, _ => "error"
  | ["plan_dispatch", intentS, tid, tasksS, qsS] =>
    match parsePlanIntent intentS,
          (parseSemiList tasksS).mapM parsePlanTask,
          (parseSemiList qsS).mapM parseBlockingQuestion with
    | some intent, some tasks, some qs => toString (canDispatchMutating intent tasks qs tid)
    | _, _, _ => "error"
  | ["scope_admit", authS, decsS, myS, otherS] =>
    match parsePathAuthority authS, (parseSemiList decsS).mapM parsePathDecision with
    | some auth, some decs =>
      toString (scopeAdmitted auth decs (parsePipeList myS) (parsePipeList otherS))
    | _, _ => "error"
  | ["authority_admit", roleS, tierS, expFS, refS, prevS, retS, fmS, srS, smS] =>
    match parseRole roleS, parseTier tierS, parseTier prevS, retS.toNat? with
    | some role, some tier, some prev, some retries =>
      let req : DispatchRequest :=
        { role := role
        , requestedTier := tier
        , explicitFAuth := parseBool01 expFS
        , isRefusalRetry := parseBool01 refS
        , prevTier := prev
        , retriesAfterFirst := retries
        , forbiddenModel := parseBool01 fmS
        , sameImplRuntime := parseBool01 srS
        , sameImplModel := parseBool01 smS
        }
      toString (dispatchAdmitted req)
    | _, _, _, _ => "error"
  | ["stage_admit", stageS, discS, execS, tcS, chS, trS, rvS, seS, ecS, grS, gvS, rmS, ciS, raS] =>
    match parseStage stageS, discS.toNat?, execS.toNat? with
    | some st, some disc, some exec =>
      let ev : StageEvidence :=
        { discoveredTests := disc
        , executedTests := exec
        , toolchainMatched := parseBool01 tcS
        , receiptChainOk := parseBool01 chS
        , treeBoundOk := parseBool01 trS
        , reviewPassed := parseBool01 rvS
        , sawyerStagedExact := parseBool01 seS
        , sawyerExcludedClean := parseBool01 ecS
        , gpgSignRequired := parseBool01 grS
        , gpgSigValid := parseBool01 gvS
        , remoteHeadMatches := parseBool01 rmS
        , ciPassed := parseBool01 ciS
        , releaseAuthorized := parseBool01 raS
        }
      toString (stageAdmitted st ev)
    | _, _, _ => "error"
  | ["review_closure", mode, itemsS] =>
    match (parseSemiList itemsS).mapM parseReviewItem with
    | some items =>
      if mode == "valid" then toString (reviewClosureValid items)
      else if mode == "rereview" then toString (canRequestReReview items)
      else "error"
    | none => "error"
  | _ => "error"

def main : IO Unit := do
  let stdin ← IO.getStdin
  let content ← stdin.readToEnd
  for line in content.splitOn "\n" do
    let out := evalLine line
    if !out.isEmpty then
      IO.println out
