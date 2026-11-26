/-
  BirkinSpec.Oracle — Executable Lean 4 reference oracle for differential testing against Rust.

  Reads line-oriented queries on stdin and writes exact Lean-verified verdicts to stdout:
    combine <n1> <n2> ...                                             -> combined exit code nat
    layer_edge <src> <dst>                                            -> true | false (against Birkin's 6-layer DAG)
    fallback <forb:0|1> <allow:0|1>                                   -> true | false
    compression <min> <max> <reqLt:0|1> <th> <tr_bp>                  -> true | false
    receipt_chain [entry1 entry2 ...]                                 -> true | false
    receipt_admission <reqs> <head> <tree> <spec> <clean> <dirty> [e] -> true | false
-/

import BirkinSpec

open BirkinSpec

def parseBool01 (s : String) : Bool :=
  s == "1" || s == "true"

def parseOptStr (s : String) : Option String :=
  if s == "-" then none else some s

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
  | _ => "error"

def main : IO Unit := do
  let stdin ← IO.getStdin
  let content ← stdin.readToEnd
  for line in content.splitOn "\n" do
    let out := evalLine line
    if !out.isEmpty then
      IO.println out
