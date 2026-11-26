/-
  BirkinSpec.Oracle — Executable Lean 4 reference oracle for differential testing against Rust.

  Reads line-oriented queries on stdin and writes exact Lean-verified verdicts to stdout:
    combine <n1> <n2> ...          -> combined exit code nat
    layer_edge <src> <dst>         -> true | false (against Birkin's 6-layer DAG)
    fallback <forb:0|1> <allow:0|1> -> true | false
    compression <min> <max> <reqLt:0|1> <th> <tr_bp> -> true | false
-/

import BirkinSpec

open BirkinSpec

def parseBool01 (s : String) : Bool :=
  s == "1" || s == "true"

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
  | _ => "error"

def main : IO Unit := do
  let stdin ← IO.getStdin
  let content ← stdin.readToEnd
  for line in content.splitOn "\n" do
    let out := evalLine line
    if !out.isEmpty then
      IO.println out
