/-
  BirkinSpec.Json — Zero-dependency pure-Lean 4 RFC 8259 JSON parser and encoder.

  Intentionally avoids importing `Lean.Data.Json` so `birkin-kernel` compiles to a
  small standalone native executable with zero Lean compiler shared-library dependencies.
-/

namespace BirkinSpec

inductive JVal where
  | null
  | bool (b : Bool)
  | nat  (n : Nat)
  | str  (s : String)
  | arr  (xs : List JVal)
  | obj  (kvs : List (String × JVal))
  deriving Repr

namespace JVal

private def hexDigit (n : Nat) : Char :=
  if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

private def escapeChar (c : Char) : String :=
  match c with
  | '"'  => "\\\""
  | '\\' => "\\\\"
  | '\n' => "\\n"
  | '\r' => "\\r"
  | '\t' => "\\t"
  | _ =>
    let code := c.toNat
    if code < 32 then
      let hi := hexDigit ((code / 16) % 16)
      let lo := hexDigit (code % 16)
      String.ofList ['\\', 'u', '0', '0', hi, lo]
    else
      String.singleton c

def encodeStr (s : String) : String :=
  "\"" ++ String.join (s.toList.map escapeChar) ++ "\""

partial def encode : JVal → String
  | .null   => "null"
  | .bool b => if b then "true" else "false"
  | .nat n  => toString n
  | .str s  => encodeStr s
  | .arr xs => "[" ++ String.intercalate "," (xs.map encode) ++ "]"
  | .obj kvs =>
    let pairs := kvs.map (fun (k, v) => encodeStr k ++ ":" ++ encode v)
    "{" ++ String.intercalate "," pairs ++ "}"

def getField? : JVal → String → Option JVal
  | .obj kvs, key => (kvs.find? (fun (k, _) => k == key)).map Prod.snd
  | _, _ => none

def asStr? : JVal → Option String
  | .str s => some s
  | _ => none

def asBool? : JVal → Option Bool
  | .bool b => some b
  | _ => none

def asNat? : JVal → Option Nat
  | .nat n => some n
  | _ => none

def asArr? : JVal → Option (List JVal)
  | .arr xs => some xs
  | _ => none

def asStrList? (v : JVal) : Option (List String) :=
  match v with
  | .arr xs => xs.mapM asStr?
  | _ => none

private structure Cursor where
  chars : Array Char
  pos   : Nat

private def isWs (c : Char) : Bool :=
  c == ' ' || c == '\n' || c == '\r' || c == '\t'

private partial def skipWs (c : Cursor) : Cursor :=
  if h : c.pos < c.chars.size then
    if isWs (c.chars[c.pos]) then skipWs { c with pos := c.pos + 1 } else c
  else
    c

private def peek? (c : Cursor) : Option Char :=
  if h : c.pos < c.chars.size then some c.chars[c.pos] else none

private def advance (c : Cursor) : Cursor :=
  { c with pos := c.pos + 1 }

private def expectLit (c : Cursor) (lit : String) : Except String Cursor :=
  let rec go (cs : List Char) (cur : Cursor) : Except String Cursor :=
    match cs with
    | [] => .ok cur
    | ch :: rest =>
      match peek? cur with
      | some got =>
        if got == ch then go rest (advance cur)
        else .error s!"unexpected character '{got}' while parsing '{lit}'"
      | none => .error s!"unexpected EOF while parsing '{lit}'"
  go lit.toList c

private def hexVal? (c : Char) : Option Nat :=
  let n := c.toNat
  if 48 ≤ n && n ≤ 57 then some (n - 48)
  else if 65 ≤ n && n ≤ 70 then some (n - 55)
  else if 97 ≤ n && n ≤ 102 then some (n - 87)
  else none

private def parseHex4 (c : Cursor) : Except String (Nat × Cursor) := do
  let mut acc := 0
  let mut cur := c
  for _ in [0, 1, 2, 3] do
    match peek? cur with
    | some ch =>
      match hexVal? ch with
      | some d =>
        acc := acc * 16 + d
        cur := advance cur
      | none => throw s!"invalid hex escape character '{ch}'"
    | none => throw "unexpected EOF in \\u escape"
  pure (acc, cur)

private partial def parseString (c : Cursor) : Except String (String × Cursor) := do
  match peek? c with
  | some '"' =>
    let mut cur := advance c
    let mut out : Array Char := #[]
    while true do
      match peek? cur with
      | none => throw "unterminated JSON string"
      | some '"' =>
        cur := advance cur
        return (String.ofList out.toList, cur)
      | some '\\' =>
        cur := advance cur
        match peek? cur with
        | none => throw "unterminated escape sequence in JSON string"
        | some '"'  => out := out.push '"'; cur := advance cur
        | some '\\' => out := out.push '\\'; cur := advance cur
        | some '/'  => out := out.push '/'; cur := advance cur
        | some 'b'  => out := out.push (Char.ofNat 8); cur := advance cur
        | some 'f'  => out := out.push (Char.ofNat 12); cur := advance cur
        | some 'n'  => out := out.push '\n'; cur := advance cur
        | some 'r'  => out := out.push '\r'; cur := advance cur
        | some 't'  => out := out.push '\t'; cur := advance cur
        | some 'u'  =>
          let (code, nextCur) ← parseHex4 (advance cur)
          if 0xD800 ≤ code && code ≤ 0xDBFF then
            match peek? nextCur, peek? (advance nextCur) with
            | some '\\', some 'u' =>
              let (low, afterLow) ← parseHex4 (advance (advance nextCur))
              if 0xDC00 ≤ low && low ≤ 0xDFFF then
                let scalar := 0x10000 + ((code - 0xD800) * 0x400) + (low - 0xDC00)
                out := out.push (Char.ofNat scalar)
                cur := afterLow
              else
                throw "invalid UTF-16 low surrogate in JSON string"
            | _, _ => throw "unpaired UTF-16 high surrogate in JSON string"
          else if 0xDC00 ≤ code && code ≤ 0xDFFF then
            throw "unexpected UTF-16 low surrogate in JSON string"
          else
            out := out.push (Char.ofNat code)
            cur := nextCur
        | some other => throw s!"invalid escape '\\{other}' in JSON string"
      | some ch =>
        if ch.toNat < 32 then
          throw "unescaped control character in JSON string"
        out := out.push ch
        cur := advance cur
    throw "unreachable"
  | _ => throw "expected '\"' to start JSON string"

private partial def parseNat (c : Cursor) : Except String (Nat × Cursor) := do
  let mut cur := c
  let mut digits := 0
  let mut acc := 0
  while true do
    match peek? cur with
    | some ch =>
      let n := ch.toNat
      if 48 ≤ n && n ≤ 57 then
        acc := acc * 10 + (n - 48)
        digits := digits + 1
        cur := advance cur
      else
        break
    | none => break
  if digits == 0 then
    throw "expected non-negative integer"
  match peek? cur with
  | some '.' | some 'e' | some 'E' =>
    throw "floating-point numbers are not accepted by the workflow kernel"
  | _ => pure (acc, cur)

mutual

private partial def parseVal (c : Cursor) : Except String (JVal × Cursor) := do
  let cur := skipWs c
  match peek? cur with
  | none => throw "unexpected EOF while parsing JSON value"
  | some 'n' =>
    let next ← expectLit cur "null"
    pure (.null, next)
  | some 't' =>
    let next ← expectLit cur "true"
    pure (.bool true, next)
  | some 'f' =>
    let next ← expectLit cur "false"
    pure (.bool false, next)
  | some '"' =>
    let (s, next) ← parseString cur
    pure (.str s, next)
  | some '[' => parseArr (advance cur)
  | some '{' => parseObj (advance cur)
  | some ch =>
    if 48 ≤ ch.toNat && ch.toNat ≤ 57 then
      let (n, next) ← parseNat cur
      pure (.nat n, next)
    else
      throw s!"unexpected character '{ch}' at position {cur.pos}"

private partial def parseArr (c : Cursor) : Except String (JVal × Cursor) := do
  let cur := skipWs c
  match peek? cur with
  | some ']' => pure (.arr [], advance cur)
  | _ =>
    let mut elems : Array JVal := #[]
    let mut cur := cur
    while true do
      let (v, next) ← parseVal cur
      elems := elems.push v
      let after := skipWs next
      match peek? after with
      | some ',' => cur := advance after
      | some ']' => return (.arr elems.toList, advance after)
      | some ch => throw s!"expected ',' or ']' in array, found '{ch}'"
      | none => throw "unterminated JSON array"
    throw "unreachable"

private partial def parseObj (c : Cursor) : Except String (JVal × Cursor) := do
  let cur := skipWs c
  match peek? cur with
  | some '}' => pure (.obj [], advance cur)
  | _ =>
    let mut pairs : Array (String × JVal) := #[]
    let mut cur := cur
    while true do
      let kcur := skipWs cur
      let (key, afterKey) ← parseString kcur
      let colonCur := skipWs afterKey
      match peek? colonCur with
      | some ':' =>
        let (v, afterVal) ← parseVal (advance colonCur)
        pairs := pairs.push (key, v)
        let sep := skipWs afterVal
        match peek? sep with
        | some ',' => cur := advance sep
        | some '}' => return (.obj pairs.toList, advance sep)
        | some ch => throw s!"expected ',' or '}}' in object, found '{ch}'"
        | none => throw "unterminated JSON object"
      | some ch => throw s!"expected ':' after object key, found '{ch}'"
      | none => throw "unexpected EOF after object key"
    throw "unreachable"

end

def parse (input : String) : Except String JVal := do
  let cur : Cursor := { chars := input.toList.toArray, pos := 0 }
  let (val, rest) ← parseVal cur
  let trailing := skipWs rest
  if trailing.pos != trailing.chars.size then
    throw s!"trailing characters after JSON value at position {trailing.pos}"
  pure val

end JVal

end BirkinSpec
