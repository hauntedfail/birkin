/-
  BirkinSpec.ExitCode — Formally verified exit-code severity lattice.

  Proves that `combine` forms a commutative, associative, idempotent join-semilattice
  with `pass` as identity and `toolError` as absorbing top element, and that `combineAll`
  is fail-closed: it returns `pass` if and only if every input is `pass`.
-/

namespace BirkinSpec

inductive ExitCode where
  | pass
  | static
  | liveContract
  | liveTransient
  | drift
  | toolError
  deriving DecidableEq, Repr

namespace ExitCode

def toNat : ExitCode → Nat
  | .pass          => 0
  | .static        => 1
  | .liveContract  => 2
  | .liveTransient => 3
  | .drift         => 4
  | .toolError     => 5

def fromNat? : Nat → Option ExitCode
  | 0 => some .pass
  | 1 => some .static
  | 2 => some .liveContract
  | 3 => some .liveTransient
  | 4 => some .drift
  | 5 => some .toolError
  | _ => none

/-- Strict total severity ordering: toolError > static > liveContract > drift > liveTransient > pass. -/
def severityRank : ExitCode → Nat
  | .pass          => 0
  | .liveTransient => 1
  | .drift         => 2
  | .liveContract  => 3
  | .static        => 4
  | .toolError     => 5

def combine (a b : ExitCode) : ExitCode :=
  if severityRank a ≥ severityRank b then a else b

def combineAll : List ExitCode → ExitCode
  | []      => .pass
  | c :: cs => combine c (combineAll cs)

theorem toNat_roundtrip (c : ExitCode) : fromNat? (toNat c) = some c := by
  cases c <;> rfl

theorem severityRank_inj {a b : ExitCode} (h : severityRank a = severityRank b) : a = b := by
  cases a <;> cases b <;> first | rfl | contradiction

theorem combine_assoc (a b c : ExitCode) :
    combine (combine a b) c = combine a (combine b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem combine_comm (a b : ExitCode) :
    combine a b = combine b a := by
  cases a <;> cases b <;> rfl

theorem combine_idem (a : ExitCode) :
    combine a a = a := by
  cases a <;> rfl

theorem combine_pass_left (a : ExitCode) :
    combine .pass a = a := by
  cases a <;> rfl

theorem combine_pass_right (a : ExitCode) :
    combine a .pass = a := by
  cases a <;> rfl

theorem combine_toolError_left (a : ExitCode) :
    combine .toolError a = .toolError := by
  cases a <;> rfl

theorem combine_toolError_right (a : ExitCode) :
    combine a .toolError = .toolError := by
  cases a <;> rfl

theorem severityRank_le_combine_left (a b : ExitCode) :
    severityRank a ≤ severityRank (combine a b) := by
  cases a <;> cases b <;> decide

theorem severityRank_le_combine_right (a b : ExitCode) :
    severityRank b ≤ severityRank (combine a b) := by
  cases a <;> cases b <;> decide

theorem combine_eq_pass_iff (a b : ExitCode) :
    combine a b = .pass ↔ a = .pass ∧ b = .pass := by
  cases a <;> cases b <;> decide

/-- Fail-closed monotonicity: the combined severity is never lower than any constituent check. -/
theorem combineAll_mem_le : ∀ (xs : List ExitCode) (c : ExitCode),
    c ∈ xs → severityRank c ≤ severityRank (combineAll xs)
  | [], _, h => by cases h
  | x :: xs, c, h => by
    simp only [combineAll]
    cases h with
    | head =>
      exact severityRank_le_combine_left x (combineAll xs)
    | tail _ hmem =>
      have ih := combineAll_mem_le xs c hmem
      exact Nat.le_trans ih (severityRank_le_combine_right x (combineAll xs))

/-- No violation can ever be masked: `combineAll` returns `pass` iff every element is `pass`. -/
theorem combineAll_eq_pass_iff : ∀ (xs : List ExitCode),
    combineAll xs = .pass ↔ ∀ c ∈ xs, c = .pass
  | [] => by simp [combineAll]
  | x :: xs => by
    simp only [combineAll, combine_eq_pass_iff, combineAll_eq_pass_iff xs]
    constructor
    · intro ⟨hx, hxs⟩ c hc
      cases hc with
      | head => exact hx
      | tail _ hmem => exact hxs c hmem
    · intro h
      exact ⟨h x (List.Mem.head _), fun c hc => h c (List.Mem.tail _ hc)⟩

end ExitCode
end BirkinSpec
