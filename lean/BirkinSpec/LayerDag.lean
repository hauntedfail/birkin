/-
  BirkinSpec.LayerDag — Formally verified architecture layer DAG & acyclicity proofs.

  Proves that:
  1. Same-layer imports are always permitted (`edgeAllowed_refl`).
  2. Any layer dependency graph admitting a strictly decreasing rank function is
     mathematically acyclic (`validRankOrder_acyclic`).
  3. Birkin's own 6-layer architecture (core < models < utils < engines < orchestration < cli)
     is provably acyclic (`birkin_six_layer_dag_acyclic`).
-/

namespace BirkinSpec

structure LayerRule where
  name : String
  allowedDeps : List String
  deriving DecidableEq, Repr

def findLayer (rules : List LayerRule) (name : String) : Option LayerRule :=
  rules.find? (fun r => r.name == name)

/-- Returns true iff an import from `srcLayer` to `dstLayer` is permitted by `rules`. -/
def edgeAllowed (rules : List LayerRule) (srcLayer dstLayer : String) : Bool :=
  if srcLayer == dstLayer then
    true
  else
    match findLayer rules srcLayer with
    | none      => true
    | some rule => rule.allowedDeps.contains dstLayer

/-- Direct declared dependency relation between named layers. -/
def DirectDep (rules : List LayerRule) (src dst : String) : Prop :=
  ∃ r ∈ rules, r.name = src ∧ dst ∈ r.allowedDeps

/-- Transitive reachability along declared layer dependencies. -/
inductive Reachable (rules : List LayerRule) : String → String → Prop where
  | single {a b : String} : DirectDep rules a b → Reachable rules a b
  | trans  {a b c : String} : DirectDep rules a b → Reachable rules b c → Reachable rules a c

/-- A strict topological witness: every declared dependency strictly decreases layer rank. -/
def ValidRankOrder (rules : List LayerRule) (rank : String → Nat) : Prop :=
  ∀ r ∈ rules, ∀ d ∈ r.allowedDeps, rank d < rank r.name

theorem edgeAllowed_refl (rules : List LayerRule) (layer : String) :
    edgeAllowed rules layer layer = true := by
  simp [edgeAllowed]

theorem edgeAllowed_false_implies_ne {rules : List LayerRule} {s d : String}
    (h : edgeAllowed rules s d = false) : s ≠ d := by
  intro heq
  subst heq
  rw [edgeAllowed_refl] at h
  contradiction

theorem reachable_rank_lt {rules : List LayerRule} {rank : String → Nat}
    (hvalid : ValidRankOrder rules rank) {a b : String} (hreach : Reachable rules a b) :
    rank b < rank a := by
  induction hreach with
  | single hdep =>
    rcases hdep with ⟨r, hr_mem, hr_name, hd_mem⟩
    rw [← hr_name]
    exact hvalid r hr_mem _ hd_mem
  | trans hdep _ ih =>
    rcases hdep with ⟨r, hr_mem, hr_name, hd_mem⟩
    have h1 : rank _ < rank r.name := hvalid r hr_mem _ hd_mem
    rw [hr_name] at h1
    exact Nat.lt_trans ih h1

/-- Soundness of topological rank witnesses: no layer can reach itself (strict DAG). -/
theorem validRankOrder_acyclic {rules : List LayerRule} {rank : String → Nat}
    (hvalid : ValidRankOrder rules rank) : ∀ a : String, ¬ Reachable rules a a := by
  intro a hcyc
  have hlt := reachable_rank_lt hvalid hcyc
  exact Nat.lt_irrefl (rank a) hlt

/-- Birkin's own 6-layer architecture specification. -/
def birkinSixLayers : List LayerRule :=
  [ { name := "core",          allowedDeps := [] }
  , { name := "models",        allowedDeps := ["core"] }
  , { name := "utils",         allowedDeps := ["core", "models"] }
  , { name := "engines",       allowedDeps := ["core", "models", "utils"] }
  , { name := "orchestration", allowedDeps := ["core", "models", "utils", "engines"] }
  , { name := "cli",           allowedDeps := ["core", "models", "utils", "engines", "orchestration"] }
  ]

def birkinLayerRank : String → Nat
  | "core"          => 0
  | "models"        => 1
  | "utils"         => 2
  | "engines"       => 3
  | "orchestration" => 4
  | "cli"           => 5
  | _               => 6

theorem birkinSixLayers_validRank : ValidRankOrder birkinSixLayers birkinLayerRank := by
  intro r hr d hd
  simp only [birkinSixLayers, List.mem_cons, List.not_mem_nil, or_false] at hr
  rcases hr with rfl | rfl | rfl | rfl | rfl | rfl
  · simp at hd
  · simp at hd; subst hd; decide
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at hd
    rcases hd with rfl | rfl <;> decide
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at hd
    rcases hd with rfl | rfl | rfl <;> decide
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at hd
    rcases hd with rfl | rfl | rfl | rfl <;> decide
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at hd
    rcases hd with rfl | rfl | rfl | rfl | rfl <;> decide

/-- Machine-checked proof that Birkin's 6-layer architecture forms a strict acyclic DAG. -/
theorem birkin_six_layer_dag_acyclic : ∀ a : String, ¬ Reachable birkinSixLayers a a :=
  validRankOrder_acyclic birkinSixLayers_validRank

end BirkinSpec
