/-
  BirkinSpec.PlanContract — Formally verified execution-plan invariants.

  Proves fail-closed properties for durable workflow plans (`fly-face` / `xo`):
  1. `planOnly` intent never permits mutating unit dispatch (`canDispatchMutating_planOnly_false`).
  2. Open blocking questions forbid mutating dispatch (`canDispatchMutating_questionBlocked_false`).
  3. Blocked prerequisites forbid mutating dispatch (`canDispatchMutating_blockedPrereq_false`).
  4. Valid plans enforce `done -> hasCompletionEvidence` (`planValid_done_requires_evidence`).
  5. Valid plans propagate blocked prerequisites to downstream tasks (`planValid_blocked_propagates`).
  6. Topological dependency ordering implies strict acyclicity (`depsOrdered_acyclic`).
-/

namespace BirkinSpec

inductive PlanIntent where
  | planOnly
  | implement
  deriving DecidableEq, Repr

inductive TaskStatus where
  | ready
  | blocked
  | inProgress
  | done
  | superseded
  deriving DecidableEq, Repr

structure PlanTask where
  id                    : String
  status                : TaskStatus
  dependsOn             : List String
  hasCompletionEvidence : Bool
  allowedPathsNonempty  : Bool
  verificationNonempty  : Bool
  deriving DecidableEq, Repr

structure BlockingQuestion where
  id     : String
  blocks : List String
  deriving DecidableEq, Repr

def taskById (tasks : List PlanTask) (id : String) : Option PlanTask :=
  tasks.find? (fun t => t.id == id)

def depsOrderedAux (seen : List String) : List PlanTask → Bool
  | [] => true
  | t :: rest =>
    (!seen.contains t.id)
    && t.dependsOn.all (fun d => seen.contains d)
    && depsOrderedAux (t.id :: seen) rest

def depsOrdered (tasks : List PlanTask) : Bool :=
  depsOrderedAux [] tasks

def isQuestionBlocked (questions : List BlockingQuestion) (tid : String) : Bool :=
  questions.any (fun q => q.blocks.contains tid)

def hasBlockedPrereq (tasks : List PlanTask) (t : PlanTask) : Bool :=
  t.dependsOn.any (fun d =>
    match taskById tasks d with
    | some dt => dt.status == .blocked
    | none    => true)

def allPrereqsDone (tasks : List PlanTask) (t : PlanTask) : Bool :=
  t.dependsOn.all (fun d =>
    match taskById tasks d with
    | some dt => dt.status == .done
    | none    => false)

def taskWellFormed (tasks : List PlanTask) (questions : List BlockingQuestion) (t : PlanTask) : Bool :=
  let baseOk := t.allowedPathsNonempty && t.verificationNonempty
  let doneOk := if t.status == .done then t.hasCompletionEvidence else true
  let activeOk :=
    if t.status == .inProgress || t.status == .done then allPrereqsDone tasks t else true
  let blockPropOk :=
    if isQuestionBlocked questions t.id || hasBlockedPrereq tasks t then
      t.status == .blocked || t.status == .superseded
    else
      true
  baseOk && doneOk && activeOk && blockPropOk

def questionsValid (tasks : List PlanTask) (questions : List BlockingQuestion) : Bool :=
  questions.all (fun q =>
    q.blocks.all (fun tid =>
      match taskById tasks tid with
      | some t => t.status == .blocked
      | none   => false))

def planValid (tasks : List PlanTask) (questions : List BlockingQuestion) : Bool :=
  (!tasks.isEmpty)
  && depsOrdered tasks
  && tasks.all (taskWellFormed tasks questions)
  && questionsValid tasks questions

def canDispatchMutating (intent : PlanIntent) (tasks : List PlanTask)
    (questions : List BlockingQuestion) (tid : String) : Bool :=
  (intent == .implement)
  && planValid tasks questions
  && match taskById tasks tid with
     | some t =>
       (t.status == .ready)
       && (!isQuestionBlocked questions tid)
       && (!hasBlockedPrereq tasks t)
       && allPrereqsDone tasks t
     | none => false

theorem canDispatchMutating_planOnly_false (tasks : List PlanTask)
    (questions : List BlockingQuestion) (tid : String) :
    canDispatchMutating .planOnly tasks questions tid = false := by
  simp [canDispatchMutating]

theorem canDispatchMutating_questionBlocked_false (intent : PlanIntent)
    (tasks : List PlanTask) (questions : List BlockingQuestion) (tid : String)
    (hq : isQuestionBlocked questions tid = true) :
    canDispatchMutating intent tasks questions tid = false := by
  unfold canDispatchMutating
  cases h : taskById tasks tid with
  | none => simp
  | some t => simp [hq]

theorem canDispatchMutating_blockedPrereq_false (intent : PlanIntent)
    (tasks : List PlanTask) (questions : List BlockingQuestion) (tid : String) (t : PlanTask)
    (hfind : taskById tasks tid = some t)
    (hb : hasBlockedPrereq tasks t = true) :
    canDispatchMutating intent tasks questions tid = false := by
  unfold canDispatchMutating
  simp [hfind, hb]

theorem planValid_done_requires_evidence {tasks : List PlanTask} {questions : List BlockingQuestion}
    {t : PlanTask} (hv : planValid tasks questions = true) (hmem : t ∈ tasks)
    (hdone : t.status = .done) : t.hasCompletionEvidence = true := by
  unfold planValid at hv
  have h1 := (Bool.and_eq_true _ _ |>.mp hv).1
  have hall := (Bool.and_eq_true _ _ |>.mp h1).2
  have hwf := List.all_eq_true.mp hall t hmem
  unfold taskWellFormed at hwf
  simp [hdone] at hwf
  exact hwf.1.1.2

theorem planValid_blocked_propagates {tasks : List PlanTask} {questions : List BlockingQuestion}
    {t : PlanTask} (hv : planValid tasks questions = true) (hmem : t ∈ tasks)
    (hb : hasBlockedPrereq tasks t = true) :
    t.status = .blocked ∨ t.status = .superseded := by
  unfold planValid at hv
  have h1 := (Bool.and_eq_true _ _ |>.mp hv).1
  have hall := (Bool.and_eq_true _ _ |>.mp h1).2
  have hwf := List.all_eq_true.mp hall t hmem
  unfold taskWellFormed at hwf
  simp [hb] at hwf
  exact hwf.2

/-- Strict list-order reachability witness proving topological ordering prevents cycles. -/
def TaskDepIn (tasks : List PlanTask) (a b : String) : Prop :=
  ∃ t ∈ tasks, t.id = a ∧ b ∈ t.dependsOn

inductive TaskReachable (tasks : List PlanTask) : String → String → Prop where
  | single {a b : String} : TaskDepIn tasks a b → TaskReachable tasks a b
  | trans  {a b c : String} : TaskDepIn tasks a b → TaskReachable tasks b c → TaskReachable tasks a c

def taskPosAux : Nat → List PlanTask → String → Nat
  | n, [], _ => n
  | n, t :: rest, id => if t.id == id then n else taskPosAux (n + 1) rest id

theorem depsOrderedAux_no_seen_mem :
    ∀ (tasks : List PlanTask) (seen : List String),
      depsOrderedAux seen tasks = true →
      ∀ t ∈ tasks, t.id ∉ seen
  | [], _, _, _, h => by cases h
  | x :: xs, seen, hord, t, hmem => by
    unfold depsOrderedAux at hord
    have h1 := (Bool.and_eq_true _ _ |>.mp hord).1
    have hnot : (!seen.contains x.id) = true := (Bool.and_eq_true _ _ |>.mp h1).1
    have hrest : depsOrderedAux (x.id :: seen) xs = true := (Bool.and_eq_true _ _ |>.mp hord).2
    cases hmem with
    | head =>
      intro hcontain
      simp at hnot
      exact hnot hcontain
    | tail _ htail =>
      have ih := depsOrderedAux_no_seen_mem xs (x.id :: seen) hrest t htail
      intro hcontain
      exact ih (List.mem_cons_of_mem x.id hcontain)

theorem depsOrderedAux_pos_lt :
    ∀ (tasks : List PlanTask) (seen : List String) (idx : Nat),
      depsOrderedAux seen tasks = true →
      (∀ s ∈ seen, taskPosAux 0 [] s = 0) →
      ∀ (a b : String),
        (∃ t ∈ tasks, t.id = a ∧ b ∈ t.dependsOn) →
        b ∈ seen ∨ taskPosAux idx tasks b < taskPosAux idx tasks a
  | [], _, _, _, _, _, _, ⟨_, h, _, _⟩ => by cases h
  | x :: xs, seen, idx, hord, _, a, b, ⟨t, hmem, htid, hdep⟩ => by
    unfold depsOrderedAux at hord
    have h1 := (Bool.and_eq_true _ _ |>.mp hord).1
    have hdeps := (Bool.and_eq_true _ _ |>.mp h1).2
    have hrest := (Bool.and_eq_true _ _ |>.mp hord).2
    cases hmem with
    | head =>
      left
      exact List.contains_iff_mem.mp (List.all_eq_true.mp hdeps b hdep)
    | tail _ htail =>
      have hne_ax : x.id ≠ a := by
        have hnot := depsOrderedAux_no_seen_mem xs (x.id :: seen) hrest t htail
        intro heq
        subst htid
        exact hnot (heq ▸ List.mem_cons_self ..)
      have hrec := depsOrderedAux_pos_lt xs (x.id :: seen) (idx + 1) hrest (fun _ _ => rfl) a b ⟨t, htail, htid, hdep⟩
      cases hrec with
      | inl hseen =>
        cases List.mem_cons.mp hseen with
        | inl hbx =>
          right
          subst hbx
          have ha_pos : idx + 1 ≤ taskPosAux (idx + 1) xs a := by
            clear hord h1 hdeps hrest hne_ax htail htid hdep
            generalize (idx + 1) = k
            induction xs generalizing k with
            | nil => exact Nat.le_refl k
            | cons y ys ihy =>
              unfold taskPosAux
              split
              · exact Nat.le_refl k
              · exact Nat.le_trans (Nat.le_succ k) (ihy (k + 1))
          have hax_b : (x.id == a) = false := beq_false_of_ne hne_ax
          simp only [taskPosAux, beq_self_eq_true, ↓reduceIte, hax_b]
          exact Nat.lt_of_lt_of_le (Nat.lt_succ_self idx) ha_pos
        | inr htail_seen => left; exact htail_seen
      | inr hlt =>
        right
        by_cases hbx : x.id = b
        · subst hbx
          have ha_pos : idx + 1 ≤ taskPosAux (idx + 1) xs a := by
            clear hord h1 hdeps hrest hne_ax htail htid hdep hlt
            generalize (idx + 1) = k
            induction xs generalizing k with
            | nil => exact Nat.le_refl k
            | cons y ys ihy =>
              unfold taskPosAux
              split
              · exact Nat.le_refl k
              · exact Nat.le_trans (Nat.le_succ k) (ihy (k + 1))
          have hax_b : (x.id == a) = false := beq_false_of_ne hne_ax
          simp only [taskPosAux, beq_self_eq_true, ↓reduceIte, hax_b]
          exact Nat.lt_of_lt_of_le (Nat.lt_succ_self idx) ha_pos
        · have hbx_b : (x.id == b) = false := beq_false_of_ne hbx
          have hax_b : (x.id == a) = false := beq_false_of_ne hne_ax
          simp only [taskPosAux, hbx_b, hax_b]
          exact hlt

theorem depsOrdered_dep_pos_lt {tasks : List PlanTask} (hord : depsOrdered tasks = true)
    {a b : String} (hdep : TaskDepIn tasks a b) :
    taskPosAux 0 tasks b < taskPosAux 0 tasks a := by
  have h := depsOrderedAux_pos_lt tasks [] 0 hord (fun _ h => by cases h) a b hdep
  cases h with
  | inl hnil => cases hnil
  | inr hlt => exact hlt

theorem depsOrdered_reachable_pos_lt {tasks : List PlanTask} (hord : depsOrdered tasks = true)
    {a b : String} (hreach : TaskReachable tasks a b) :
    taskPosAux 0 tasks b < taskPosAux 0 tasks a := by
  induction hreach with
  | single hdep => exact depsOrdered_dep_pos_lt hord hdep
  | trans hdep _ ih => exact Nat.lt_trans ih (depsOrdered_dep_pos_lt hord hdep)

theorem depsOrdered_acyclic {tasks : List PlanTask} (hord : depsOrdered tasks = true) :
    ∀ a : String, ¬ TaskReachable tasks a a := by
  intro a hcyc
  exact Nat.lt_irrefl (taskPosAux 0 tasks a) (depsOrdered_reachable_pos_lt hord hcyc)

end BirkinSpec
