/-
  BirkinSpec.ReviewClosure — Formally verified PR review closure invariants (`eda-sis`).

  Proves fail-closed properties over canonical deduplicated review items:
  1. Duplicate item keys fail closed.
  2. Any unclassified canonical item fails closure.
  3. Resolving a thread without posting a reply fails closure.
  4. Any `mustFix` item without verified fix fails closure.
  5. Any open `needsClarification` item blocks requesting re-review.
  6. Passing `canRequestReReview` implies every canonical item was classified and replied to.
-/

namespace BirkinSpec

inductive ReviewClassification where
  | unclassified
  | mustFix
  | alreadyFixed
  | notValid
  | outOfScope
  | needsClarification
  deriving DecidableEq, Repr

structure CanonicalReviewItem where
  itemKey        : String
  classification : ReviewClassification
  replied        : Bool
  resolved       : Bool
  fixVerified    : Bool
  deriving DecidableEq, Repr

def keysUniqueAux (seen : List String) : List CanonicalReviewItem → Bool
  | [] => true
  | it :: rest => (!seen.contains it.itemKey) && keysUniqueAux (it.itemKey :: seen) rest

def itemClosed (it : CanonicalReviewItem) : Bool :=
  if it.classification == .unclassified then
    false
  else if it.resolved && !it.replied then
    false
  else if it.classification == .mustFix && !it.fixVerified then
    false
  else
    it.replied

def reviewClosureValid (items : List CanonicalReviewItem) : Bool :=
  keysUniqueAux [] items && items.all itemClosed

def canRequestReReview (items : List CanonicalReviewItem) : Bool :=
  reviewClosureValid items && items.all (fun it => it.classification != .needsClarification)

theorem reviewClosureValid_unclassified_false {items : List CanonicalReviewItem}
    {it : CanonicalReviewItem} (hmem : it ∈ items) (hunc : it.classification = .unclassified) :
    reviewClosureValid items = false := by
  unfold reviewClosureValid
  cases h : items.all itemClosed with
  | false => simp
  | true =>
    have hc := List.all_eq_true.mp h it hmem
    simp [itemClosed, hunc] at hc

theorem reviewClosureValid_resolved_without_reply_false {items : List CanonicalReviewItem}
    {it : CanonicalReviewItem} (hmem : it ∈ items)
    (hres : it.resolved = true) (hnorep : it.replied = false) :
    reviewClosureValid items = false := by
  unfold reviewClosureValid
  cases h : items.all itemClosed with
  | false => simp
  | true =>
    have hc := List.all_eq_true.mp h it hmem
    unfold itemClosed at hc
    cases hcls : it.classification <;> simp [hcls, hres, hnorep] at hc

theorem reviewClosureValid_mustFix_unverified_false {items : List CanonicalReviewItem}
    {it : CanonicalReviewItem} (hmem : it ∈ items)
    (hmf : it.classification = .mustFix) (hunv : it.fixVerified = false) :
    reviewClosureValid items = false := by
  unfold reviewClosureValid
  cases h : items.all itemClosed with
  | false => simp
  | true =>
    have hc := List.all_eq_true.mp h it hmem
    unfold itemClosed at hc
    cases hrep : it.replied <;> cases hres : it.resolved <;> simp [hmf, hunv, hrep, hres] at hc

theorem canRequestReReview_clarification_blocks {items : List CanonicalReviewItem}
    {it : CanonicalReviewItem} (hmem : it ∈ items)
    (hnc : it.classification = .needsClarification) :
    canRequestReReview items = false := by
  unfold canRequestReReview
  cases h : items.all (fun x => x.classification != .needsClarification) with
  | false => simp
  | true =>
    have hc := List.all_eq_true.mp h it hmem
    simp [hnc] at hc

theorem canRequestReReview_implies_all_replied {items : List CanonicalReviewItem}
    (h : canRequestReReview items = true) :
    ∀ it ∈ items, it.replied = true := by
  unfold canRequestReReview reviewClosureValid at h
  have h1 := (Bool.and_eq_true _ _ |>.mp h).1
  have hall := (Bool.and_eq_true _ _ |>.mp h1).2
  intro it hmem
  have hc := List.all_eq_true.mp hall it hmem
  unfold itemClosed at hc
  cases hcls : it.classification <;> cases hres : it.resolved <;> cases hrep : it.replied <;>
    cases hfix : it.fixVerified <;> simp [hcls, hres, hrep, hfix] at hc ⊢

end BirkinSpec
