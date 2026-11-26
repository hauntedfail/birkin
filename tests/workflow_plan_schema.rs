use birkin::plan_contract::{load_plan_document, validate_plan_document};
use birkin::workflow_models::PlanDocument;
use serde_json::{json, Value};
use tempfile::NamedTempFile;

fn portable_plan() -> Value {
    json!({
        "version": 1,
        "intent": "implement",
        "outcome": "Validate incoming plans.",
        "non_goals": [],
        "constraints": ["Use the existing loader."],
        "evidence": ["src/plan_contract.rs"],
        "questions": [{"id": "follow-up", "question": "Who maintains the fixtures?", "blocks": []}],
        "tasks": [{
            "id": "loader",
            "title": "Check the plan schema",
            "context": "Plans arrive as JSON files.",
            "expected_behavior": "Missing fields produce schema errors.",
            "status": "ready",
            "depends_on": [],
            "allowed_paths": ["src/"],
            "forbidden_paths": [],
            "acceptance": ["The error identifies the missing field."],
            "verification": [{"method": "cargo test", "expected": "All loader tests pass."}],
            "stop_conditions": ["The schema changes."],
            "owner": "implementation",
            "completion_evidence": []
        }]
    })
}

fn load(plan: &Value) -> Result<PlanDocument, String> {
    let file = NamedTempFile::new().unwrap();
    serde_json::to_writer(file.as_file(), plan).unwrap();
    load_plan_document(file.path())
}

#[test]
fn loader_rejects_each_missing_portable_array() {
    for (parent, field) in [
        ("", "non_goals"),
        ("", "constraints"),
        ("", "evidence"),
        ("", "questions"),
        ("", "tasks"),
        ("/tasks/0", "depends_on"),
        ("/tasks/0", "allowed_paths"),
        ("/tasks/0", "forbidden_paths"),
        ("/tasks/0", "acceptance"),
        ("/tasks/0", "verification"),
        ("/tasks/0", "stop_conditions"),
        ("/tasks/0", "completion_evidence"),
        ("/questions/0", "blocks"),
    ] {
        let mut plan = portable_plan();
        let object = plan.pointer_mut(parent).unwrap().as_object_mut().unwrap();
        assert!(object.remove(field).is_some());
        let Err(error) = load(&plan) else {
            panic!("loaded plan without {parent}/{field}");
        };
        assert!(
            error.contains(&format!("missing field `{field}`")),
            "{error}"
        );
    }
}

#[test]
fn portable_plan_loads_with_optional_task_defaults() {
    let mut plan = portable_plan();
    let loaded = load(&plan).unwrap();
    assert!(validate_plan_document(&loaded).valid);
    assert!(loaded.tasks[0].verification_output_paths.is_empty());
    assert_eq!(loaded.tasks[0].checkout_root, None);

    plan["questions"] = json!([]);
    assert!(validate_plan_document(&load(&plan).unwrap()).valid);
}

#[test]
fn extended_plan_loads_with_task_overrides_and_extra_metadata() {
    let mut plan = portable_plan();
    let root = tempfile::tempdir().unwrap();
    plan["assumptions"] = json!(["The checkout exists."]);
    plan["tasks"][0]["checkout_root"] = json!(root.path());
    plan["tasks"][0]["verification_output_paths"] = json!(["target/"]);
    plan["tasks"][0]["notes"] = json!("Run locally.");
    let loaded = load(&plan).unwrap();
    assert!(validate_plan_document(&loaded).valid);
    assert_eq!(
        loaded.tasks[0].checkout_root.as_deref(),
        root.path().to_str()
    );
    assert_eq!(loaded.tasks[0].verification_output_paths, ["target/"]);
}
