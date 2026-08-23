use serde_json::Value;

#[test]
fn published_schema_carries_the_native_v1_manifest_limits() {
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/plugin-manifest.v1.json"))
            .expect("parse plugin manifest schema");

    assert_eq!(
        schema.pointer("/properties/id/maxLength"),
        Some(&Value::from(128))
    );
    assert!(
        schema
            .pointer("/properties/id/pattern")
            .and_then(Value::as_str)
            .is_some_and(|pattern| pattern.contains("{0,61}"))
    );
    assert_eq!(
        schema.pointer("/properties/runtime/properties/args/maxItems"),
        Some(&Value::from(32))
    );
    assert_eq!(
        schema.pointer("/properties/runtime/properties/args/items/maxLength"),
        Some(&Value::from(4096))
    );
    assert_eq!(
        schema.pointer("/properties/runtime/properties/args/items/pattern"),
        Some(&Value::from("^[^\\u0000]*$"))
    );
    assert_eq!(
        schema.pointer("/properties/capabilities/properties/maxInputBytes/minimum"),
        Some(&Value::from(0))
    );
    assert_eq!(
        schema.pointer("/properties/capabilities/properties/maxInputBytes/maximum"),
        Some(&Value::from(16_777_216))
    );
    assert_eq!(
        schema.pointer("/properties/limits/properties/timeBudgetMs/anyOf/0/const"),
        Some(&Value::from(0))
    );
    assert_eq!(
        schema.pointer("/properties/limits/properties/timeBudgetMs/anyOf/1/minimum"),
        Some(&Value::from(50))
    );
    assert_eq!(
        schema.pointer("/properties/limits/properties/timeBudgetMs/anyOf/1/maximum"),
        Some(&Value::from(1000))
    );
}
