//! Reject ambiguous duplicate JSON members at every external boundary.
use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::fmt;
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
                Number::from_f64(v)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(v)) = a.next_element()? {
                    values.push(v);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut values = Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON member"));
                    }
                    let Strict(v) = a.next_value()?;
                    values.insert(key, v);
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    let Strict(value) = serde_json::from_slice::<Strict>(bytes)?;
    serde_json::from_value(value)
}
#[cfg(test)]
fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, serde_json::Error> {
    from_slice(text.as_bytes())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicates_at_any_depth_are_rejected() {
        for input in [r#"{"x":1,"x":2}"#, r#"{"a":[{"x":1,"\u0078":2}]}"#] {
            assert!(from_str::<Value>(input).is_err());
        }
    }
    #[test]
    fn distinct_objects_and_large_integer_are_preserved() {
        let s = r#"{"a":[{"x":1},{"x":2}],"n":18446744073709551615}"#;
        assert_eq!(
            from_str::<Value>(s).unwrap(),
            serde_json::from_str::<Value>(s).unwrap()
        );
    }
    #[test]
    fn trailing_or_excessively_nested_json_is_rejected() {
        assert!(from_str::<Value>("{}{}").is_err());
        assert!(from_str::<Value>(&("[".repeat(200) + &"]".repeat(200))).is_err());
    }
}
