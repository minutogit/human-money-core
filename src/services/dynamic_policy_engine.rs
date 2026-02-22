use cel_interpreter::{Context, Program, Value};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use rust_decimal::Decimal;
use std::str::FromStr;

/// Result enum for policy evaluation
#[derive(Debug, PartialEq)]
pub enum PolicyEngineError {
    CompilationError(String),
    EvaluationError(String),
    TypeMismatch(String),
}

/// The Dynamic Policy Engine evaluates CEL rules against a given state
pub struct DynamicPolicyEngine;

impl DynamicPolicyEngine {
    /// Evaluates a single CEL expression against the provided voucher and transaction JSON states.
    pub fn evaluate_rule(
        expression: &str,
        voucher_state: &JsonValue,
        transaction_state: Option<&JsonValue>,
    ) -> Result<bool, PolicyEngineError> {
        let program = Program::compile(expression)
            .map_err(|e| PolicyEngineError::CompilationError(format!("{:?}", e)))?;

        let mut context = Context::default();

        let v_val = Self::json_to_cel(voucher_state)?;
        let _ = context.add_variable("Voucher", v_val);

        if let Some(t_state) = transaction_state {
            let t_val = Self::json_to_cel(t_state)?;
            let _ = context.add_variable("Transaction", t_val);
        }

        // Custom Functions registrieren
        Self::register_custom_functions(&mut context);

        let result = program
            .execute(&context)
            .map_err(|e| PolicyEngineError::EvaluationError(format!("{:?}", e)))?;

        match result {
            Value::Bool(b) => Ok(b),
            _ => Err(PolicyEngineError::TypeMismatch(
                "Expression did not evaluate to a boolean".into(),
            )),
        }
    }

    /// Recursively converts `serde_json::Value` to `cel_interpreter::Value`
    fn json_to_cel(json: &JsonValue) -> Result<Value, PolicyEngineError> {
        match json {
            JsonValue::Null => Ok(Value::Null),
            JsonValue::Bool(b) => Ok(Value::Bool(*b)),
            JsonValue::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(Value::Int(i))
                } else if let Some(u) = n.as_u64() {
                    // CEL natively supports UInt (u64) for large positive limits
                    Ok(Value::UInt(u))
                } else if let Some(f) = n.as_f64() {
                    Ok(Value::Float(f))
                } else {
                    Err(PolicyEngineError::TypeMismatch(
                        "Unsupported number type".into(),
                    ))
                }
            }
            JsonValue::String(s) => Ok(Value::String(s.clone().into())),
            JsonValue::Array(arr) => {
                let mut cel_arr = Vec::new();
                for item in arr {
                    cel_arr.push(Self::json_to_cel(item)?);
                }
                Ok(Value::List(cel_arr.into()))
            }
            JsonValue::Object(obj) => {
                let mut cel_map: HashMap<String, Value> = HashMap::new();
                for (k, v) in obj {
                    cel_map.insert(k.clone(), Self::json_to_cel(v)?);
                }
                Ok(Value::Map(cel_map.into()))
            }
        }
    }

    /// Registers the custom functions needed for checking domains (like Decimal checks)
    fn register_custom_functions(context: &mut Context) {
        // Implementierung der in .dev/Business Rules Engines.md spezifizierten Custom Function
        context.add_function("check_decimals", |amount_str: std::sync::Arc<String>, max_places: i64| -> bool {
            if let Ok(dec) = Decimal::from_str(&amount_str) {
                return dec.scale() <= max_places as u32;
            }
            false
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_evaluate_dynamic_rules_cel_engine_core() {
        let voucher_json = json!({
            "nominal_value": {
                "amount": "50.000",
                "unit": "Minuto"
            },
            "signatures": [
                { "role": "creator" },
                { "role": "guarantor", "details": { "gender": "1" } },
                { "role": "guarantor", "details": { "gender": "2" } }
            ]
        });

        // Basis Objekt-Zugriff
        assert_eq!(
            DynamicPolicyEngine::evaluate_rule("Voucher.nominal_value.unit == 'Minuto'", &voucher_json, None),
            Ok(true)
        );

        // Test der injizierten Custom Function check_decimals
        // 50.000 hat 3 Nachkommastellen
        assert_eq!(
            DynamicPolicyEngine::evaluate_rule("check_decimals(Voucher.nominal_value.amount, 3)", &voucher_json, None),
            Ok(true)
        );
        assert_eq!(
            DynamicPolicyEngine::evaluate_rule("check_decimals(Voucher.nominal_value.amount, 2)", &voucher_json, None),
            Ok(false) // Schlägt korrekt fehl, da 3 > 2
        );
    }
}
