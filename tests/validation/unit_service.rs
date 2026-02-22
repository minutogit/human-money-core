//! tests/validation/unit_service.rs
//!
//! Unit-Tests für die Validierung mittels der neuen CEL-basierten DynamicPolicyEngine.
//! Diese Tests ersetzen die alten, imperativen Rust-Tests und verifizieren, dass die
//! dynamischen Regeln (Regex, Listenfilterung, Custom Functions) exakt wie die 
//! zuvor gelöschten FieldGroupRules und ContentRules funktionieren.

use human_money_core::services::dynamic_policy_engine::DynamicPolicyEngine;
use serde_json::json;

#[test]
fn test_cel_content_rules_fixed_fields() {
    let voucher_json = json!({
        "nominal_value": { "unit": "EUR", "amount": "50.00" }
    });
    
    // Unit muss exakt "EUR" sein
    let expr = "Voucher.nominal_value.unit == 'EUR'";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr, &voucher_json, None), Ok(true));
    
    let expr_fail = "Voucher.nominal_value.unit == 'USD'";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr_fail, &voucher_json, None), Ok(false));
}

#[test]
fn test_cel_regex_patterns() {
    let voucher_json = json!({
        "voucher_standard": { "template": { "description": "INV-999888" } }
    });
    
    // cel-interpreter native regex Evaluierung (entspricht der alten Regex-Regel)
    let expr = "Voucher.voucher_standard.template.description.matches('^INV-[0-9]{6}$')";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr, &voucher_json, None), Ok(true));
}

#[test]
fn test_cel_field_group_rules_gender_counting() {
    // Ersetzt die komplexe validate_field_group_rules für die Bürgen-Diversität
    let voucher_json = json!({
        "signatures": [
            { "role": "creator" },
            { "role": "guarantor", "details": { "gender": "1" } },
            { "role": "guarantor", "details": { "gender": "1" } },
            { "role": "guarantor", "details": { "gender": "2" } }
        ]
    });
    
    // Regel: Es müssen exakt zwei männliche Bürgen (gender == '1') vorhanden sein.
    // Wir nutzen `has()` Makros, um Panic bei fehlenden Feldern zu vermeiden (Safe Navigation).
    let expr_male = "Voucher.signatures.filter(s, has(s.role) && s.role == 'guarantor' && has(s.details) && has(s.details.gender) && s.details.gender == '1').size() == 2";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr_male, &voucher_json, None), Ok(true));

    // Regel: Es muss exakt ein weiblicher Bürge (gender == '2') vorhanden sein.
    let expr_female = "Voucher.signatures.filter(s, has(s.role) && s.role == 'guarantor' && has(s.details) && has(s.details.gender) && s.details.gender == '2').size() == 1";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr_female, &voucher_json, None), Ok(true));
    
    // Negativ-Test: Keine drei weiblichen Bürgen
    let expr_fail = "Voucher.signatures.filter(s, has(s.role) && s.role == 'guarantor' && has(s.details) && has(s.details.gender) && s.details.gender == '2').size() == 3";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr_fail, &voucher_json, None), Ok(false));
}
