//! tests/validation/unit_service.rs
//!
//! Unit tests for validation using the new CEL-based DynamicPolicyEngine.
//! These tests replace the old, imperative Rust tests and verify that
//! dynamic rules (regex, list filtering, custom functions) work exactly like the
//! previously removed FieldGroupRules and ContentRules.

use human_money_core::services::dynamic_policy_engine::DynamicPolicyEngine;
use serde_json::json;

#[test]
fn test_cel_content_rules_fixed_fields() {
    let voucher_json = json!({
        "nominal_value": { "unit": "EUR", "amount": "50.00" }
    });
    
    // Unit must be exactly "EUR"
    let expr = "Voucher.nominal_value.unit == 'EUR'";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr, &voucher_json, None), Ok(true));
    
    let expr_fail = "Voucher.nominal_value.unit == 'USD'";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr_fail, &voucher_json, None), Ok(false));
}

#[test]
fn test_cel_regex_patterns() {
    let voucher_json = json!({
        "creator": { "first_name": "Alice" }
    });
    
    // cel-interpreter native regex evaluation
    let expr = "Voucher.creator.first_name.matches('^[A-Z][a-z]+$')";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr, &voucher_json, None), Ok(true));
}

#[test]
fn test_cel_field_group_rules_gender_counting() {
    // Replaces the complex validate_field_group_rules for guarantor diversity
    let voucher_json = json!({
        "signatures": [
            { "role": "creator" },
            { "role": "guarantor", "details": { "gender": "1" } },
            { "role": "guarantor", "details": { "gender": "1" } },
            { "role": "guarantor", "details": { "gender": "2" } }
        ]
    });
    
    // Rule: Exactly two male guarantors (gender == '1') must be present.
    // We use `has()` macros to avoid panic on missing fields (Safe Navigation).
    let expr_male = "Voucher.signatures.filter(s, has(s.role) && s.role == 'guarantor' && has(s.details) && has(s.details.gender) && s.details.gender == '1').size() == 2";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr_male, &voucher_json, None), Ok(true));

    // Rule: Exactly one female guarantor (gender == '2') must be present.
    let expr_female = "Voucher.signatures.filter(s, has(s.role) && s.role == 'guarantor' && has(s.details) && has(s.details.gender) && s.details.gender == '2').size() == 1";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr_female, &voucher_json, None), Ok(true));
    
    // Negative test: Not three female guarantors
    let expr_fail = "Voucher.signatures.filter(s, has(s.role) && s.role == 'guarantor' && has(s.details) && has(s.details.gender) && s.details.gender == '2').size() == 3";
    assert_eq!(DynamicPolicyEngine::evaluate_rule(expr_fail, &voucher_json, None), Ok(false));
}

