use crate::error::{ValidationError, VoucherCoreError};
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;

pub fn validate_transaction_types(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    let allowed = &standard.immutable.features.allowed_t_types;
    for tx in &voucher.transactions {
        if !tx.t_type.is_empty() && !allowed.contains(&tx.t_type) {
            return Err(ValidationError::TransactionTypeNotAllowed {
                t_type: tx.t_type.clone(),
                allowed: allowed.clone(),
            }
            .into());
        }
    }
    Ok(())
}

pub fn get_failing_custom_rules(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<Vec<String>, VoucherCoreError> {
    let mut failing = Vec::new();
    if !standard.immutable.custom_rules.is_empty() {
        let voucher_json = serde_json::to_value(voucher)?;
        let tx_json = voucher.transactions.last().map(|tx| serde_json::to_value(tx).unwrap());

        for (rule_name, rule) in &standard.immutable.custom_rules {
            match crate::services::dynamic_policy_engine::DynamicPolicyEngine::evaluate_rule(
                &rule.expression,
                &voucher_json,
                tx_json.as_ref(),
            ) {
                Ok(true) => {}
                Ok(false) => failing.push(rule.message.clone()),
                Err(e) => failing.push(format!("CEL Error in {}: {:?}", rule_name, e)),
            }
        }
    }
    Ok(failing)
}
