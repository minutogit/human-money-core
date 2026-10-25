//! Versioned L2 sidecars. L1 transactions, canonical serialization and SST tags
//! are not modified. The author signs blind output commitments separately.
use crate::{
    Error,
    models::voucher::Voucher,
    services::{crypto, l2_gateway, utils},
};
use humoco_proto::causal::CausalOutputProof;
fn invalid(reason: &str) -> Error {
    Error::Validation(crate::error::ValidationError::SecurityViolation(
        reason.into(),
    ))
}
/// Authenticates one transaction's outputs using its ORIGINAL ephemeral author.
/// This never re-signs or changes a Layer-1 transaction or its SST trap.
pub fn create_output_proof(
    voucher: &Voucher,
    key: impl Into<crypto::EphemeralKey>,
) -> Result<CausalOutputProof, Error> {
    let key = key.into();
    let tx = voucher
        .transactions
        .last()
        .ok_or_else(|| invalid("output transaction missing"))?;
    let root = voucher
        .transactions
        .first()
        .ok_or_else(|| invalid("output root missing"))?;
    let decode = |value: &str, field: &str| crypto::decode_bs58_fixed::<32>(value, field);
    let sender = decode(
        tx.sender_ephemeral_pub
            .as_deref()
            .ok_or_else(|| invalid("output author missing"))?,
        "sender_pubkey",
    )?;
    if sender != key.verifying_key().to_bytes() {
        return Err(invalid("output proof requires original author key"));
    }
    let state_hash = decode(
        &crypto::get_hash(utils::to_canonical_json(tx)?),
        "state_hash",
    )?;
    let mut proof = CausalOutputProof {
        version: 1,
        voucher_id: l2_gateway::calculate_layer2_voucher_id(root)?,
        transaction_id: decode(&tx.t_id, "transaction_id")?,
        state_hash,
        sender_pubkey: sender,
        receiver_pubkey_hash: tx
            .receiver_ephemeral_pub_hash
            .as_deref()
            .map(|hash| decode(hash, "receiver_pubkey_hash"))
            .transpose()?,
        change_pubkey_hash: tx
            .change_ephemeral_pub_hash
            .as_deref()
            .map(|hash| decode(hash, "change_pubkey_hash"))
            .transpose()?,
        root_valid_until_ms: utils::parse_timestamp_ms(&voucher.valid_until)?,
        is_root: tx.t_type == "init",
        signature: [0; 64],
    };
    proof.signature = key.sign(&proof.digest().map_err(invalid)?).to_bytes();
    Ok(proof)
}
/// A recipient checks every supplied sidecar against its actual full L1 deed.
/// A proof with an invented output/state hash is never enough to receive goods.
pub fn validate_output_proof(
    voucher: &Voucher,
    tx: &crate::models::voucher::Transaction,
    proof: &CausalOutputProof,
) -> Result<(), Error> {
    let root = voucher
        .transactions
        .first()
        .ok_or_else(|| invalid("output root missing"))?;
    let decode = |value: &str, field: &str| crypto::decode_bs58_fixed::<32>(value, field);
    if !proof.verify()
        || proof.voucher_id != l2_gateway::calculate_layer2_voucher_id(root)?
        || proof.transaction_id != decode(&tx.t_id, "transaction_id")?
        || proof.state_hash
            != decode(
                &crypto::get_hash(utils::to_canonical_json(tx)?),
                "state_hash",
            )?
        || proof.sender_pubkey
            != decode(
                tx.sender_ephemeral_pub
                    .as_deref()
                    .ok_or_else(|| invalid("output author missing"))?,
                "sender_pubkey",
            )?
        || proof.receiver_pubkey_hash
            != tx
                .receiver_ephemeral_pub_hash
                .as_deref()
                .map(|hash| decode(hash, "receiver_pubkey_hash"))
                .transpose()?
        || proof.change_pubkey_hash
            != tx
                .change_ephemeral_pub_hash
                .as_deref()
                .map(|hash| decode(hash, "change_pubkey_hash"))
                .transpose()?
        || proof.root_valid_until_ms != utils::parse_timestamp_ms(&voucher.valid_until)?
        || proof.is_root != (tx.t_type == "init")
    {
        return Err(invalid(
            "L2 output sidecar does not match the immutable L1 deed",
        ));
    }
    Ok(())
}
