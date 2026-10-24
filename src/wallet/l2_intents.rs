//! Stage outbound intent on the same temporary wallet as its new L1 state.
use super::Wallet;
use crate::{Error,models::{voucher::Voucher,l2_intent::L2SendIntent},services::l2_gateway};
use rand_core::{OsRng,RngCore};
fn invalid(reason:&str)->Error { Error::Validation(crate::error::ValidationError::SecurityViolation(reason.into())) }
impl Wallet {
    pub(crate) fn stage_l2_send_intent(&mut self, local_id:&str, voucher:&Voucher, network:u8)->Result<L2SendIntent,Error> {
        if network > 1 { return Err(invalid("invalid intent network")); }
        if let Some(intent) = self.profile.l2_send_intents.get(local_id) {
            if intent.network != network { return Err(invalid("pending intent network cannot change")); }
            return Ok(intent.clone());
        }
        if self.profile.l2_send_intents.len() >= 256 { return Err(invalid("pending intent capacity exhausted")); }
        let transaction = voucher.transactions.last().ok_or_else(||invalid("intent transaction missing"))?;
        let root = voucher.transactions.first().ok_or_else(||invalid("intent root missing"))?;
        let voucher_id = l2_gateway::calculate_layer2_voucher_id(root)?;
        let mut auth = [0;32]; OsRng.try_fill_bytes(&mut auth).map_err(|_|invalid("intent entropy unavailable"))?;
        let mut request = l2_gateway::generate_lock_request(&voucher_id,transaction,&auth)?;
        request.causal_output = self.profile.l2_causal_outputs.get(&transaction.t_id).cloned();
        let request_bytes = serde_json::to_vec(&request)?;
        // Legacy foreign histories cannot be re-signed by this wallet. Preserve
        // their L1 portability; online admission stays qualified/pending.
        let mut chain_request_bytes = if voucher.transactions.len() <= 256 {
            l2_gateway::build_voucher_lock_chain_with_outputs(voucher,None,request.clone(),&self.profile.l2_causal_outputs)
                .ok().map(|chain|serde_json::to_vec(&chain)).transpose()?.unwrap_or_default()
        } else { Vec::new() };
        if chain_request_bytes.len() > 65_536 { chain_request_bytes.clear(); }
        let transaction_bytes = serde_json::to_vec(transaction)?;
        let used:usize = self.profile.l2_send_intents.values().map(|i|i.request_bytes.len()+i.transaction_bytes.len()+i.chain_request_bytes.len()).sum();
        if request_bytes.len()>65_536 || chain_request_bytes.len()>65_536 || transaction_bytes.len()>131_072
            || used.saturating_add(request_bytes.len()).saturating_add(chain_request_bytes.len()).saturating_add(transaction_bytes.len())>8*1024*1024 {
            return Err(invalid("pending intent byte budget exhausted"));
        }
        let root_valid_until_ms = crate::services::utils::parse_timestamp_ms(&voucher.valid_until)?;
        let parent = *blake3::hash(root.t_id.as_bytes()).as_bytes();
        let intent = L2SendIntent {local_instance_id:local_id.into(),request_bytes,chain_request_bytes,transaction_bytes,
            created_at_ms:request.created_at_ms,network,shard_id:u16::from_be_bytes([parent[0],parent[1]]),root_valid_until_ms,retained_original_observed:false,
            stored_challenge: None, terminal_resolution: None};
        self.profile.l2_send_intents.insert(local_id.into(),intent.clone());
        Ok(intent)
    }
}
