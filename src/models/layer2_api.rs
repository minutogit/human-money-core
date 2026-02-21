use serde::{Deserialize, Serialize};

pub mod base58_32 {
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&bs58::encode(data).into_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
        vec.try_into()
            .map_err(|_| de::Error::custom("Length mismatch, expected 32 bytes"))
    }
}

pub mod base58_32_vec {
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(data.len()))?;
        for e in data {
            seq.serialize_element(&bs58::encode(e).into_string())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s_vec = Vec::<String>::deserialize(deserializer)?;
        let mut res = Vec::with_capacity(s_vec.len());
        for s in s_vec {
            let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
            let arr: [u8; 32] = vec
                .try_into()
                .map_err(|_| de::Error::custom("Length mismatch, expected 32 bytes"))?;
            res.push(arr);
        }
        Ok(res)
    }
}

pub mod base58_32_opt {
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(d) => serializer.serialize_str(&bs58::encode(d).into_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => {
                let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
                let arr: [u8; 32] = vec
                    .try_into()
                    .map_err(|_| de::Error::custom("Length mismatch, expected 32 bytes"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

pub mod base58_64 {
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&bs58::encode(data).into_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
        vec.try_into()
            .map_err(|_| de::Error::custom("Length mismatch, expected 64 bytes"))
    }
}

pub mod base58_64_opt {
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(d) => serializer.serialize_str(&bs58::encode(d).into_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => {
                let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
                let arr: [u8; 64] = vec
                    .try_into()
                    .map_err(|_| de::Error::custom("Length mismatch, expected 64 bytes"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

/// Vorbereitung für die spätere Anti-Spam/Sybil Zugangskontrolle.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2AuthPayload {
    #[serde(with = "crate::models::layer2_api::base58_32")]
    pub ephemeral_pubkey: [u8; 32],      // Der temporäre Sender-Key
    #[serde(with = "crate::models::layer2_api::base58_64_opt")]
    pub auth_signature: Option<[u8; 64]>, // Platzhalter für die spätere Challenge-Signatur
}

/// Request: Verankern eines Gutscheins (Genesis) oder einer Transaktion
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2LockRequest {
    pub auth: L2AuthPayload,
    #[serde(with = "crate::models::layer2_api::base58_32")]
    pub ds_tag: [u8; 32],           // Deterministischer Hash des Inputs (oder Voucher-ID bei Genesis)
    #[serde(with = "crate::models::layer2_api::base58_32")]
    pub transaction_hash: [u8; 32], // Der Hash der neuen Transaktion (t_id)
    pub is_genesis: bool,
    #[serde(with = "crate::models::layer2_api::base58_32")]
    pub sender_ephemeral_pub: [u8; 32],

    
    #[serde(with = "crate::models::layer2_api::base58_32_opt", default)]
    pub receiver_ephemeral_pub_hash: Option<[u8; 32]>, 

    #[serde(with = "crate::models::layer2_api::base58_32_opt", default)]
    pub change_ephemeral_pub_hash: Option<[u8; 32]>,
    
    #[serde(with = "crate::models::layer2_api::base58_64")]
    pub layer2_signature: [u8; 64], 

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>, // Only required when is_genesis = true
}

/// Request: Abfragen, ob eine Kette sicher ist
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2StatusQuery {
    pub auth: L2AuthPayload,
    #[serde(with = "crate::models::layer2_api::base58_32_vec")]
    pub target_ds_tags: Vec<[u8; 32]>, // Liste der zu prüfenden Anker
}

/// Response: Das Urteil des L2-Servers
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum L2Verdict {
    Ok {
        #[serde(with = "crate::models::layer2_api::base58_64")]
        signature: [u8; 64],
    },
    Verified {
        #[serde(with = "crate::models::layer2_api::base58_64")]
        signature: [u8; 64],
    },
    DoubleSpend {
        #[serde(with = "crate::models::layer2_api::base58_32")]
        conflicting_t_id: [u8; 32],
        #[serde(with = "crate::models::layer2_api::base58_64")]
        proof_signature: [u8; 64],
        // Weitere Beweisdaten können hier später hinzugefügt werden
    },
    ConflictFound { // Added for the query endpoint
        #[serde(with = "crate::models::layer2_api::base58_32")]
        conflicting_t_id: [u8; 32],
    },
}
