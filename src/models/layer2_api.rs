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
    pub layer2_voucher_id: String, // Hex string (64 chars), Pflichtfeld
    pub ds_tag: Option<String>,    // Hex string (64 chars), None bei 'init'
    
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

/// Datenstruktur für einen einzelnen Lock-Eintrag auf dem Layer 2.
/// Dient als kryptografischer Beweis für den Zustand eines Tags.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2LockEntry {
    pub layer2_voucher_id: String,
    #[serde(with = "crate::models::layer2_api::base58_32")]
    pub t_id: [u8; 32],
    #[serde(with = "crate::models::layer2_api::base58_32")]
    pub sender_ephemeral_pub: [u8; 32],
    #[serde(with = "crate::models::layer2_api::base58_32_opt", default)]
    pub receiver_ephemeral_pub_hash: Option<[u8; 32]>, 
    #[serde(with = "crate::models::layer2_api::base58_32_opt", default)]
    pub change_ephemeral_pub_hash: Option<[u8; 32]>,
    #[serde(with = "crate::models::layer2_api::base58_64")]
    pub layer2_signature: [u8; 64],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

/// Request: Abfragen des Zustands eines Gutscheins und Abgleich der Transaktionshistorie.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2StatusQuery {
    pub auth: L2AuthPayload,
    pub layer2_voucher_id: String,
    /// Der vollständige Base58-String des zu prüfenden Tags (Herausforderung).
    pub challenge_ds_tag: String,
    /// Exponentiell ausgedünnte Liste von Vorgänger-Präfixen (10 Zeichen Base58) zur LCA-Suche.
    pub locator_prefixes: Vec<String>,
}

/// Request: Batch-Upload von mehreren Transaktionen zur Synchronisation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2BatchLockRequest {
    pub auth: L2AuthPayload,
    pub layer2_voucher_id: String,
    pub locks: Vec<L2LockRequest>,
}

/// Response: Das Urteil des L2-Servers über den Zustand eines Tags oder der Kette.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum L2Verdict {
    /// Der Tag ist vergeben. Beinhaltet den vollständigen Beweis (LockEntry).
    Verified {
        lock_entry: L2LockEntry,
    },
    /// Der Server kennt diesen Tag noch nicht, hat aber einen gemeinsamen Ahnen gefunden.
    MissingLocks {
        /// Das 10-Zeichen Präfix der letzten gemeinsamen Transaktion.
        sync_point: String,
    },
    /// Der Gutschein (Voucher ID) ist dem Layer 2 System gänzlich unbekannt.
    UnknownVoucher,
    /// Veraltet/Fallback: Allgemeine Bestätigung (sollte durch Verified ersetzt werden).
    #[serde(rename = "Ok")]
    Ok {
        #[serde(with = "crate::models::layer2_api::base58_64")]
        signature: [u8; 64],
    },
    /// Die Anfrage wurde vom Server abgelehnt (z.B. ungültige Signatur).
    Rejected {
        reason: String,
    },
}

/// Umschlag für alle L2-Server-Antworten.
/// Garantiert die Authentizität des Servers durch eine Ed25519-Signatur.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2ResponseEnvelope {
    pub verdict: L2Verdict,
    #[serde(with = "crate::models::layer2_api::base58_64")]
    pub server_signature: [u8; 64],
}
