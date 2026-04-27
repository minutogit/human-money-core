use std::{env, fs, path::PathBuf};

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bip39::{Language, Mnemonic};
use chrono::DateTime;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
const X25519_MULTICODEC_PREFIX: [u8; 2] = [0xec, 0x01];

#[test]
#[ignore = "requires WOT_SPEC_DIR or sibling ../wot-spec checkout"]
fn wot_phase_1_identity_trust_and_hmc_vectors() -> Result<()> {
    let phase1 = read_vector("phase-1-interop.json")?;
    let identity = &phase1["identity"];

    let mnemonic = Mnemonic::parse_in_normalized(
        Language::English,
        string_at(identity, "mnemonic")?,
    )?;
    let bip39_seed = mnemonic.to_seed("");
    assert_eq!(hex::encode(bip39_seed), string_at(identity, "bip39_seed_hex")?);

    let ed25519_seed = hkdf_sha256(&bip39_seed, b"wot/identity/ed25519/v1")?;
    assert_eq!(hex::encode(ed25519_seed), string_at(identity, "ed25519_seed_hex")?);

    let signing_key = SigningKey::from_bytes(&ed25519_seed);
    let ed25519_public = signing_key.verifying_key().to_bytes();
    assert_eq!(hex::encode(ed25519_public), string_at(identity, "ed25519_public_hex")?);
    assert_eq!(ed25519_did(&ed25519_public), string_at(identity, "did")?);
    assert_eq!(format!("{}#sig-0", ed25519_did(&ed25519_public)), string_at(identity, "kid")?);

    let x25519_seed = hkdf_sha256(&bip39_seed, b"wot/encryption/x25519/v1")?;
    assert_eq!(hex::encode(x25519_seed), string_at(identity, "x25519_seed_hex")?);

    let x25519_secret = StaticSecret::from(x25519_seed);
    let x25519_public = X25519PublicKey::from(&x25519_secret).to_bytes();
    assert_eq!(hex::encode(x25519_public), string_at(identity, "x25519_public_hex")?);
    assert_eq!(URL_SAFE_NO_PAD.encode(x25519_public), string_at(identity, "x25519_public_b64")?);
    assert_eq!(x25519_multibase(&x25519_public), string_at(identity, "x25519_public_multibase")?);

    let did_document = &phase1["did_resolution"]["did_document"];
    assert_eq!(sha256_jcs_hex(did_document)?, string_at(&phase1["did_resolution"], "jcs_sha256")?);

    let attestation = &phase1["attestation_vc_jws"];
    let attestation_jws = string_at(attestation, "jws")?;
    let parts = jws_parts(attestation_jws)?;
    let (header, payload) = verify_jws(attestation_jws)?;
    assert_eq!(header, attestation["header"]);
    assert_eq!(payload, attestation["payload"]);
    assert_eq!(format!("{}.{}", parts[0], parts[1]), string_at(attestation, "signing_input")?);
    assert_eq!(parts[2], string_at(attestation, "signature_b64")?);
    assert_eq!(sha256_jcs_hex(&payload)?, string_at(attestation, "payload_jcs_sha256")?);
    assert_eq!(payload["issuer"], payload["iss"]);
    assert_eq!(payload["credentialSubject"]["id"], payload["sub"]);

    let ecies = &phase1["ecies"];
    let ephemeral_private = array32(hex_bytes(string_at(ecies, "ephemeral_private_hex")?)?)?;
    let recipient_public = X25519PublicKey::from(array32(URL_SAFE_NO_PAD.decode(string_at(ecies, "recipient_x25519_public_b64")?)?)?);
    let ephemeral_secret = StaticSecret::from(ephemeral_private);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret).to_bytes();
    assert_eq!(URL_SAFE_NO_PAD.encode(ephemeral_public), string_at(ecies, "ephemeral_public_b64")?);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public).to_bytes();
    assert_eq!(hex::encode(shared_secret), string_at(ecies, "shared_secret_hex")?);
    let ecies_aes_key = hkdf_sha256(&shared_secret, string_at(ecies, "hkdf_info")?.as_bytes())?;
    assert_eq!(hex::encode(ecies_aes_key), string_at(ecies, "aes_key_hex")?);
    let ecies_nonce = hex_bytes(string_at(ecies, "nonce_hex")?)?;
    let ecies_ciphertext = aes256_gcm_encrypt(&ecies_aes_key, &ecies_nonce, string_at(ecies, "plaintext")?.as_bytes())?;
    assert_eq!(URL_SAFE_NO_PAD.encode(&ecies_ciphertext), string_at(ecies, "ciphertext_b64")?);
    let ecies_plaintext = aes256_gcm_decrypt(&ecies_aes_key, &ecies_nonce, &ecies_ciphertext)?;
    assert_eq!(String::from_utf8(ecies_plaintext)?, string_at(ecies, "plaintext")?);

    let log_encryption = &phase1["log_payload_encryption"];
    let log_nonce_digest = Sha256::digest(format!(
        "{}|{}",
        string_at(log_encryption, "device_id")?,
        integer_at(log_encryption, "seq")?,
    ).as_bytes());
    let log_nonce = &log_nonce_digest[..12];
    assert_eq!(hex::encode(log_nonce), string_at(log_encryption, "nonce_hex")?);
    let space_content_key = hex_bytes(string_at(log_encryption, "space_content_key_hex")?)?;
    let log_ciphertext_tag = aes256_gcm_encrypt(&space_content_key, log_nonce, string_at(log_encryption, "plaintext")?.as_bytes())?;
    assert_eq!(hex::encode(&log_ciphertext_tag), string_at(log_encryption, "ciphertext_tag_hex")?);
    let mut log_blob = log_nonce.to_vec();
    log_blob.extend_from_slice(&log_ciphertext_tag);
    assert_eq!(URL_SAFE_NO_PAD.encode(&log_blob), string_at(log_encryption, "blob_b64")?);
    let log_plaintext = aes256_gcm_decrypt(&space_content_key, log_nonce, &log_ciphertext_tag)?;
    assert_eq!(String::from_utf8(log_plaintext)?, string_at(log_encryption, "plaintext")?);

    let log_entry = &phase1["log_entry_jws"];
    let (_log_header, log_payload) = verify_jws(string_at(log_entry, "jws")?)?;
    assert_eq!(log_payload, log_entry["payload"]);

    let capability = &phase1["space_capability_jws"];
    let capability_public_key = array32(hex_bytes(string_at(capability, "verification_key_hex")?)?)?;
    assert_eq!(ed25519_multibase(&capability_public_key), string_at(capability, "verification_key_multibase")?);
    let (_capability_header, capability_payload) = verify_jws_with_public_key(
        string_at(capability, "jws")?,
        &capability_public_key,
    )?;
    assert_eq!(capability_payload, capability["payload"]);

    let admin = &phase1["admin_key_derivation"];
    let admin_seed = hkdf_sha256(&bip39_seed, string_at(admin, "hkdf_info")?.as_bytes())?;
    assert_eq!(hex::encode(admin_seed), string_at(admin, "ed25519_seed_hex")?);
    let admin_public_key = SigningKey::from_bytes(&admin_seed).verifying_key().to_bytes();
    assert_eq!(hex::encode(admin_public_key), string_at(admin, "ed25519_public_hex")?);
    assert_eq!(ed25519_did(&admin_public_key), string_at(admin, "did")?);

    let personal = &phase1["personal_doc"];
    let personal_key = hkdf_sha256(&bip39_seed, string_at(personal, "hkdf_info")?.as_bytes())?;
    assert_eq!(hex::encode(personal_key), string_at(personal, "key_hex")?);
    assert_eq!(personal_doc_id(&personal_key), string_at(personal, "doc_id")?);

    let sd_jwt = &phase1["sd_jwt_vc_trust_list"];
    let disclosure_encoded = encode_jcs_base64url(&sd_jwt["disclosure"])?;
    let disclosure_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure_encoded.as_bytes()));
    assert_eq!(disclosure_digest, string_at(sd_jwt, "disclosure_digest")?);

    let issuer_signed_jwt = string_at(sd_jwt, "issuer_signed_jwt")?;
    let (_sd_header, sd_payload) = verify_jws(issuer_signed_jwt)?;
    assert_eq!(sd_payload["_sd_alg"], "sha-256");
    assert_eq!(format!("{}~{}~", issuer_signed_jwt, disclosure_encoded), string_at(sd_jwt, "sd_jwt_compact")?);

    Ok(())
}

#[test]
#[ignore = "requires WOT_SPEC_DIR or sibling ../wot-spec checkout"]
fn wot_device_delegation_vectors() -> Result<()> {
    let vector = read_vector("device-delegation.json")?;

    let binding = &vector["device_key_binding_jws"];
    let (binding_header, binding_payload) = verify_jws(string_at(binding, "jws")?)?;
    assert_eq!(binding_header, binding["header"]);
    assert_eq!(binding_payload, binding["payload"]);
    assert_eq!(sha256_jcs_hex(&binding_payload)?, string_at(binding, "payload_jcs_sha256")?);

    verify_delegated_attestation_bundle(
        &vector["delegated_attestation_bundle"]["bundle"],
        "sign-attestation",
    )?;

    for (name, invalid_case) in object_at(&vector["invalid_cases"])?.iter() {
        let result = verify_delegated_attestation_bundle(&invalid_case["bundle"], "sign-attestation");
        assert!(result.is_err(), "invalid case {name} should be rejected");
    }

    Ok(())
}

fn verify_delegated_attestation_bundle(bundle: &Value, required_capability: &str) -> Result<()> {
    ensure!(string_at(bundle, "type")? == "wot-delegated-attestation-bundle/v1", "unexpected bundle type");

    let (attestation_header, attestation_payload) = verify_jws(string_at(bundle, "attestationJws")?)?;
    let (binding_header, binding_payload) = verify_jws(string_at(bundle, "deviceKeyBindingJws")?)?;

    let identity_did = did_or_kid_to_did(string_at(&binding_header, "kid")?);
    ensure!(string_at(&binding_payload, "iss")? == identity_did, "binding issuer does not match header kid DID");

    let attestation_kid = string_at(&attestation_header, "kid")?;
    ensure!(string_at(&binding_payload, "deviceKid")? == attestation_kid, "deviceKid does not match attestation kid");
    ensure!(string_at(&binding_payload, "sub")? == attestation_kid, "binding sub does not match attestation kid");

    let device_public_key = did_key_public_key_bytes(attestation_kid)?;
    ensure!(
        string_at(&binding_payload, "devicePublicKeyMultibase")? == ed25519_multibase(&device_public_key),
        "devicePublicKeyMultibase does not match deviceKid",
    );

    let capabilities = array_at(&binding_payload["capabilities"])?;
    ensure!(
        capabilities.iter().any(|capability| capability.as_str() == Some(required_capability)),
        "required capability missing",
    );

    ensure!(attestation_payload["issuer"] == binding_payload["iss"], "attestation issuer mismatch");
    ensure!(attestation_payload["iss"] == binding_payload["iss"], "attestation iss mismatch");

    let iat = attestation_payload["iat"].as_i64().context("attestation iat must be an integer")?;
    let valid_from = parse_rfc3339_unix(string_at(&binding_payload, "validFrom")?)?;
    let valid_until = parse_rfc3339_unix(string_at(&binding_payload, "validUntil")?)?;
    ensure!(valid_from <= iat && iat <= valid_until, "attestation iat outside binding validity window");

    Ok(())
}

fn read_vector(name: &str) -> Result<Value> {
    let root = env::var("WOT_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("../wot-spec"));
    let path = root.join("test-vectors").join(name);
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read vector {}", path.display()))?;
    Ok(serde_json::from_str(&content)?)
}

fn hkdf_sha256(input_key_material: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, input_key_material);
    let mut output = [0u8; 32];
    hkdf.expand(info, &mut output).map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(output)
}

fn verify_jws(jws: &str) -> Result<(Value, Value)> {
    let parts = jws_parts(jws)?;
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    let public_key_bytes = did_key_public_key_bytes(string_at(&header, "kid")?)?;
    verify_jws_with_public_key(jws, &public_key_bytes)
}

fn verify_jws_with_public_key(jws: &str, public_key_bytes: &[u8; 32]) -> Result<(Value, Value)> {
    let parts = jws_parts(jws)?;
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    let payload: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2])?;
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| anyhow::anyhow!("expected 64-byte Ed25519 signature"))?;
    let signature = Signature::from_bytes(&signature_array);
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)?;
    verifying_key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)?;
    Ok((header, payload))
}

fn jws_parts(jws: &str) -> Result<Vec<&str>> {
    let parts = jws.split('.').collect::<Vec<_>>();
    ensure!(parts.len() == 3, "expected compact JWS with three parts");
    Ok(parts)
}

fn sha256_jcs_hex(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(human_money_core::to_canonical_json(value)?.as_bytes())))
}

fn encode_jcs_base64url(value: &Value) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(human_money_core::to_canonical_json(value)?.as_bytes()))
}

fn ed25519_did(public_key: &[u8; 32]) -> String {
    format!("did:key:{}", ed25519_multibase(public_key))
}

fn ed25519_multibase(public_key: &[u8; 32]) -> String {
    prefixed_multibase(&ED25519_MULTICODEC_PREFIX, public_key)
}

fn x25519_multibase(public_key: &[u8; 32]) -> String {
    prefixed_multibase(&X25519_MULTICODEC_PREFIX, public_key)
}

fn prefixed_multibase(prefix: &[u8; 2], public_key: &[u8; 32]) -> String {
    let mut encoded = Vec::with_capacity(prefix.len() + public_key.len());
    encoded.extend_from_slice(prefix);
    encoded.extend_from_slice(public_key);
    format!("z{}", bs58::encode(encoded).into_string())
}

fn personal_doc_id(key: &[u8; 32]) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&key[0..4]),
        hex::encode(&key[4..6]),
        hex::encode(&key[6..8]),
        hex::encode(&key[8..10]),
        hex::encode(&key[10..16]),
    )
}

fn aes256_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("AES-256-GCM encryption failed"))
}

fn aes256_gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("AES-256-GCM decryption failed"))
}

fn did_key_public_key_bytes(did_or_kid: &str) -> Result<[u8; 32]> {
    let did = did_or_kid_to_did(did_or_kid);
    let multibase = did.strip_prefix("did:key:").context("expected did:key")?;
    let encoded = multibase.strip_prefix('z').context("expected base58btc multibase")?;
    let decoded = bs58::decode(encoded).into_vec()?;
    ensure!(decoded.len() == 34, "expected multicodec prefix plus 32-byte public key");
    ensure!(decoded[0] == ED25519_MULTICODEC_PREFIX[0] && decoded[1] == ED25519_MULTICODEC_PREFIX[1], "expected Ed25519 multicodec prefix");
    Ok(decoded[2..].try_into().expect("validated length"))
}

fn did_or_kid_to_did(did_or_kid: &str) -> &str {
    did_or_kid.split('#').next().unwrap_or(did_or_kid)
}

fn parse_rfc3339_unix(value: &str) -> Result<i64> {
    Ok(DateTime::parse_from_rfc3339(value)?.timestamp())
}

fn hex_bytes(value: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(value)?)
}

fn array32(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

fn string_at<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().with_context(|| format!("expected string at {key}"))
}

fn integer_at(value: &Value, key: &str) -> Result<i64> {
    value[key].as_i64().with_context(|| format!("expected integer at {key}"))
}

fn array_at(value: &Value) -> Result<&Vec<Value>> {
    value.as_array().context("expected array")
}

fn object_at(value: &Value) -> Result<&serde_json::Map<String, Value>> {
    value.as_object().context("expected object")
}
