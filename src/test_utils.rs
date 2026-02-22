//! # src/test_utils.rs
//!
//! HINWEIS: Diese Datei wurde stark refaktorisiert, um die Mnemonic-Phrasen der Test-Akteure für die neuen APIs verfügbar zu machen.
//! Zentrale Hilfsfunktionen für alle Tests (intern und extern).

// HINWEIS: Absoluter Pfad zu externen Crates für mehr Robustheit
use bip39::Language;
use ed25519_dalek::{Signer, SigningKey};
use lazy_static::lazy_static;
use std::path::Path;
use std::path::PathBuf;
use toml;

// HINWEIS: Alle `human_money_core` Imports wurden zu `crate` geändert.
use crate::app_service::{AppService, ProfileInfo};
use crate::models::{
    conflict::{CanonicalMetadataStore, KnownFingerprints, OwnFingerprints, ProofStore},
    profile::{BundleMetadataStore, PublicProfile, UserProfile, VoucherStore},
    signature::DetachedSignature,
    voucher::{Address, Collateral, Transaction, ValueDefinition, VoucherSignature},
    voucher_standard_definition::{SignatureBlock, VoucherStandardDefinition},
};
use crate::services::{
    bundle_processor,
    crypto_utils::{
        self, create_user_id, generate_ed25519_keypair_for_tests, get_hash, get_hash_from_slices,
        sign_ed25519,
    },
    secure_container_manager, signature_manager,
    utils::to_canonical_json,
    voucher_manager::{NewVoucherData, create_transaction, create_voucher},
};
use crate::wallet::Wallet;
use crate::{
    UserIdentity, VoucherCoreError, VoucherInstance, VoucherStatus, models::voucher::Voucher,
};
use std::ops::Deref;

/// Bündelt alle Informationen eines Test-Benutzers.
/// Enthält die Mnemonic, die für `FileStorage::new` und `login` benötigt wird.
#[derive(Clone)]
pub struct TestUser {
    pub identity: UserIdentity,
    pub mnemonic: String,
    pub passphrase: Option<&'static str>,
    pub prefix: Option<&'static str>,
}

impl Deref for TestUser {
    type Target = UserIdentity;

    fn deref(&self) -> &Self::Target {
        &self.identity
    }
}

/// Erstellt eine `TestUser`-Instanz mit der langsamen, produktionssicheren Schlüsselableitung.
/// Notwendig für Tests, die Passphrasen oder die Recovery-Logik verifizieren.
pub fn user_from_mnemonic_slow(
    mnemonic: &str,
    passphrase: Option<&'static str>,
    prefix: Option<&'static str>,
) -> TestUser {
    // HINWEIS: Dies ist absichtlich die "langsame" Funktion, um sicherzustellen, dass die Tests
    // exakt dieselbe kryptographische Logik wie der Produktionscode verwenden.
    let (public_key, signing_key) = crypto_utils::derive_ed25519_keypair(mnemonic, passphrase)
        .expect("Failed to derive keypair from test mnemonic");

    let user_id = create_user_id(&public_key, prefix).unwrap();

    let identity = UserIdentity {
        signing_key,
        public_key,
        user_id,
    };

    TestUser {
        identity,
        mnemonic: mnemonic.to_string(),
        passphrase,
        prefix,
    }
}

/// Erstellt eine `TestUser`-Instanz mit der schnellen, nur für Tests gedachten Schlüsselableitung.
/// Hält die meisten Tests performant. Ignoriert Passphrasen.
fn user_from_mnemonic_fast(mnemonic: &str, prefix: Option<&'static str>) -> TestUser {
    let (public_key, signing_key) =
        crypto_utils::generate_ed25519_keypair_for_tests(Some(mnemonic));

    let user_id = create_user_id(&public_key, prefix).unwrap();

    let identity = UserIdentity {
        signing_key,
        public_key,
        user_id,
    };

    TestUser {
        identity,
        mnemonic: mnemonic.to_string(),
        passphrase: None, // Passphrase wird von der schnellen Methode nicht verwendet.
        prefix,
    }
}

/// Feste, deterministische Mnemonics für reproduzierbare Tests.
mod mnemonics {
    pub const ALICE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    pub const BOB: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    pub const CHARLIE: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    pub const DAVID: &str =
        "brother offer escape switch virtual school pet quiz point hurdle boil popular";
    pub const HACKER: &str =
        "clog cloud attitude around people thought sad will cute police feature junior";
    // HINZUGEFÜGT: Fehlende Mnemonics für Konsistenz
    pub const REPORTER: &str =
        "travel shell spy arctic clarify velvet wrist cigar jewel vintage life head";
}

/// Eine Struktur, die alle für Tests benötigten, einmalig erstellten Identitäten enthält.
#[allow(dead_code)]
pub struct TestActors {
    pub alice: TestUser,
    pub bob: TestUser,
    pub charlie: TestUser,
    pub david: TestUser,
    pub issuer: TestUser,
    pub hacker: TestUser,
    pub guarantor1: TestUser,
    pub guarantor2: TestUser,
    pub male_guarantor: TestUser,
    pub female_guarantor: TestUser,
    pub sender: TestUser,
    pub recipient1: TestUser,
    pub recipient2: TestUser,
    pub test_user: TestUser,
    pub victim: TestUser,
    pub reporter: TestUser,
}

lazy_static! {
    /// Ein deterministischer Herausgeber, der zum Signieren der Test-Standards verwendet wird.
    pub static ref TEST_ISSUER: TestUser = user_from_mnemonic_fast(
        "seek ethics foam novel hat faculty royal donkey burger frost advice visa",
        Some("issuer")
    );
}

lazy_static! {
    /// Initialisiert einmalig alle Akteure, sodass sie in allen Tests wiederverwendet werden können.
    pub static ref ACTORS: TestActors = TestActors {
        // Alice wird in Krypto-Tests verwendet und MUSS die langsame Ableitung nutzen
        alice: user_from_mnemonic_slow(mnemonics::ALICE, None, Some("al")),
        bob: user_from_mnemonic_fast(mnemonics::BOB, Some("bo")),
        charlie: user_from_mnemonic_fast(mnemonics::CHARLIE, Some("ch")),
        david: user_from_mnemonic_fast(mnemonics::DAVID, Some("da")),
        issuer: user_from_mnemonic_fast(mnemonics::BOB, Some("is")), // Re-use a known-good one
        guarantor1: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("g1")),
        guarantor2: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("g2")),
        male_guarantor: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("mg")),
        female_guarantor: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("fg")),
        sender: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("se")),
        recipient1: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("r1")),
        recipient2: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("r2")),
        victim: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("vi")),
        reporter: user_from_mnemonic_fast(mnemonics::REPORTER, Some("reporter")),

        // Diese Akteure MÜSSEN die langsame, produktionsgetreue Ableitung verwenden
        hacker: user_from_mnemonic_slow(mnemonics::HACKER, Some("wrong"), Some("ha")),
        test_user: user_from_mnemonic_slow(&generate_valid_mnemonic(), Some("pass"), Some("tu")),
    };

    /// Ein deterministischer Herausgeber, der zum Signieren der Test-Standards verwendet wird.

    /// Lädt den Minuto-Standard und signiert ihn zur Laufzeit für die Tests.
    pub static ref MINUTO_STANDARD: (VoucherStandardDefinition, String) = {
        let issuer = &TEST_ISSUER;
        let toml_str = include_str!("../voucher_standards/minuto_v1/standard.toml");

        let mut standard: VoucherStandardDefinition = toml::from_str(toml_str)
            .expect("Failed to parse Minuto TOML template for tests");

        standard.signature = None;
        let canonical_json_for_signing = to_canonical_json(&standard)
            .expect("Failed to create canonical JSON for Minuto standard");
        let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

        let signature = sign_ed25519(&issuer.identity.signing_key, hash_to_sign.as_bytes());
        let signature_block = SignatureBlock {
            issuer_id: issuer.identity.user_id.clone(),
            signature: bs58::encode(signature.to_bytes()).into_string(),
        };
        standard.signature = Some(signature_block);
        let canonical_json_immutable = to_canonical_json(&standard.immutable).unwrap();
        let logic_hash = get_hash(canonical_json_immutable.as_bytes());
        (standard, logic_hash)
    };

    /// Lädt den Silber-Standard und signiert ihn zur Laufzeit für die Tests.
    pub static ref SILVER_STANDARD: (VoucherStandardDefinition, String) = {
        let issuer = &TEST_ISSUER;
        let toml_str = include_str!("../voucher_standards/silver_v1/standard.toml");

        let mut standard: VoucherStandardDefinition = toml::from_str(toml_str)
            .expect("Failed to parse Silver TOML template for tests");

        standard.signature = None;
        let canonical_json = to_canonical_json(&standard).unwrap();
        let hash = get_hash(canonical_json.as_bytes());
        let signature = sign_ed25519(&issuer.identity.signing_key, hash.as_bytes());
        standard.signature = Some(SignatureBlock { issuer_id: issuer.identity.user_id.clone(), signature: bs58::encode(signature.to_bytes()).into_string() });
        let canonical_json_immutable = to_canonical_json(&standard.immutable).unwrap();
        let logic_hash = get_hash(canonical_json_immutable.as_bytes());
        (standard, logic_hash)
    };

    /// Lädt den `required_signatures`-Test-Standard und signiert ihn zur Laufzeit.
    pub static ref REQUIRED_SIG_STANDARD: (VoucherStandardDefinition, String) = {
        let issuer_for_signing = &TEST_ISSUER; // Dieser signiert nur die Standard-Datei selbst
        // HINWEIS: Pfad wurde angepasst, um von `src/` aus zu funktionieren.
        let toml_str = include_str!("../tests/test_data/standards/standard_required_signatures.toml");

        // --- DYNAMISCHE ID-INJEKTION (Ihre vorgeschlagene Lösung) ---
        // 1. Parse als generischer TOML-Wert, nicht als finale Struktur
        let mut standard_value: toml::Value = toml::from_str(toml_str)
            .expect("Failed to parse Required Sig TOML as toml::Value");

        // 2. Hole die korrekten, zur Laufzeit generierten IDs aus der ACTORS-Struktur
        let correct_issuer_id = ACTORS.issuer.user_id.clone();
        let correct_charlie_id = ACTORS.charlie.user_id.clone();

        // 3. Durchsuche die TOML-Struktur und ersetze die IDs
        if let Some(toml::Value::Table(validation)) = standard_value.get_mut("validation") {
            if let Some(toml::Value::Array(sig_rules)) = validation.get_mut("required_signatures") {
                for rule_value in sig_rules.iter_mut() {
                    if let Some(rule) = rule_value.as_table_mut() {                        // Finde die spezifische Regel, die wir patchen wollen
                        if let Some(toml::Value::String(desc)) = rule.get("role_description") {
                            if desc == "Official stamp from the authority" {
                                // 4. Ersetze die Platzhalter durch die echten, korrekten IDs
                                let new_allowed_ids = toml::Value::Array(vec![
                                    toml::Value::String(correct_issuer_id.clone()),
                                    toml::Value::String(correct_charlie_id.clone()),
                                ]);
                                rule.insert("allowed_signer_ids".to_string(), new_allowed_ids);
                                break; // Regel gefunden und gepatcht
                            }
                        }
                    }
                }
            }
        }
        // --- ENDE DYNAMISCHE ID-INJEKTION ---

        // 5. Konvertiere den *modifizierten* TOML-Wert in die finale Struktur
        let mut standard: VoucherStandardDefinition = standard_value.try_into()
            .expect("Failed to deserialize modified TOML value into VoucherStandardDefinition");

        standard.signature = None;
        let canonical_json_for_signing = to_canonical_json(&standard)
            .expect("Failed to create canonical JSON for Required Sig standard");
        let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

        let signature = sign_ed25519(&issuer_for_signing.identity.signing_key, hash_to_sign.as_bytes());
        let signature_block = SignatureBlock {
            issuer_id: issuer_for_signing.identity.user_id.clone(),
            signature: bs58::encode(signature.to_bytes()).into_string(),
        };
        standard.signature = Some(signature_block);
        let canonical_json_immutable = to_canonical_json(&standard.immutable).unwrap();
        let logic_hash = get_hash(canonical_json_immutable.as_bytes());
        (standard, logic_hash)
    };
}

#[allow(dead_code)]
pub fn generate_valid_mnemonic() -> String {
    crypto_utils::generate_mnemonic(12, Language::English)
        .expect("Test mnemonic generation should not fail")
}

#[allow(dead_code)]
pub fn generate_signed_standard_toml(template_path: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut absolute_path = PathBuf::from(manifest_dir);
    absolute_path.push(template_path);

    let issuer = &crate::test_utils::TEST_ISSUER;
    let toml_str = std::fs::read_to_string(&absolute_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read TOML template at '{:?}': {}",
            absolute_path, e
        )
    });

    let mut standard: VoucherStandardDefinition =
        toml::from_str(&toml_str).expect("Failed to parse TOML template for signing");

    standard.signature = None;
    let canonical_json_for_signing =
        to_canonical_json(&standard).expect("Failed to create canonical JSON for standard");
    let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

    let signature = sign_ed25519(&issuer.identity.signing_key, hash_to_sign.as_bytes());
    let signature_block = SignatureBlock {
        issuer_id: issuer.identity.user_id.clone(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
    };
    standard.signature = Some(signature_block);

    toml::to_string(&standard).expect("Failed to serialize standard back to TOML string")
}

#[allow(dead_code)]
pub fn create_custom_standard(
    base_standard: &VoucherStandardDefinition,
    modifier: impl FnOnce(&mut VoucherStandardDefinition),
) -> (VoucherStandardDefinition, String) {
    let mut standard = base_standard.clone();
    modifier(&mut standard);

    standard.signature = None;
    let canonical_json = to_canonical_json(&standard).unwrap();
    let hash = get_hash(canonical_json.as_bytes());

    let signature = crate::test_utils::TEST_ISSUER
        .identity
        .signing_key
        .sign(hash.as_bytes());

    standard.signature = Some(crate::models::voucher_standard_definition::SignatureBlock {
        issuer_id: crate::test_utils::TEST_ISSUER.identity.user_id.clone(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
    });

    let canonical_json_immutable = to_canonical_json(&standard.immutable).unwrap();
    let logic_hash = get_hash(canonical_json_immutable.as_bytes());

    (standard, logic_hash)
}

#[allow(dead_code)]
pub fn setup_voucher_with_one_tx() -> (
    &'static VoucherStandardDefinition,
    String,
    &'static UserIdentity,
    &'static UserIdentity,
    Voucher,
    crate::services::voucher_manager::TransactionSecrets,
) {
    let (standard, standard_hash) = (
        &crate::test_utils::SILVER_STANDARD.0,
        &crate::test_utils::SILVER_STANDARD.1,
    );
    let creator = &crate::test_utils::ACTORS.alice.identity;
    let recipient = &crate::test_utils::ACTORS.bob.identity;

    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(creator.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "100.0000".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };

    let initial_voucher = create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &creator.signing_key,
        "en",
    )
    .unwrap();

    // Für die ERSTE Transaktion (Init -> Tx1) ist der Anchor der Hash des User-IDs (Permanent Key).
    // KORREKTUR: Der Anchor ist der "holder"-Key, der aus dem Nonce abgeleitet wurde.
    let holder_key = derive_holder_key(&initial_voucher, &creator.signing_key);
    let (voucher_after_tx1, secrets) = create_transaction(
        &initial_voucher,
        standard,
        &creator.user_id,
        &creator.signing_key, // Permanent Key (ID/Trap)
        &holder_key,          // Ephemeral Key (Anchor Resolution)
        &recipient.user_id,
        "40.0000",
    )
    .unwrap();

    (
        standard,
        standard_hash.to_string(),
        creator,
        recipient,
        voucher_after_tx1,
        secrets,
    )
}

#[allow(dead_code)]
pub fn setup_in_memory_wallet(identity: &UserIdentity) -> Wallet {
    let profile = UserProfile {
        user_id: identity.user_id.clone(),
        first_name: None,
        last_name: None,
        organization: None,
        community: None,
        address: None,
        gender: None,
        email: None,
        phone: None,
        coordinates: None,
        url: None,
        service_offer: None,
        needs: None,
        l2_server_pubkey: None,
    };
    Wallet {
        profile,
        voucher_store: VoucherStore::default(),
        bundle_meta_store: BundleMetadataStore::default(),
        known_fingerprints: KnownFingerprints::default(),
        own_fingerprints: OwnFingerprints::default(),
        proof_store: ProofStore::default(),
        fingerprint_metadata: CanonicalMetadataStore::default(),
    }
}

#[allow(dead_code)]
pub fn create_test_wallet(
    seed_phrase_extra: &str,
) -> Result<(Wallet, UserIdentity), VoucherCoreError> {
    let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some(seed_phrase_extra));
    let user_id = create_user_id(&public_key, Some("test"))
        .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

    let identity = UserIdentity {
        signing_key,
        public_key,
        user_id: user_id.clone(),
    };

    let profile = UserProfile {
        user_id,
        first_name: None,
        last_name: None,
        organization: None,
        community: None,
        address: None,
        gender: None,
        email: None,
        phone: None,
        coordinates: None,
        url: None,
        service_offer: None,
        needs: None,
        l2_server_pubkey: None,
    };

    let wallet = Wallet {
        profile,
        voucher_store: VoucherStore::default(),
        bundle_meta_store: BundleMetadataStore::default(),
        known_fingerprints: KnownFingerprints::default(),
        own_fingerprints: OwnFingerprints::default(),
        proof_store: ProofStore::default(),
        fingerprint_metadata: CanonicalMetadataStore::default(),
    };

    Ok((wallet, identity))
}

#[allow(dead_code)]
pub fn add_voucher_to_wallet(
    wallet: &mut Wallet,
    identity: &UserIdentity,
    amount: &str,
    standard: &VoucherStandardDefinition,
    with_valid_guarantors: bool,
) -> Result<String, VoucherCoreError> {
    let creator_info = PublicProfile {
        id: Some(identity.user_id.clone()),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        address: Some(Address::default()),
        ..Default::default()
    };

    let nominal_value_info = ValueDefinition {
        amount: amount.to_string(),
        ..Default::default()
    };

    let new_voucher_data = NewVoucherData {
        creator_profile: creator_info,
        nominal_value: nominal_value_info,
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };

    let standard_hash = get_hash(to_canonical_json(&standard.immutable)?);

    let mut voucher = create_voucher_for_manipulation(
        new_voucher_data,
        standard,
        &standard_hash,
        &identity.signing_key,
        "en",
    );

    if with_valid_guarantors {
        let sig_data1 = create_guarantor_signature_data(
            &crate::test_utils::ACTORS.guarantor1.identity,
            "1",
            &voucher.voucher_id,
        );
        let sig_data2 = create_guarantor_signature_data(
            &crate::test_utils::ACTORS.guarantor2.identity,
            "2",
            &voucher.voucher_id,
        );

        // --- KORREKTUR (Fix E0505): ---
        // 1. Extrahiere die 'details' durch Borgen und sofortiges Klonen.
        //    Dadurch wird der Borrow sofort beendet.
        let details1 = match &sig_data1 {
            DetachedSignature::Signature(s) => s.details.clone(),
        };
        let details2 = match &sig_data2 {
            DetachedSignature::Signature(s) => s.details.clone(),
        };

        // Extrahiere init_t_id
        let init_t_id = &voucher.transactions[0].t_id;

        // 2. Jetzt können 'sig_data1' und 'sig_data2' sicher verschoben (moved) werden,
        //    da keine aktiven Borrows mehr existieren.
        let signed_sig1 = signature_manager::complete_and_sign_detached_signature(
            sig_data1, // MOVE
            &crate::test_utils::ACTORS.guarantor1.identity,
            details1,            // Verwende die geklonten Details
            &voucher.voucher_id, // Pass the voucher_id
            init_t_id,           // Pass init_t_id
        )?;
        let signed_sig2 = signature_manager::complete_and_sign_detached_signature(
            sig_data2, // MOVE
            &crate::test_utils::ACTORS.guarantor2.identity,
            details2,            // Verwende die geklonten Details
            &voucher.voucher_id, // Pass the voucher_id
            init_t_id,           // Pass init_t_id
        )?;

        // HINWEIS: Die 'if let' sind jetzt redundant, da DetachedSignature nur eine Variante hat (oder wir matchen oben).
        // Wir verwenden `let` und ignorieren die Warnung oder strukturieren um.
        let DetachedSignature::Signature(s1) = signed_sig1;
        let DetachedSignature::Signature(s2) = signed_sig2;
        voucher.signatures.push(s1);
        voucher.signatures.push(s2);
    }

    // P2PKH Support: Re-Derive Holder Seed
    let holder_key = derive_holder_key(&voucher, &identity.signing_key);
    let _holder_seed = bs58::encode(holder_key.to_bytes()).into_string();

    let local_id = Wallet::calculate_local_instance_id(&voucher, &identity.user_id)?;
    wallet.voucher_store.vouchers.insert(
        local_id.clone(),
        VoucherInstance {
            voucher: voucher.clone(),
            status: VoucherStatus::Active,
            local_instance_id: local_id.clone(),
            // current_secret_seed: Some(holder_seed), // Removed in stateless refactor
        },
    );

    Ok(local_id.clone())
}

/// Eine zentrale Hilfsfunktion, um einen `AppService` zu instanziieren
/// und direkt ein Profil darin zu erstellen.
///
/// Diese Funktion kapselt den korrekten, mehrstufigen Prozess des Profil-Managements
/// und gibt alle notwendigen Informationen für nachfolgende Testschritte zurück.
///
/// # Returns
/// Ein Tupel `(AppService, ProfileInfo)`, wobei:
/// - `AppService` die entsperrte Service-Instanz ist.
/// - `ProfileInfo` die Metadaten des erstellten Profils enthält (inkl. `folder_name`).
#[allow(dead_code)]
pub fn setup_service_with_profile(
    base_path: &Path,
    user: &TestUser,
    profile_name: &str,
    password: &str,
) -> (AppService, ProfileInfo) {
    let mut service =
        AppService::new(base_path).expect("Failed to create AppService in test setup");

    service
        .create_profile(
            profile_name,
            &user.mnemonic,
            user.passphrase,
            user.prefix,
            password,
        )
        .unwrap_or_else(|e| {
            panic!(
                "Failed to create profile '{}' in test setup: {}",
                profile_name, e
            )
        });

    let profile_info = service
        .list_profiles()
        .expect("Failed to list profiles after creation")
        .into_iter()
        .find(|p| p.profile_name == profile_name)
        .expect("Could not find freshly created profile in index");

    (service, profile_info)
}

/// Erstellt eine Transaktion und extrahiert automatisch den neuen Seed für die nächste Transaktion.
/// Dies simuliert das Verhalten des Wallets in Tests.
pub fn create_transaction_with_auto_decrypt(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
    sender_id: &str,
    sender_permanent_key: &SigningKey,
    sender_ephemeral_key: &SigningKey,
    recipient_id: &str,
    _recipient_permanent_key: &SigningKey, // Nicht mehr benötigt, aber wir lassen es im Signature, um bestehende Calls nicht zu brechen?
    amount: &str,
) -> Result<(Voucher, SigningKey), VoucherCoreError> {
    let (new_voucher, secrets) = create_transaction(
        voucher,
        standard,
        sender_id,
        sender_permanent_key,
        sender_ephemeral_key,
        recipient_id,
        amount,
    )?;

    // Use returned secret directly
    let seed_bytes = bs58::decode(secrets.recipient_seed)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(format!("Invalid seed base58: {}", e)))?;

    let seed_arr: [u8; 32] = seed_bytes.try_into().expect("Seed must be 32 bytes");
    let next_key = SigningKey::from_bytes(&seed_arr);

    Ok((new_voucher, next_key))
}

pub fn create_guarantor_signature_data(
    guarantor_identity: &UserIdentity,
    gender: &str,
    voucher_id: &str, // Add voucher_id parameter
) -> DetachedSignature {
    let data = VoucherSignature {
        voucher_id: voucher_id.to_string(), // Use the provided voucher_id
        signer_id: guarantor_identity.user_id.clone(),
        signature_id: String::new(),
        signature: String::new(),
        signature_time: String::new(),
        role: "guarantor".to_string(),
        details: Some(crate::models::profile::PublicProfile {
            id: None,
            first_name: Some("Guarantor".to_string()),
            last_name: Some("Test".to_string()),
            gender: Some(gender.to_string()),
            ..Default::default()
        }),
        ..Default::default() // Stellt sicher, dass alle optionalen Felder initialisiert sind
    };
    // KORREKTUR: Verwende den vereinheitlichten Enum-Typ
    DetachedSignature::Signature(data)
}

#[allow(dead_code)]
pub fn create_additional_signature_data(
    signer_identity: &UserIdentity,
    description: &str,
) -> DetachedSignature {
    let data = crate::models::voucher::VoucherSignature {
        signature_id: String::new(),
        signer_id: signer_identity.user_id.clone(),
        signature: String::new(),
        signature_time: String::new(),
        role: description.to_string(), // description wird zu role
        ..Default::default() // Stellt sicher, dass alle optionalen Felder (firstName, etc.) None sind
    };
    DetachedSignature::Signature(data)
}

/// Creates a signature with proper voucher_id for testing purposes
#[allow(dead_code)]
pub fn create_additional_signature_data_with_voucher_id(
    signer_identity: &UserIdentity,
    description: &str,
    voucher_id: &str,
) -> DetachedSignature {
    let data = crate::models::voucher::VoucherSignature {
        voucher_id: voucher_id.to_string(), // Add the voucher_id
        signature_id: String::new(),
        signer_id: signer_identity.user_id.clone(),
        signature: String::new(),
        signature_time: String::new(),
        role: description.to_string(), // description wird zu role
        ..Default::default() // Stellt sicher, dass alle optionalen Felder (firstName, etc.) None sind
    };
    DetachedSignature::Signature(data)
}

#[allow(dead_code)]
pub fn debug_open_container(
    container_bytes: &[u8],
    recipient_identity: &UserIdentity,
) -> Result<Voucher, VoucherCoreError> {
    let container: crate::models::secure_container::SecureContainer =
        serde_json::from_slice(container_bytes)?;
    let payload = secure_container_manager::open_secure_container(&container, recipient_identity)?;
    let voucher: Voucher = serde_json::from_slice(&payload)?;
    Ok(voucher)
}

#[allow(dead_code)]
pub fn create_minuto_voucher_data(creator_profile: PublicProfile) -> NewVoucherData {
    NewVoucherData {
        validity_duration: Some("P4Y".to_string()),
        non_redeemable_test_voucher: true,
        nominal_value: ValueDefinition {
            unit: "".to_string(),
            amount: "60".to_string(),
            abbreviation: Some("".to_string()),
            description: Some("Qualitative Leistung".to_string()),
        },
        collateral: Some(Collateral {
            value: ValueDefinition {
                unit: "".to_string(),
                amount: "".to_string(),
                abbreviation: Some("".to_string()),
                description: Some("".to_string()),
            },
            collateral_type: Some("".to_string()),
            redeem_condition: Some("".to_string()),
        }),
        creator_profile,
    }
}

#[allow(dead_code)]
pub fn create_voucher_for_manipulation(
    data: NewVoucherData,
    standard: &VoucherStandardDefinition,
    standard_hash: &str,
    signing_key: &ed25519_dalek::SigningKey,
    lang_preference: &str,
) -> Voucher {
    let creation_date_str = crate::services::utils::get_current_timestamp();
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&creation_date_str).unwrap();
    let duration_str = data.validity_duration.as_deref().unwrap_or_else(|| {
        panic!(
            "Test voucher creation requires a validity_duration. Voucher details: creator='{}', amount='{}'",
            data.creator_profile.id.as_ref().unwrap_or(&"N/A".to_string()), data.nominal_value.amount
        )
    });
    let mut valid_until_dt =
        crate::services::voucher_manager::add_iso8601_duration(creation_dt.into(), duration_str)
            .expect("Failed to calculate validity in test helper");

    if let Some(rule) = &standard.mutable.app_config.round_up_validity_to {
        if rule == "end_of_year" {
            use chrono::{Datelike, TimeZone};
            let rounded_date =
                chrono::NaiveDate::from_ymd_opt(valid_until_dt.year(), 12, 31).unwrap();
            let rounded_time = chrono::NaiveTime::from_hms_micro_opt(23, 59, 59, 999_999).unwrap();
            valid_until_dt = chrono::Utc.from_utc_datetime(&rounded_date.and_time(rounded_time));
        }
    }

    let valid_until = valid_until_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let mut nonce_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();

    let description_template = crate::services::standard_manager::get_localized_text(
        &standard.mutable.i18n.descriptions,
        lang_preference,
    )
    .unwrap_or("");
    let final_description = description_template.replace("{{amount}}", &data.nominal_value.amount);

    let mut final_nominal_value = data.nominal_value;
    final_nominal_value.unit = standard.immutable.blueprint.unit.clone();
    final_nominal_value.abbreviation = Some(standard.immutable.identity.abbreviation.clone());

    let final_collateral = if !standard.immutable.blueprint.collateral_type.is_empty() {
        Some(Collateral {
            value: ValueDefinition {
                unit: data
                    .collateral
                    .as_ref()
                    .map_or(String::new(), |c| c.value.unit.clone()),
                amount: data
                    .collateral
                    .as_ref()
                    .map_or(String::new(), |c| c.value.amount.clone()),
                abbreviation: data
                    .collateral
                    .as_ref()
                    .and_then(|c| c.value.abbreviation.clone()),
                description: data
                    .collateral
                    .as_ref()
                    .and_then(|c| c.value.description.clone()),
            },
            collateral_type: Some(standard.immutable.blueprint.collateral_type.clone()),
            redeem_condition: None,
        })
    } else {
        None
    };

    let mut voucher = Voucher {
        voucher_standard: crate::models::voucher::VoucherStandard {
            name: standard.immutable.identity.name.clone(),
            uuid: standard.immutable.identity.uuid.clone(),
            standard_definition_hash: standard_hash.to_string(),
            template: crate::models::voucher::VoucherTemplateData {
                description: final_description,
                primary_redemption_type: "goods_or_services".to_string(),
                allow_partial_transfers: standard.immutable.features.allow_partial_transfers,
                issuance_minimum_validity_duration: standard.immutable.issuance.issuance_minimum_validity_duration.clone(),
                footnote: crate::services::standard_manager::get_localized_text(&standard.mutable.i18n.footnotes, lang_preference).unwrap_or("").to_string(),
            },
        },
        voucher_id: "".to_string(),
        voucher_nonce,
        creation_date: creation_date_str.clone(),
        valid_until: valid_until.clone(),
        non_redeemable_test_voucher: false,
        nominal_value: final_nominal_value,
        collateral: final_collateral,
        creator_profile: data.creator_profile,
        transactions: vec![],
        signatures: vec![],
    };

    // Logik von create_voucher (Schritt 3) replizieren:
    // 1. Hash des Gutscheins *ohne* ID und Signaturen
    let voucher_json = to_canonical_json(&voucher).unwrap();
    let voucher_hash = crypto_utils::get_hash(voucher_json);
    voucher.voucher_id = voucher_hash.clone();

    // 4. Init-Transaktion erstellen (MIT P2PKH ANKER & L2 SIGNATUR)

    // A. Keys ableiten
    let prefix = voucher
        .creator_profile
        .id
        .as_ref()
        .and_then(|id| id.split(':').next())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let (genesis_secret, genesis_public) = crypto_utils::derive_ephemeral_key_pair(
        signing_key,
        &nonce_bytes,
        "genesis",
        Some(&prefix),
    )
    .expect("Failed to derive genesis key");
    let genesis_pub_str = bs58::encode(genesis_public.to_bytes()).into_string();

    let (_, holder_public) =
        crypto_utils::derive_ephemeral_key_pair(signing_key, &nonce_bytes, "holder", Some(&prefix))
            .expect("Failed to derive holder key");
    let holder_anchor_hash = crypto_utils::get_hash(holder_public.to_bytes());

    let prev_hash = {
        let v_id_bytes = bs58::decode(&voucher.voucher_id)
            .into_vec()
            .expect("Invalid voucher_id");
        let v_nonce_bytes = bs58::decode(&voucher.voucher_nonce)
            .into_vec()
            .expect("Invalid voucher_nonce");
        get_hash_from_slices(&[&v_id_bytes, &v_nonce_bytes])
    };

    let mut init_tx = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type: "init".to_string(),
        t_time: creation_date_str.clone(),
        sender_id: Some(voucher.creator_profile.id.as_ref().unwrap().clone()),
        recipient_id: voucher.creator_profile.id.as_ref().unwrap().clone(),
        amount: voucher.nominal_value.amount.clone(),
        sender_remaining_amount: None,
        sender_identity_signature: None,
        receiver_ephemeral_pub_hash: Some(holder_anchor_hash),
        sender_ephemeral_pub: Some(genesis_pub_str.clone()),
        change_ephemeral_pub_hash: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: Some(valid_until.clone()),
    };

    let tx_json_for_id = crate::to_canonical_json(&init_tx).unwrap();
    let init_t_id = crate::crypto_utils::get_hash(tx_json_for_id);
    init_tx.t_id = init_t_id.clone();

    // 2. Ersteller-Signatur (role: "creator") erstellen (JETZT GEBUNDEN)
    let mut creator_sig_obj = VoucherSignature {
        voucher_id: voucher_hash.clone(),
        signature_id: "".to_string(),
        signer_id: voucher.creator_profile.id.as_ref().unwrap().clone(),
        signature: "".to_string(),
        signature_time: creation_date_str.clone(),
        role: "creator".to_string(),
        details: None,
    };

    creator_sig_obj.signature_id = get_hash_from_slices(&[
        to_canonical_json(&creator_sig_obj).unwrap().as_bytes(),
        init_t_id.as_bytes(),
    ]);

    let digital_signature =
        crypto_utils::sign_ed25519(signing_key, creator_sig_obj.signature_id.as_bytes());
    creator_sig_obj.signature = bs58::encode(digital_signature.to_bytes()).into_string();

    // 3. Signatur dem Array hinzufügen
    voucher.signatures.push(creator_sig_obj);

    // B. Finale ID & L2 Signatur
    let v_id = crate::services::l2_gateway::calculate_layer2_voucher_id(&init_tx)
        .expect("Failed to calculate v_id");
    voucher.transactions.push(resign_transaction_ext(
        init_tx,
        signing_key,
        &v_id,
        Some(&genesis_secret),
    ));

    voucher
}

#[allow(dead_code)]
pub fn create_guarantor_signature_with_time(
    voucher: &Voucher,
    guarantor_identity: &UserIdentity,
    guarantor_first_name: &str,
    role: &str,
    guarantor_gender: &str,
    signature_time: &str,
) -> VoucherSignature {
    let mut signature_data = VoucherSignature {
        voucher_id: voucher.voucher_id.clone(),
        signature_id: "".to_string(),
        signer_id: guarantor_identity.user_id.clone(),
        signature_time: signature_time.to_string(),
        role: role.to_string(), // KORREKTUR: Verwende die übergebene Rolle
        details: Some(crate::models::profile::PublicProfile {
            id: None,
            first_name: Some(guarantor_first_name.to_string()),
            last_name: Some("Guarantor".to_string()),
            gender: Some(guarantor_gender.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut data_for_id_hash = signature_data.clone();
    data_for_id_hash.signature_id = "".to_string();
    data_for_id_hash.signature = "".to_string();

    let init_t_id = &voucher.transactions[0].t_id;
    signature_data.signature_id = get_hash_from_slices(&[
        to_canonical_json(&data_for_id_hash).unwrap().as_bytes(),
        init_t_id.as_bytes(),
    ]);

    let digital_signature = sign_ed25519(
        &guarantor_identity.signing_key,
        signature_data.signature_id.as_bytes(),
    );
    signature_data.signature = bs58::encode(digital_signature.to_bytes()).into_string();
    signature_data
}

#[allow(dead_code)]
pub fn create_guarantor_signature(
    voucher: &Voucher,
    guarantor_identity: &UserIdentity,
    guarantor_first_name: &str,
    role: &str,             // KORREKTUR: Fehlender Parameter 'role'
    guarantor_gender: &str, // KORREKTUR: 'gender' ist jetzt der 4. Parameter
) -> VoucherSignature {
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
    let signature_time = (creation_dt + chrono::Duration::days(1)).to_rfc3339();
    let mut signature_data = VoucherSignature {
        voucher_id: voucher.voucher_id.clone(), // Use the voucher's ID
        signature_id: "".to_string(),
        signer_id: guarantor_identity.user_id.clone(),
        signature_time: signature_time.to_string(),
        role: role.to_string(), // KORREKTUR: Verwende die übergebene Rolle
        details: Some(crate::models::profile::PublicProfile {
            id: None,
            first_name: Some(guarantor_first_name.to_string()),
            last_name: Some("Guarantor".to_string()),
            gender: Some(guarantor_gender.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut data_for_id_hash = signature_data.clone();
    data_for_id_hash.signature_id = "".to_string();
    data_for_id_hash.signature = "".to_string();

    let init_t_id = &voucher.transactions[0].t_id;
    signature_data.signature_id = get_hash_from_slices(&[
        to_canonical_json(&data_for_id_hash).unwrap().as_bytes(),
        init_t_id.as_bytes(),
    ]);

    let digital_signature = sign_ed25519(
        &guarantor_identity.signing_key,
        signature_data.signature_id.as_bytes(),
    );
    signature_data.signature = bs58::encode(digital_signature.to_bytes()).into_string();
    signature_data
}

#[allow(dead_code)]
pub fn create_male_guarantor_signature(voucher: &Voucher) -> VoucherSignature {
    create_guarantor_signature(
        voucher,
        &crate::test_utils::ACTORS.male_guarantor.identity,
        "Martin",
        "guarantor", // KORREKTUR: Fehlendes 'role'-Argument
        "1",         // 'gender' ist jetzt das 5. Argument
    )
}

#[allow(dead_code)]
pub fn create_female_guarantor_signature(voucher: &Voucher) -> VoucherSignature {
    // Korrigiert E0412
    create_guarantor_signature(
        voucher,
        &crate::test_utils::ACTORS.female_guarantor.identity,
        "Frida",
        "guarantor", // KORREKTUR: Fehlendes 'role'-Argument
        "2",         // 'gender' ist jetzt das 5. Argument
    )
}

#[allow(dead_code)]
pub fn resign_transaction(
    tx: Transaction,
    signer_key: &ed25519_dalek::SigningKey,
    v_id: &str,
) -> Transaction {
    resign_transaction_ext(tx, signer_key, v_id, None)
}

#[allow(dead_code)]
pub fn resign_transaction_ext(
    mut tx: Transaction,
    signer_key: &ed25519_dalek::SigningKey,
    v_id: &str,
    l2_signer_key: Option<&ed25519_dalek::SigningKey>,
) -> Transaction {
    tx.t_id = "".to_string();
    tx.layer2_signature = None;
    tx.sender_identity_signature = None;

    // Die t_id muss auf dem kanonischen JSON der gesamten Tx basieren (inkl. ephemeral fields)
    tx.t_id = crypto_utils::get_hash(to_canonical_json(&tx).unwrap());

    // 1. Layer 2 Signature: Signiert den vollen Payload
    let t_id_raw = bs58::decode(&tx.t_id).into_vec().unwrap();

    let sender_pub_raw = tx
        .sender_ephemeral_pub
        .as_ref()
        .map(|s| bs58::decode(s).into_vec().unwrap_or_default())
        .unwrap_or_default();
    let receiver_hash_raw = tx
        .receiver_ephemeral_pub_hash
        .as_ref()
        .map(|h| bs58::decode(h).into_vec().unwrap());
    let change_hash_raw = tx
        .change_ephemeral_pub_hash
        .as_ref()
        .map(|h| bs58::decode(h).into_vec().unwrap());

    let challenge_ds_tag = if tx.t_type == "init" {
        tx.t_id.clone()
    } else {
        tx.trap_data
            .as_ref()
            .map(|td| td.ds_tag.clone())
            .unwrap_or_else(|| tx.t_id.clone())
    };

    let to_32_bytes = |vec: Vec<u8>| -> [u8; 32] { vec[..32].try_into().unwrap() };

    let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
        &challenge_ds_tag,
        v_id,
        &to_32_bytes(t_id_raw.clone()),
        &to_32_bytes(sender_pub_raw),
        receiver_hash_raw
            .as_ref()
            .map(|v| to_32_bytes(v.clone()))
            .as_ref(),
        change_hash_raw
            .as_ref()
            .map(|v| to_32_bytes(v.clone()))
            .as_ref(),
        tx.deletable_at.as_deref(),
    );

    let proof_key = l2_signer_key.unwrap_or(signer_key);
    let l2_sig = crypto_utils::sign_ed25519(proof_key, &payload_hash);
    tx.layer2_signature = Some(bs58::encode(l2_sig.to_bytes()).into_string());

    // 2. Sender Identity Signature (L1): Signiert t_id (raw) mit Sender Permanent Key
    if tx.sender_id.is_some() {
        let identity_sig = crypto_utils::sign_ed25519(signer_key, &t_id_raw);
        tx.sender_identity_signature = Some(bs58::encode(identity_sig.to_bytes()).into_string());
    }

    tx
}

#[allow(dead_code)]
pub fn create_test_bundle(
    sender_identity: &UserIdentity,
    vouchers: Vec<Voucher>,
    recipient_id: &str,
    message: Option<&str>,
) -> Result<Vec<u8>, VoucherCoreError> {
    let result = bundle_processor::create_and_encrypt_bundle(
        sender_identity,
        vouchers,
        recipient_id,
        message.map(|s| s.to_string()),
        // HINZUGEFÜGT: Fehlende Argumente mit Standardwerten, um alte Tests nicht zu brechen
        Vec::new(),
        std::collections::HashMap::new(),
        None, // sender_profile_name
    )?;
    Ok(result.0)
}

#[cfg(test)]
mod tests {
    use crate::services::utils::{get_current_timestamp, get_timestamp};
    use chrono::{DateTime, Datelike, Timelike, Utc};
    use regex::Regex;

    // Helper function to parse the timestamp string and check basic format
    fn parse_and_validate_format(timestamp_str: &str) -> Result<DateTime<Utc>, String> {
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$").unwrap();
        if !re.is_match(timestamp_str) {
            return Err(format!(
                "Timestamp '{}' does not match expected format YYYY-MM-DDTHH:MM:SS.ffffffZ",
                timestamp_str
            ));
        }

        DateTime::parse_from_rfc3339(timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| format!("Failed to parse timestamp '{}': {}", timestamp_str, e))
    }

    #[test]
    fn test_get_current_timestamp_format() {
        let timestamp = get_current_timestamp();
        println!("Current Timestamp: {}", timestamp);
        assert!(parse_and_validate_format(&timestamp).is_ok());
    }

    #[test]
    fn test_get_timestamp_add_years() {
        let years_to_add = 2;
        let now = Utc::now();
        let expected_year = now.year() + years_to_add;

        let timestamp = get_timestamp(years_to_add, false);
        println!("Timestamp (+{} years): {}", years_to_add, timestamp);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(
            parsed_dt.year(),
            expected_year,
            "Year should be incremented correctly"
        );
    }

    #[test]
    fn test_get_timestamp_end_of_current_year() {
        let now = Utc::now();
        let current_year = now.year();

        let timestamp = get_timestamp(0, true);
        println!(
            "Timestamp (End of Current Year {}): {}",
            current_year, timestamp
        );
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(
            parsed_dt.year(),
            current_year,
            "Year should be the current year"
        );
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        assert_eq!(
            parsed_dt.nanosecond(),
            999_999_000,
            "Nanoseconds should indicate the last microsecond"
        );
    }

    #[test]
    fn test_get_timestamp_end_of_future_year() {
        let years_to_add = 3;
        let now = Utc::now();
        let expected_year = now.year() + years_to_add;

        let timestamp = get_timestamp(years_to_add, true);
        println!(
            "Timestamp (End of Future Year {}): {}",
            expected_year, timestamp
        );
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(
            parsed_dt.year(),
            expected_year,
            "Year should be the future year"
        );
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        assert_eq!(
            parsed_dt.nanosecond(),
            999_999_000,
            "Nanoseconds should indicate the last microsecond"
        );
    }

    #[test]
    fn test_get_timestamp_end_of_leap_year() {
        let now = Utc::now();
        let mut years_to_add = 0;
        loop {
            let target_year = now.year() + years_to_add;
            if chrono::NaiveDate::from_ymd_opt(target_year, 2, 29).is_some() {
                break;
            }
            years_to_add += 1;
            if years_to_add > 4 {
                panic!("Could not find a leap year within 4 years for testing");
            }
        }

        let leap_year = now.year() + years_to_add;
        println!("Testing end_of_year for leap year: {}", leap_year);

        let timestamp = get_timestamp(years_to_add, true);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(
            parsed_dt.year(),
            leap_year,
            "Year should be the target leap year"
        );
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
    }

    #[test]
    fn test_get_timestamp_add_years_crossing_leap_day() {
        let now = Utc::now();
        let mut years_to_add = 0;
        loop {
            let target_year = now.year() + years_to_add;
            if chrono::NaiveDate::from_ymd_opt(target_year, 2, 29).is_some() {
                if years_to_add > 0 {
                    break;
                }
            }
            years_to_add += 1;
            if years_to_add > 4 {
                panic!("Could not find a future leap year within 4 years for testing");
            }
        }

        let target_leap_year = now.year() + years_to_add;
        println!("Testing add_years to reach leap year: {}", target_leap_year);

        let timestamp = get_timestamp(years_to_add, false);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(
            parsed_dt.year(),
            target_leap_year,
            "Year should be the target leap year"
        );
    }
}

// Helper to derive the holder key for Init transaction
// Helper to derive the holder key for Init transaction
pub fn derive_holder_key(
    voucher: &crate::models::voucher::Voucher,
    creator_signing_key: &ed25519_dalek::SigningKey,
) -> ed25519_dalek::SigningKey {
    let nonce_bytes = bs58::decode(&voucher.voucher_nonce).into_vec().unwrap();
    let nonce_arr: [u8; 16] = nonce_bytes.try_into().unwrap();

    let prefix = voucher
        .creator_profile
        .id
        .as_ref()
        .and_then(|id| id.split(':').next())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let (holder_key, _) = crate::services::crypto_utils::derive_ephemeral_key_pair(
        creator_signing_key,
        &nonce_arr,
        "holder",
        Some(&prefix),
    )
    .unwrap();
    holder_key
}
