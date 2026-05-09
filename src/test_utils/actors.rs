use crate::services::mnemonic::MnemonicLanguage;
use crate::services::crypto_utils::{self, create_user_id};
use crate::UserIdentity;
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
    let (public_key, signing_key) = crypto_utils::derive_ed25519_keypair(mnemonic, passphrase, MnemonicLanguage::English)
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
pub fn user_from_mnemonic_fast(mnemonic: &str, prefix: Option<&'static str>) -> TestUser {
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
        passphrase: None,
        prefix,
    }
}

/// Feste, deterministische Mnemonics für reproduzierbare Tests.
pub mod mnemonics {
    pub const ALICE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    pub const BOB: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    pub const CHARLIE: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    pub const DAVID: &str =
        "brother offer escape switch virtual school pet quiz point hurdle boil popular";
    pub const HACKER: &str =
        "clog cloud attitude around people thought sad will cute police feature junior";
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

#[allow(dead_code)]
pub fn init_test_issuer() -> TestUser {
    user_from_mnemonic_fast(
        "seek ethics foam novel hat faculty royal donkey burger frost advice visa",
        Some("issuer"),
    )
}

#[allow(dead_code)]
pub fn init_actors() -> TestActors {
    TestActors {
        alice: user_from_mnemonic_slow(mnemonics::ALICE, None, Some("al")),
        bob: user_from_mnemonic_fast(mnemonics::BOB, Some("bo")),
        charlie: user_from_mnemonic_fast(mnemonics::CHARLIE, Some("ch")),
        david: user_from_mnemonic_fast(mnemonics::DAVID, Some("da")),
        issuer: user_from_mnemonic_fast(mnemonics::BOB, Some("is")),
        guarantor1: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("g1")),
        guarantor2: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("g2")),
        male_guarantor: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("mg")),
        female_guarantor: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("fg")),
        sender: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("se")),
        recipient1: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("r1")),
        recipient2: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("r2")),
        victim: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("vi")),
        reporter: user_from_mnemonic_fast(mnemonics::REPORTER, Some("reporter")),
        hacker: user_from_mnemonic_slow(mnemonics::HACKER, Some("wrong"), Some("ha")),
        test_user: user_from_mnemonic_slow(&generate_valid_mnemonic(), Some("pass"), Some("tu")),
    }
}

#[allow(dead_code)]
pub fn generate_valid_mnemonic() -> String {
    crypto_utils::generate_mnemonic(12, MnemonicLanguage::English)
        .expect("Test mnemonic generation should not fail")
}
