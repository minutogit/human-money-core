use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use human_money_core::services::trap_manager::{derive_m, generate_trap};
use human_money_core::services::voucher_validation::validate_voucher_against_standard;
use human_money_core::test_utils::setup_voucher_with_one_tx;
use rand::rngs::OsRng;

#[test]
fn test_hkdf_determinism() {
    let prev_hash = "prev_hash_123456789";
    let secret = b"super_secret_sender_key_32_bytes_long!!";
    let prefix = "minuto:region_a";

    // 1. Run 100 times, must always be identical
    let first_m = derive_m(prev_hash, secret, prefix).unwrap();

    for _ in 0..100 {
        let m = derive_m(prev_hash, secret, prefix).unwrap();
        assert_eq!(first_m, m, "HKDF must be deterministic!");
    }

    // 2. Avalanche Effect: Change one bit in prev_hash
    let prev_hash_modified = "prev_hash_123456788"; // changed last char
    let second_m = derive_m(prev_hash_modified, secret, prefix).unwrap();

    assert_ne!(first_m, second_m, "Avalanche effect missing!");
}

#[test]
fn test_trap_identity_recovery() {
    // Mathematical proof: ID = V - (V1-V2)*(U1-U2)^-1 * U1
    // We simulate the Solver Formula using raw scalars/points.

    let mut rng = OsRng;

    // Fixed Secret ID (as a point)
    let id_scalar = Scalar::random(&mut rng);
    let id_point = id_scalar * ED25519_BASEPOINT_POINT;

    // Fixed Secret Slope m
    let m = Scalar::random(&mut rng);

    // Transaction A (Input U1)
    let u1 = Scalar::random(&mut rng);
    let v1 = (u1 * m) * ED25519_BASEPOINT_POINT + id_point;

    // Transaction B (Input U2) - Same m, same ID!
    let u2 = Scalar::random(&mut rng);
    let v2 = (u2 * m) * ED25519_BASEPOINT_POINT + id_point;

    // Solver Logic:
    // 1. Calculate Delta V and Delta U
    // Delta V = V1 - V2 = (m*U1 + ID) - (m*U2 + ID) = m*(U1-U2)
    // Delta U = U1 - U2
    let delta_v = v1 - v2;
    let delta_u = u1 - u2; // Scalar

    // 2. Calculate m = Delta V * (Delta U)^-1
    let delta_u_inv = delta_u.invert();
    let m_calculated_point = delta_v * delta_u_inv; // This is m * G

    // 3. Extracted ID = V1 - m_calculated * U1
    let id_calculated = v1 - (m_calculated_point * u1);

    assert_eq!(
        id_calculated, id_point,
        "Identity extraction failed mathematically!"
    );
}

#[test]
fn test_random_slope_attack() {
    // Security Test: Attacker uses random m instead of HKDF-derived m.
    // Goal: Avoid detection if their ID is leaked?
    // Result: The system still calculates a ds_tag collision because ds_tag depends on Input, not m.
    // The proof verification on Receiver side might pass if they sign a valid ZKP for the FAKE m.
    // BUT: The Trap logic (Double Spend) will fail to extract the real ID.
    // However, the test here is to prove that the ds_tag is still generated correctly (independent of m).

    // Note: In the real system, m is not an input to generate_trap, it is used internally.
    // But generate_trap takes m as argument.

    let mut rng = OsRng;
    let u_scalar = Scalar::random(&mut rng);
    let id_point = Scalar::random(&mut rng) * ED25519_BASEPOINT_POINT;

    // Case 1: Real m
    let m_real = Scalar::random(&mut rng);
    let trap_real =
        generate_trap("tag_1".to_string(), &u_scalar, &m_real, &id_point, "prefix").unwrap();

    // Case 2: Fake m
    let m_fake = Scalar::random(&mut rng);
    let trap_fake =
        generate_trap("tag_1".to_string(), &u_scalar, &m_fake, &id_point, "prefix").unwrap();

    // The ds_tag MUST be identical (it is passed in, so this test just confirms API usage)
    assert_eq!(trap_real.ds_tag, trap_fake.ds_tag);

    // But the Blinded ID (V) will be different!
    assert_ne!(trap_real.blinded_id, trap_fake.blinded_id);

    // This confirms that if an attacker varies m, they create a NEW blinded ID V.
    // If they double spend, we have (U1, V1) and (U2, V2).
    // If U1 != U2 (different transactions), we solve.
    // If they use random m each time, we calculate:
    // m_calc = (V1-V2)/(U1-U2).
    // V1 = m1*U1 + ID. V2 = m2*U2 + ID.
    // V1-V2 = m1*U1 - m2*U2.
    // This is NOT m*(U1-U2).
    // So extracting ID will yield GARBAGE.
    // This is known behavior. The account is locked due to ds_tag collision, but ID is not revealed.
    // This is an acceptable trade-off (Privacy).
}

#[test]
fn test_trap_parameter_manipulation_with_bypass() {
    // Attack: Manipulate Trap U to NOT match Hash(Input).
    // This requires bypassing signature verification because the signature covers the Trap.

    human_money_core::set_signature_bypass(true);

    let (standard, _hash, _creator, _recipient, mut voucher, _secrets) =
        setup_voucher_with_one_tx();

    // Manipulate the Trap U in the transaction
    // The original U is valid. We overwrite it with random junk.
    // format: just change base58 string to something valid base58 but wrong value
    let wrong_u_scalar = Scalar::random(&mut OsRng);
    let wrong_u_str = bs58::encode(wrong_u_scalar.as_bytes()).into_string();

    voucher
        .transactions
        .last_mut()
        .unwrap()
        .trap_data
        .as_mut()
        .expect("Trap data missing")
        .u = wrong_u_str;

    // Now validate.
    // The signature check is bypassed.
    // But the `verify_trap` logic deep inside `validate_transaction` should check:
    // calculated_u = hash_to_scalar(input)
    // if calculated_u != trap.u -> Error.

    let result = validate_voucher_against_standard(&voucher, standard);

    assert!(
        result.is_err(),
        "Manipulation of Trap U must be detected even with signature bypass!"
    );

    let err_msg = format!("{:?}", result.err());
    // The error should come from verify_trap: "Varying Input Mismatch" or similar
    assert!(
        err_msg.contains("Varying Input Mismatch")
            || err_msg.contains("Trap Scalar U does not match"),
        "Error message should indicate Trap U mismatch. Got: {}",
        err_msg
    );

    human_money_core::set_signature_bypass(false);
}

#[test]
fn test_hash_to_curve_not_default() {
    // Dieser Test stellt sicher, dass `hash_to_curve` (auch wenn deprecated) nicht einfach 
    // den Default-Wert der EdwardsPoint Kurve zurückgibt. Ein trivialer Punkt auf der Kurve 
    // hebelt die Sicherheit von Elliptic Curve Cryptography komplett aus.
    #[allow(deprecated)]
    let point = human_money_core::services::trap_manager::hash_to_curve(b"test_input");
    let default_point = curve25519_dalek::edwards::EdwardsPoint::default();
    assert_ne!(point, default_point, "hash_to_curve must not return the default identity point");
}

#[test]
fn test_calculate_challenge_not_zero() {
    // Dieser Test beweist mathematisch, dass unsere Implementierung eine Challenge ungleich 0 erzwingt.
    // Wenn die Challenge c = 0 ist, kann ein Angreifer das Geheimnis m ignorieren und einfach s zufällig wählen 
    // (s * X == R + 0 * Y wird zu s * X == R). Indem wir aktiv genau diese Fälschung konstruieren 
    // und verlangen, dass der Verifier sie ablehnt, erhärten wir das System.
    
    use human_money_core::services::trap_manager::hash_to_scalar;
    
    let mut rng = OsRng;
    
    // Zufällige Eingabewerte
    let u_input = b"test_u_input";
    let expected_ds_tag = "test_tag";
    let u_scalar = hash_to_scalar(u_input);
    let id_scalar = Scalar::random(&mut rng);
    let my_id_point = id_scalar * ED25519_BASEPOINT_POINT;
    
    // X = u * G
    let x_base = u_scalar * ED25519_BASEPOINT_POINT;
    
    // Wähle V (Blinded ID) einfach zufällig aus, da wir m nicht kennen.
    // Daher wird Y = V - ID zufällig sein.
    let m_fake = Scalar::random(&mut rng);
    let v_point = (u_scalar * m_fake) * ED25519_BASEPOINT_POINT + my_id_point; // V = (u*m)*G + ID
    
    // ZKP FÄLSCHUNG: wähle s zufällig (ohne r, c, oder echtes m zu benutzen)
    let s_fake = Scalar::random(&mut rng);
    // Setze R = s_fake * X
    let commitment_r = s_fake * x_base;
    
    // Serialisierung des Fakery-TrapData
    let u_str = bs58::encode(u_scalar.as_bytes()).into_string();
    let blinded_id_str = bs58::encode(v_point.compress().as_bytes()).into_string();
    
    let mut proof_bytes = Vec::with_capacity(64);
    proof_bytes.extend_from_slice(commitment_r.compress().as_bytes());
    proof_bytes.extend_from_slice(s_fake.as_bytes());
    let proof_str = bs58::encode(proof_bytes).into_string();
    
    let trap_data = human_money_core::models::voucher::TrapData {
        ds_tag: expected_ds_tag.to_string(),
        u: u_str,
        blinded_id: blinded_id_str,
        proof: proof_str,
    };
    
    let verify_result = human_money_core::services::trap_manager::verify_trap(
        &trap_data,
        expected_ds_tag,
        u_input,
        &my_id_point,
        "prefix"
    );
    
    // Die Verifikation darf NICHT erfolgreich sein, wenn c berechnet wird und != 0 ist,
    // weil s * X = R ist, aber c * Y != 0 ist. Das bedeutet, s*X != R + c*Y.
    // Wenn calculate_challenge() hingegen (fälschlicherweise) 0 (Default) zurückgibt,
    // wird c*Y = 0 und s*X == R + 0, was eine erfolgreiche Verifikation ermöglicht.
    // Da wir wollen, dass dies fehlschlägt, MUSS verify_trap abbruch melden.
    assert!(verify_result.is_err(), "verify_trap must fail for a forged proof where s*X == R, which means challenge c must not be zero");
}
