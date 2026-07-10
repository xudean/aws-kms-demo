use super::*;

#[test]
fn encrypted_private_key_restores_to_same_public_key_with_aes_256_data_key() {
    assert_private_key_roundtrip([7u8; 32]);
}

#[test]
fn encrypted_private_key_restores_to_same_public_key_with_aes_128_data_key() {
    assert_private_key_roundtrip([9u8; 16]);
}

fn assert_private_key_roundtrip<const N: usize>(data_key: [u8; N]) {
    let private_key_seed = [42u8; ED25519_PRIVATE_KEY_LENGTH];
    let signing_key = SigningKey::from_bytes(&private_key_seed);
    let expected_public_key = signing_key.verifying_key().to_bytes();
    let expected_signature: Signature = signing_key.sign(SELF_CHECK_CHALLENGE);
    let nonce = [3u8; AES_GCM_NONCE_LENGTH];

    let encrypted_private_key =
        encrypt_private_key(&data_key, &nonce, &signing_key.to_bytes()).unwrap();
    let restored_private_key =
        decrypt_private_key(&data_key, &nonce, &encrypted_private_key).unwrap();
    let restored_private_key =
        fixed_bytes::<ED25519_PRIVATE_KEY_LENGTH>("private key", &restored_private_key).unwrap();
    let restored_public_key = SigningKey::from_bytes(&restored_private_key)
        .verifying_key()
        .to_bytes();
    let restored_signing_key = SigningKey::from_bytes(&restored_private_key);
    let restored_signature: Signature = restored_signing_key.sign(SELF_CHECK_CHALLENGE);
    let verifying_key = VerifyingKey::from_bytes(&expected_public_key).unwrap();

    assert_eq!(restored_private_key, signing_key.to_bytes());
    assert_eq!(restored_public_key, expected_public_key);
    assert_eq!(restored_signature.to_bytes(), expected_signature.to_bytes());
    verifying_key
        .verify(SELF_CHECK_CHALLENGE, &restored_signature)
        .unwrap();
}
