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

#[test]
fn rejects_oversized_json_frame_before_allocating_payload() {
    let mut frame = Vec::from(((MAX_JSON_FRAME_LENGTH + 1) as u32).to_be_bytes());
    frame.extend_from_slice(b"{}");

    let error = read_json_frame::<ParentRequest, _>(&mut frame.as_slice()).unwrap_err();
    assert!(error.to_string().contains("maximum"));
}

#[test]
fn s3_proxy_rejects_a_target_outside_its_allowlist() {
    let error = validate_s3_target(
        "other-bucket",
        "kms-keypair.json",
        "allowed-bucket",
        "kms-keypair.json",
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("only s3://allowed-bucket/kms-keypair.json is allowed")
    );
}

#[tokio::test]
async fn enclave_hello_request_returns_expected_message() {
    let response = EnclaveGrpcService
        .hello(Request::new(HelloRequest {}))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.message, "hello from enclave");
}

#[tokio::test]
async fn enclave_hello_grpc_roundtrip_over_tcp() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let server = tokio::spawn(serve_enclave_rpc(Endpoint::Tcp(addr.to_string())));
    let endpoint = Endpoint::Tcp(addr.to_string());
    let message = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match request_enclave_hello(&endpoint).await {
                Ok(message) => break message,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("gRPC server did not start in time");
    server.abort();

    assert_eq!(message, "hello from enclave");
}
