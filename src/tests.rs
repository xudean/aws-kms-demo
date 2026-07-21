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

    assert_eq!(restored_private_key, signing_key.to_bytes());
    assert_eq!(restored_public_key, expected_public_key);
}

#[test]
fn rejects_oversized_json_frame_before_allocating_payload() {
    let mut frame = Vec::from(((MAX_JSON_FRAME_LENGTH + 1) as u32).to_be_bytes());
    frame.extend_from_slice(b"{}");

    let error = read_json_frame::<BrokerRequest, _>(&mut frame.as_slice()).unwrap_err();
    assert!(error.to_string().contains("maximum"));
}

#[test]
fn enclave_broker_rejects_a_target_outside_its_allowlist() {
    let error = validate_s3_target(
        "other-bucket",
        "kms-keypair/key_manifest.json",
        "allowed-bucket",
        "kms-keypair",
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("only objects below s3://allowed-bucket/kms-keypair/ are allowed")
    );
}

#[test]
fn enclave_broker_protocol_combines_config_credentials_and_s3_requests() {
    let mut frames = Vec::new();
    write_json_frame(&mut frames, &BrokerRequest::GetSettings).unwrap();
    write_json_frame(&mut frames, &BrokerRequest::GetAwsCredentials {
        slot: KmsSlot::Primary,
    })
    .unwrap();
    write_json_frame(&mut frames, &BrokerRequest::LoadObject {
        bucket: "allowed-bucket".to_string(),
        key: "kms-keypair/key_manifest.json".to_string(),
    })
    .unwrap();

    let mut frames = frames.as_slice();
    assert!(matches!(
        read_json_frame::<BrokerRequest, _>(&mut frames).unwrap(),
        BrokerRequest::GetSettings
    ));
    assert!(matches!(
        read_json_frame::<BrokerRequest, _>(&mut frames).unwrap(),
        BrokerRequest::GetAwsCredentials {
            slot: KmsSlot::Primary
        }
    ));
    match read_json_frame::<BrokerRequest, _>(&mut frames).unwrap() {
        BrokerRequest::LoadObject { bucket, key } => {
            assert_eq!(bucket, "allowed-bucket");
            assert_eq!(key, "kms-keypair/key_manifest.json");
        }
        request => panic!("unexpected broker request: {request:?}"),
    }
}

#[test]
fn parses_region_and_account_from_full_kms_key_arn() {
    let arn = "arn:aws:kms:ap-southeast-1:111122223333:key/00000000-0000-0000-0000-000000000000";
    assert_eq!(kms_region_from_arn(arn).unwrap(), "ap-southeast-1");
    assert_eq!(kms_account_from_arn(arn).unwrap(), "111122223333");
    assert!(kms_region_from_arn("alias/not-a-full-arn").is_err());
}

#[test]
fn kms_key_storage_name_is_stable_safe_and_distinguishable() {
    let arn = "arn:aws:kms:ap-southeast-1:111122223333:key/00000000-0000-0000-0000-123456789abc";
    assert_eq!(key_material::kms_key_display_id(arn).unwrap(), "56789abc");
    let storage_id = key_material::kms_key_storage_id(arn).unwrap();
    assert!(storage_id.starts_with("56789abc-"));
    assert_eq!(storage_id.len(), 8 + 1 + 12);
    assert!(
        storage_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    );

    let other_account_arn =
        "arn:aws:kms:ap-southeast-1:444455556666:key/00000000-0000-0000-0000-123456789abc";
    assert_ne!(
        storage_id,
        key_material::kms_key_storage_id(other_account_arn).unwrap()
    );
    assert!(key_material::kms_key_storage_id("alias/not-a-full-arn").is_err());
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
