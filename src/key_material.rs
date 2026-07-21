use crate::*;
use std::fmt::Write as _;

const S3_OPERATION_MAX_ATTEMPTS: u32 = 4;

#[derive(Debug, Serialize, Deserialize)]
struct KeyManifest {
    version: u32,
    recovery_policy: String,
    key_fingerprint: String,
    private_key_algorithm: String,
    private_key_encryption: String,
    public_key: ObjectReference,
    recovery_objects: Vec<RecoveryObjectReference>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ObjectReference {
    object_key: String,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecoveryObjectReference {
    kms_key_arn: String,
    object_key: String,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicKeyDocument {
    version: u32,
    algorithm: String,
    public_key_base64: String,
    fingerprint_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecoveryPackage {
    version: u32,
    encrypted_data_key_base64: String,
    private_key_nonce_base64: String,
    encrypted_private_key_base64: String,
}

pub(crate) struct GeneratedDataKey {
    pub(crate) plaintext_data_key: Zeroizing<Vec<u8>>,
    pub(crate) encrypted_data_key: Vec<u8>,
    pub(crate) kms_key_id: String,
}

struct RestoredKeyPair {
    public_key: [u8; 32],
    fingerprint: String,
    kms_key_arn: String,
}

struct BrokerS3Client {
    endpoint: Endpoint,
}

impl BrokerS3Client {
    fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    async fn load_object(&self, bucket: &str, key: &str) -> AppResult<Option<Vec<u8>>> {
        match request_broker(&self.endpoint, &BrokerRequest::LoadObject {
            bucket: bucket.to_string(),
            key: key.to_string(),
        })? {
            BrokerResponse::Object(body) => Ok(body),
            response => Err(format!("unexpected enclave-broker response: {response:?}").into()),
        }
    }

    async fn save_object_if_absent(&self, bucket: &str, key: &str, body: Vec<u8>) -> AppResult<()> {
        match request_broker(&self.endpoint, &BrokerRequest::SaveObjectIfAbsent {
            bucket: bucket.to_string(),
            key: key.to_string(),
            body,
        })? {
            BrokerResponse::Saved => Ok(()),
            response => Err(format!("unexpected enclave-broker response: {response:?}").into()),
        }
    }
}

enum KmsDataKeyClient {
    Local {
        broker_endpoint: Endpoint,
    },
    #[cfg(feature = "nitro-enclave")]
    Nitro {
        client: nitro_kms::NitroKmsClient,
        broker_endpoint: Endpoint,
    },
}

impl KmsDataKeyClient {
    async fn from_env(broker_endpoint: Endpoint) -> AppResult<Self> {
        let running_in_enclave = match optional_env("RUNNING_IN_ENCLAVE") {
            Some(value) => parse_bool("RUNNING_IN_ENCLAVE", &value)?,
            None => match optional_env("KMS_MODE").as_deref() {
                Some("nitro") => true,
                Some("local-aws") | None => false,
                Some(other) => {
                    return Err(format!(
                        "unsupported legacy KMS_MODE '{other}', expected local-aws or nitro"
                    )
                    .into());
                }
            },
        };

        if !running_in_enclave {
            return Ok(Self::Local { broker_endpoint });
        }

        #[cfg(feature = "nitro-enclave")]
        {
            let parent_cid = optional_env("NITRO_PARENT_CID")
                .map(|value| value.parse::<u32>())
                .transpose()
                .map_err(|_| "NITRO_PARENT_CID must be a u32")?
                .unwrap_or(DEFAULT_PARENT_CID);
            let proxy_port = optional_env("NITRO_KMS_PROXY_PORT")
                .map(|value| value.parse::<u32>())
                .transpose()
                .map_err(|_| "NITRO_KMS_PROXY_PORT must be a u32")?
                .unwrap_or(DEFAULT_NITRO_KMS_PROXY_PORT);
            Ok(Self::Nitro {
                client: nitro_kms::NitroKmsClient::new(parent_cid, proxy_port),
                broker_endpoint,
            })
        }
        #[cfg(not(feature = "nitro-enclave"))]
        {
            let _ = broker_endpoint;
            Err(
                "RUNNING_IN_ENCLAVE=true requires building decrypt-server-tee with --features nitro-enclave"
                    .into(),
            )
        }
    }

    async fn generate_data_key(
        &self,
        settings: &ParentSettings,
        key: &KmsKeySettings,
    ) -> AppResult<GeneratedDataKey> {
        let credentials = match self {
            Self::Local { broker_endpoint } => {
                request_broker_credentials(broker_endpoint, key.slot)?
            }
            #[cfg(feature = "nitro-enclave")]
            Self::Nitro {
                broker_endpoint, ..
            } => request_broker_credentials(broker_endpoint, key.slot)?,
        };
        match self {
            Self::Local { .. } => {
                let client = local_kms_client(&credentials);
                let request_settings = settings.kms_request_settings(&key.key_arn)?;
                call_generate_data_key(&client, &request_settings).await
            }
            #[cfg(feature = "nitro-enclave")]
            Self::Nitro { client, .. } => {
                client
                    .generate_data_key(settings.clone(), credentials, key.key_arn.clone())
                    .await
            }
        }
    }

    async fn decrypt_data_key(
        &self,
        settings: &ParentSettings,
        key: &KmsKeySettings,
        encrypted_data_key: Vec<u8>,
    ) -> AppResult<Zeroizing<Vec<u8>>> {
        let credentials = match self {
            Self::Local { broker_endpoint } => {
                request_broker_credentials(broker_endpoint, key.slot)?
            }
            #[cfg(feature = "nitro-enclave")]
            Self::Nitro {
                broker_endpoint, ..
            } => request_broker_credentials(broker_endpoint, key.slot)?,
        };

        match self {
            Self::Local { .. } => {
                let client = local_kms_client(&credentials);
                let request_settings = settings.kms_request_settings(&key.key_arn)?;
                call_decrypt_data_key(&client, &request_settings, encrypted_data_key).await
            }
            #[cfg(feature = "nitro-enclave")]
            Self::Nitro { client, .. } => {
                client
                    .decrypt_data_key(settings.clone(), credentials, encrypted_data_key)
                    .await
            }
        }
    }
}

pub async fn run_decrypt_server_tee(
    settings: ParentSettings,
    broker_endpoint: Endpoint,
) -> AppResult<()> {
    validate_kms_configuration(&settings)?;
    let s3_client = BrokerS3Client::new(broker_endpoint.clone());
    let kms_client = KmsDataKeyClient::from_env(broker_endpoint).await?;
    println!("config: loaded from enclave-broker");
    println!("config: s3_bucket={}", settings.s3_bucket);
    println!("config: s3_prefix={}", settings.s3_prefix);

    match settings.startup_mode {
        StartupMode::InitKey => {
            let initialized = initialize_key_material(&s3_client, &kms_client, &settings).await?;
            println!("mode: init-key");
            println!(
                "public_key_base64: {}",
                STANDARD.encode(initialized.public_key)
            );
            println!("public_key_fingerprint_sha256: {}", initialized.fingerprint);
        }
        StartupMode::Serve => {
            let restored = restore_key_material(&s3_client, &kms_client, &settings).await?;
            println!("mode: restore");
            println!("kms_recovery_key_arn: {}", restored.kms_key_arn);
            println!(
                "public_key_base64: {}",
                STANDARD.encode(restored.public_key)
            );
            println!("public_key_fingerprint_sha256: {}", restored.fingerprint);
        }
    }
    Ok(())
}

async fn initialize_key_material(
    s3_client: &BrokerS3Client,
    kms_client: &KmsDataKeyClient,
    settings: &ParentSettings,
) -> AppResult<RestoredKeyPair> {
    let manifest_key = object_key(&settings.s3_prefix, MANIFEST_FILE_NAME);
    println!(
        "initialization: checking s3://{}/{}",
        settings.s3_bucket, manifest_key
    );
    if s3_client
        .load_object(&settings.s3_bucket, &manifest_key)
        .await?
        .is_some()
    {
        return Err(format!(
            "key manifest already exists at s3://{}/{}; refusing to generate or overwrite key material",
            settings.s3_bucket, manifest_key
        )
        .into());
    }

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; ED25519_PRIVATE_KEY_LENGTH]>());
    let private_key = Zeroizing::new(signing_key.to_bytes());
    let public_key = signing_key.verifying_key().to_bytes();
    let fingerprint = sha256_hex(&public_key);
    let public_document = PublicKeyDocument {
        version: KEY_MATERIAL_VERSION,
        algorithm: PRIVATE_KEY_ALGORITHM.to_string(),
        public_key_base64: STANDARD.encode(public_key),
        fingerprint_sha256: fingerprint.clone(),
    };
    let public_body = serde_json::to_vec_pretty(&public_document)?;
    let public_hash = sha256_hex(&public_body);
    let public_key_name = format!("public_key_sha256-{fingerprint}.json");
    let public_object_key = object_key(&settings.s3_prefix, &public_key_name);

    let mut recovery_objects = Vec::with_capacity(settings.kms_keys.len());
    for key in &settings.kms_keys {
        println!("initialization: generating data key with {}", key.key_arn);
        let generated = kms_client.generate_data_key(settings, key).await?;
        if generated.kms_key_id != key.key_arn {
            return Err(format!(
                "KMS GenerateDataKey returned unexpected key ID {}; expected {}",
                generated.kms_key_id, key.key_arn
            )
            .into());
        }
        validate_data_key_len(&generated.plaintext_data_key)?;
        let nonce = rand::random::<[u8; AES_GCM_NONCE_LENGTH]>();
        let encrypted_private_key =
            encrypt_private_key(&generated.plaintext_data_key, &nonce, private_key.as_ref())?;
        let package = RecoveryPackage {
            version: KEY_MATERIAL_VERSION,
            encrypted_data_key_base64: STANDARD.encode(generated.encrypted_data_key),
            private_key_nonce_base64: STANDARD.encode(nonce),
            encrypted_private_key_base64: STANDARD.encode(encrypted_private_key),
        };
        let package_body = serde_json::to_vec_pretty(&package)?;
        let package_hash = sha256_hex(&package_body);
        let storage_id = kms_key_storage_id(&key.key_arn)?;
        let display_id = kms_key_display_id(&key.key_arn)?;
        let relative_key = format!(
            "kms-key-{storage_id}/encrypted_private_key_by_kms-key-{display_id}_sha256-{package_hash}.json"
        );
        let package_object_key = object_key(&settings.s3_prefix, &relative_key);
        s3_client
            .save_object_if_absent(&settings.s3_bucket, &package_object_key, package_body)
            .await?;
        verify_uploaded_object(
            s3_client,
            &settings.s3_bucket,
            &package_object_key,
            &package_hash,
        )
        .await?;
        restore_from_package(kms_client, settings, key, &package, &public_key).await?;
        recovery_objects.push(RecoveryObjectReference {
            kms_key_arn: key.key_arn.clone(),
            object_key: package_object_key,
            sha256: package_hash,
        });
    }

    s3_client
        .save_object_if_absent(&settings.s3_bucket, &public_object_key, public_body)
        .await?;
    verify_uploaded_object(
        s3_client,
        &settings.s3_bucket,
        &public_object_key,
        &public_hash,
    )
    .await?;

    let manifest = KeyManifest {
        version: KEY_MATERIAL_VERSION,
        recovery_policy: "any-one".to_string(),
        key_fingerprint: fingerprint.clone(),
        private_key_algorithm: PRIVATE_KEY_ALGORITHM.to_string(),
        private_key_encryption: PRIVATE_KEY_ENCRYPTION.to_string(),
        public_key: ObjectReference {
            object_key: public_object_key,
            sha256: public_hash,
        },
        recovery_objects,
    };
    s3_client
        .save_object_if_absent(
            &settings.s3_bucket,
            &manifest_key,
            serde_json::to_vec_pretty(&manifest)?,
        )
        .await?;
    println!(
        "initialization: committed s3://{}/{}",
        settings.s3_bucket, manifest_key
    );

    Ok(RestoredKeyPair {
        public_key,
        fingerprint,
        kms_key_arn: String::new(),
    })
}

async fn restore_key_material(
    s3_client: &BrokerS3Client,
    kms_client: &KmsDataKeyClient,
    settings: &ParentSettings,
) -> AppResult<RestoredKeyPair> {
    let manifest_key = object_key(&settings.s3_prefix, MANIFEST_FILE_NAME);
    println!(
        "startup: loading s3://{}/{}",
        settings.s3_bucket, manifest_key
    );
    let manifest_body = s3_client
        .load_object(&settings.s3_bucket, &manifest_key)
        .await?
        .ok_or_else(|| {
            format!(
                "key manifest does not exist at s3://{}/{}; refusing to generate a replacement",
                settings.s3_bucket, manifest_key
            )
        })?;
    let manifest: KeyManifest = serde_json::from_slice(&manifest_body)?;
    validate_manifest(&manifest)?;

    let public_body = s3_client
        .load_object(&settings.s3_bucket, &manifest.public_key.object_key)
        .await?
        .ok_or_else(|| {
            format!(
                "public key object is missing: {}",
                manifest.public_key.object_key
            )
        })?;
    verify_sha256(
        "public key object",
        &public_body,
        &manifest.public_key.sha256,
    )?;
    let public_document: PublicKeyDocument = serde_json::from_slice(&public_body)?;
    let expected_public_key = validate_public_document(&public_document, &manifest)?;

    let mut failures = Vec::new();
    for key in &settings.kms_keys {
        let Some(reference) = manifest
            .recovery_objects
            .iter()
            .find(|reference| reference.kms_key_arn == key.key_arn)
        else {
            failures.push(format!("{}: no recovery object in manifest", key.key_arn));
            continue;
        };

        println!("restore: trying {}", key.key_arn);
        let attempt: AppResult<()> = async {
            let body = s3_client
                .load_object(&settings.s3_bucket, &reference.object_key)
                .await?
                .ok_or_else(|| format!("recovery object is missing: {}", reference.object_key))?;
            verify_sha256("recovery object", &body, &reference.sha256)?;
            let package: RecoveryPackage = serde_json::from_slice(&body)?;
            restore_from_package(kms_client, settings, key, &package, &expected_public_key).await
        }
        .await;

        match attempt {
            Ok(()) => {
                println!("restore: succeeded with {}", key.key_arn);
                return Ok(RestoredKeyPair {
                    public_key: expected_public_key,
                    fingerprint: manifest.key_fingerprint,
                    kms_key_arn: key.key_arn.clone(),
                });
            }
            Err(error) => {
                println!("restore: failed with {}: {error}", key.key_arn);
                failures.push(format!("{}: {error}", key.key_arn));
            }
        }
    }

    Err(format!(
        "none of the configured KMS keys could restore the private key: {}",
        failures.join("; ")
    )
    .into())
}

async fn restore_from_package(
    kms_client: &KmsDataKeyClient,
    settings: &ParentSettings,
    key: &KmsKeySettings,
    package: &RecoveryPackage,
    expected_public_key: &[u8; 32],
) -> AppResult<()> {
    if package.version != KEY_MATERIAL_VERSION {
        return Err(format!("unsupported recovery package version {}", package.version).into());
    }
    let encrypted_data_key = decode_base64(
        "encrypted_data_key_base64",
        &package.encrypted_data_key_base64,
    )?;
    let encrypted_private_key = decode_base64(
        "encrypted_private_key_base64",
        &package.encrypted_private_key_base64,
    )?;
    let nonce = decode_fixed_base64::<AES_GCM_NONCE_LENGTH>(
        "private_key_nonce_base64",
        &package.private_key_nonce_base64,
    )?;
    let plaintext_data_key = kms_client
        .decrypt_data_key(settings, key, encrypted_data_key)
        .await?;
    validate_data_key_len(&plaintext_data_key)?;
    let decrypted_private_key = Zeroizing::new(decrypt_private_key(
        &plaintext_data_key,
        &nonce,
        &encrypted_private_key,
    )?);
    let private_key = Zeroizing::new(fixed_bytes::<ED25519_PRIVATE_KEY_LENGTH>(
        "private key",
        decrypted_private_key.as_ref(),
    )?);
    let actual_public_key = SigningKey::from_bytes(&private_key)
        .verifying_key()
        .to_bytes();
    if &actual_public_key != expected_public_key {
        return Err("restored private key does not match the stored public key".into());
    }
    Ok(())
}

fn validate_kms_configuration(settings: &ParentSettings) -> AppResult<()> {
    if settings.kms_keys.len() != 2 {
        return Err("exactly two KMS keys are required".into());
    }
    if settings.kms_keys[0].key_arn == settings.kms_keys[1].key_arn {
        return Err("primary and backup KMS key ARNs must be different".into());
    }
    if kms_account_from_arn(&settings.kms_keys[0].key_arn)?
        == kms_account_from_arn(&settings.kms_keys[1].key_arn)?
    {
        eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        eprintln!("WARNING: primary and backup KMS keys belong to the SAME AWS account");
        eprintln!("WARNING: recovery still works, but account-level isolation is NOT provided");
        eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    }
    if settings.kms_keys[0].region != settings.kms_keys[1].region {
        return Err(
            "primary and backup KMS keys must be in the same region because the enclave uses one KMS vsock-proxy endpoint"
                .into(),
        );
    }
    Ok(())
}

fn validate_manifest(manifest: &KeyManifest) -> AppResult<()> {
    if manifest.version != KEY_MATERIAL_VERSION {
        return Err(format!("unsupported key manifest version {}", manifest.version).into());
    }
    if manifest.recovery_policy != "any-one" {
        return Err(format!("unsupported recovery policy {}", manifest.recovery_policy).into());
    }
    if manifest.private_key_algorithm != PRIVATE_KEY_ALGORITHM
        || manifest.private_key_encryption != PRIVATE_KEY_ENCRYPTION
    {
        return Err("unsupported private key algorithm or encryption in manifest".into());
    }
    if manifest.recovery_objects.len() != 2 {
        return Err("key manifest must contain exactly two recovery objects".into());
    }
    Ok(())
}

fn validate_public_document(
    document: &PublicKeyDocument,
    manifest: &KeyManifest,
) -> AppResult<[u8; 32]> {
    if document.version != KEY_MATERIAL_VERSION || document.algorithm != PRIVATE_KEY_ALGORITHM {
        return Err("unsupported public key document".into());
    }
    let public_key = decode_fixed_base64::<32>("public_key_base64", &document.public_key_base64)?;
    let fingerprint = sha256_hex(&public_key);
    if fingerprint != document.fingerprint_sha256 || fingerprint != manifest.key_fingerprint {
        return Err("public key fingerprint does not match the manifest".into());
    }
    Ok(public_key)
}

async fn verify_uploaded_object(
    s3_client: &BrokerS3Client,
    bucket: &str,
    key: &str,
    expected_hash: &str,
) -> AppResult<()> {
    let body = s3_client
        .load_object(bucket, key)
        .await?
        .ok_or_else(|| format!("uploaded object disappeared before verification: {key}"))?;
    verify_sha256("uploaded object", &body, expected_hash)
}

fn verify_sha256(name: &str, body: &[u8], expected: &str) -> AppResult<()> {
    let actual = sha256_hex(body);
    if actual != expected {
        return Err(format!("{name} SHA-256 mismatch: expected {expected}, got {actual}").into());
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

pub(crate) fn kms_key_display_id(key_arn: &str) -> Result<String, String> {
    let key_id = key_arn
        .split_once(":key/")
        .map(|(_, key_id)| key_id)
        .filter(|key_id| !key_id.is_empty())
        .ok_or_else(|| format!("KMS key ARN must contain a non-empty key ID: {key_arn}"))?;
    if !key_id
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err(format!("KMS key ARN contains an unsafe key ID: {key_arn}"));
    }
    Ok(key_id
        .chars()
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect())
}

pub(crate) fn kms_key_storage_id(key_arn: &str) -> Result<String, String> {
    let display_id = kms_key_display_id(key_arn)?;
    let arn_hash = sha256_hex(key_arn.as_bytes());
    Ok(format!("{display_id}-{}", &arn_hash[..12]))
}

fn object_key(prefix: &str, relative: &str) -> String {
    format!("{prefix}/{relative}")
}

fn local_kms_client(credentials: &AwsCredentials) -> KmsClient {
    let provider = SharedCredentialsProvider::new(Credentials::new(
        credentials.access_key_id.clone(),
        credentials.secret_access_key.clone(),
        credentials.session_token.clone(),
        None,
        "enclave-broker",
    ));
    let config = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .credentials_provider(provider)
        .region(Region::new(credentials.region.clone()))
        .build();
    KmsClient::from_conf(config)
}

async fn call_generate_data_key(
    kms_client: &KmsClient,
    settings: &Settings,
) -> AppResult<GeneratedDataKey> {
    let mut request = kms_client
        .generate_data_key()
        .key_id(settings.kms_key_id.clone());
    if let Some(key_spec) = settings.key_spec.clone() {
        request = request.key_spec(key_spec);
    }
    if let Some(number_of_bytes) = settings.number_of_bytes {
        request = request.number_of_bytes(number_of_bytes);
    }
    if let Some(encryption_context) = settings.encryption_context.clone() {
        request = request.set_encryption_context(Some(encryption_context));
    }
    for grant_token in settings.grant_tokens.iter().cloned() {
        request = request.grant_tokens(grant_token);
    }
    if let Some(dry_run) = settings.dry_run {
        request = request.dry_run(dry_run);
    }
    let output = request.send().await?;
    Ok(GeneratedDataKey {
        plaintext_data_key: Zeroizing::new(
            output
                .plaintext()
                .ok_or("KMS GenerateDataKey response did not include plaintext data key")?
                .as_ref()
                .to_vec(),
        ),
        encrypted_data_key: output
            .ciphertext_blob()
            .ok_or("KMS GenerateDataKey response did not include encrypted data key")?
            .as_ref()
            .to_vec(),
        kms_key_id: output
            .key_id()
            .unwrap_or(settings.kms_key_id.as_str())
            .to_string(),
    })
}

async fn call_decrypt_data_key(
    kms_client: &KmsClient,
    settings: &Settings,
    encrypted_data_key: Vec<u8>,
) -> AppResult<Zeroizing<Vec<u8>>> {
    let mut request = kms_client
        .decrypt()
        .ciphertext_blob(Blob::new(encrypted_data_key))
        .key_id(settings.kms_key_id.clone());
    if let Some(encryption_context) = settings.encryption_context.clone() {
        request = request.set_encryption_context(Some(encryption_context));
    }
    for grant_token in settings.grant_tokens.iter().cloned() {
        request = request.grant_tokens(grant_token);
    }
    if let Some(dry_run) = settings.dry_run {
        request = request.dry_run(dry_run);
    }
    Ok(Zeroizing::new(
        request
            .send()
            .await?
            .plaintext()
            .ok_or("KMS Decrypt response did not include plaintext data key")?
            .as_ref()
            .to_vec(),
    ))
}

pub(crate) async fn load_s3_object(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
) -> AppResult<Option<Vec<u8>>> {
    for attempt in 1..=S3_OPERATION_MAX_ATTEMPTS {
        println!(
            "s3: get_object s3://{bucket}/{key} (attempt {attempt}/{S3_OPERATION_MAX_ATTEMPTS})"
        );
        match s3_client.get_object().bucket(bucket).key(key).send().await {
            Ok(output) => return Ok(Some(output.body.collect().await?.into_bytes().to_vec())),
            Err(SdkError::ServiceError(error)) if error.err().is_no_such_key() => return Ok(None),
            Err(SdkError::DispatchFailure(error)) if attempt < S3_OPERATION_MAX_ATTEMPTS => {
                eprintln!(
                    "WARNING: S3 GetObject connection failed on attempt {attempt}: {error:?}; retrying"
                );
                sleep_before_s3_retry(attempt).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!("S3 GetObject retry loop always returns")
}

pub(crate) async fn save_s3_object_if_absent(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
    body: Vec<u8>,
) -> AppResult<()> {
    let expected_body = body;
    for attempt in 1..=S3_OPERATION_MAX_ATTEMPTS {
        println!(
            "s3: put_object if-absent s3://{bucket}/{key} (attempt {attempt}/{S3_OPERATION_MAX_ATTEMPTS})"
        );
        let result = s3_client
            .put_object()
            .bucket(bucket)
            .key(key)
            .if_none_match("*")
            .content_type("application/json")
            .body(ByteStream::from(expected_body.clone()))
            .send()
            .await;

        match result {
            Ok(_) => return Ok(()),
            Err(SdkError::ServiceError(error)) if error.raw().status().as_u16() == 412 => {
                let existing = load_s3_object(s3_client, bucket, key).await?;
                if existing.as_deref() == Some(expected_body.as_slice()) {
                    println!(
                        "s3: conditional write reported 412, but the existing content matches exactly; treating it as an idempotent success"
                    );
                    return Ok(());
                }
                return Err(format!(
                    "conditional S3 write refused because s3://{bucket}/{key} already exists with different content (HTTP 412)"
                )
                .into());
            }
            Err(SdkError::DispatchFailure(error)) if attempt < S3_OPERATION_MAX_ATTEMPTS => {
                eprintln!(
                    "WARNING: S3 PutObject connection failed on attempt {attempt}: {error:?}; retrying"
                );
                sleep_before_s3_retry(attempt).await;
            }
            Err(SdkError::ServiceError(error)) => {
                return Err(format!(
                    "conditional S3 write failed for s3://{bucket}/{key}: HTTP {}, code={}, message={}",
                    error.raw().status().as_u16(),
                    error.err().code().unwrap_or("unknown"),
                    error.err().message().unwrap_or("unknown")
                )
                .into());
            }
            Err(error) => {
                return Err(format!(
                    "conditional S3 write failed for s3://{bucket}/{key}: {error:?}"
                )
                .into());
            }
        }
    }
    unreachable!("S3 PutObject retry loop always returns")
}

async fn sleep_before_s3_retry(attempt: u32) {
    tokio::time::sleep(std::time::Duration::from_millis(250 * u64::from(attempt))).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_public_key_fingerprint() {
        let public_key = [7u8; 32];
        let fingerprint = sha256_hex(&public_key);
        let document = PublicKeyDocument {
            version: KEY_MATERIAL_VERSION,
            algorithm: PRIVATE_KEY_ALGORITHM.to_string(),
            public_key_base64: STANDARD.encode(public_key),
            fingerprint_sha256: fingerprint.clone(),
        };
        let manifest = KeyManifest {
            version: KEY_MATERIAL_VERSION,
            recovery_policy: "any-one".to_string(),
            key_fingerprint: fingerprint,
            private_key_algorithm: PRIVATE_KEY_ALGORITHM.to_string(),
            private_key_encryption: PRIVATE_KEY_ENCRYPTION.to_string(),
            public_key: ObjectReference {
                object_key: "prefix/public.json".to_string(),
                sha256: "unused".to_string(),
            },
            recovery_objects: Vec::new(),
        };
        assert_eq!(
            validate_public_document(&document, &manifest).unwrap(),
            public_key
        );
    }

    #[test]
    fn content_hash_changes_when_package_changes() {
        let first = RecoveryPackage {
            version: KEY_MATERIAL_VERSION,
            encrypted_data_key_base64: "a".to_string(),
            private_key_nonce_base64: "b".to_string(),
            encrypted_private_key_base64: "c".to_string(),
        };
        let mut second = serde_json::to_vec_pretty(&first).unwrap();
        second.push(b' ');
        assert_ne!(
            sha256_hex(&serde_json::to_vec_pretty(&first).unwrap()),
            sha256_hex(&second)
        );
    }

    #[test]
    fn same_account_kms_keys_are_allowed_with_warning() {
        let settings = ParentSettings {
            kms_keys: vec![
                KmsKeySettings::from_arn(
                    KmsSlot::Primary,
                    "arn:aws:kms:us-east-1:111122223333:key/primary".to_string(),
                )
                .unwrap(),
                KmsKeySettings::from_arn(
                    KmsSlot::Backup,
                    "arn:aws:kms:us-east-1:111122223333:key/backup".to_string(),
                )
                .unwrap(),
            ],
            s3_bucket: "bucket".to_string(),
            s3_prefix: "prefix".to_string(),
            startup_mode: StartupMode::Serve,
            key_spec: Some("AES_256".to_string()),
            number_of_bytes: None,
            encryption_context: None,
            grant_tokens: Vec::new(),
            dry_run: None,
        };

        validate_kms_configuration(&settings).unwrap();
    }
}
