use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use aws_config::BehaviorVersion;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

const PRIVATE_KEY_ALGORITHM: &str = "ED25519";
const PRIVATE_KEY_ENCRYPTION: &str = "AES-GCM";
const S3_KEY: &str = "kms-keypair.json";
const SELF_CHECK_CHALLENGE: &[u8] = b"aws-kms-demo:keypair-self-check:v1";
const ED25519_PRIVATE_KEY_LENGTH: usize = 32;
const AES_GCM_NONCE_LENGTH: usize = 12;
const ED25519_SIGNATURE_LENGTH: usize = 64;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::dotenv();

    let settings = Settings::from_env()?;
    println!("config: loaded");
    println!("config: kms_key_id={}", settings.kms_key_id);
    println!("config: s3_bucket={}", settings.s3_bucket);
    println!("config: s3_key={}", settings.s3_key);

    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let kms_client = KmsClient::new(&config);
    let s3_client = S3Client::new(&config);

    println!(
        "startup: checking key material at s3://{}/{}",
        settings.s3_bucket, settings.s3_key
    );
    match load_key_material(&s3_client, &settings.s3_bucket, &settings.s3_key).await? {
        Some(stored) => {
            println!(
                "found key material in s3://{}/{}; restoring key pair",
                settings.s3_bucket, settings.s3_key
            );
            let restored = restore_key_pair(&kms_client, &settings, stored).await?;

            println!("mode: restore");
            println!(
                "public_key_base64: {}",
                STANDARD.encode(restored.public_key)
            );
        }
        None => {
            println!(
                "no key material found in s3://{}/{}; generating key pair",
                settings.s3_bucket, settings.s3_key
            );
            let generated = generate_key_pair(&kms_client, &settings).await?;
            save_key_material(
                &s3_client,
                &settings.s3_bucket,
                &settings.s3_key,
                &generated,
            )
            .await?;

            println!("mode: generate");
            println!("public_key_base64: {}", generated.public_key_base64);
            println!("uploaded: s3://{}/{}", settings.s3_bucket, settings.s3_key);
        }
    }

    Ok(())
}

async fn generate_key_pair(
    kms_client: &KmsClient,
    settings: &Settings,
) -> Result<KeyMaterial, Box<dyn std::error::Error>> {
    println!("generation: calling KMS GenerateDataKey");
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
    println!("generation: KMS GenerateDataKey completed");
    let plaintext_data_key = output
        .plaintext()
        .ok_or("KMS GenerateDataKey response did not include plaintext data key")?
        .as_ref()
        .to_vec();
    let encrypted_data_key = output
        .ciphertext_blob()
        .ok_or("KMS GenerateDataKey response did not include encrypted data key")?
        .as_ref()
        .to_vec();

    validate_data_key_len(&plaintext_data_key)?;
    println!(
        "generation: plaintext data key length={} bytes",
        plaintext_data_key.len()
    );

    println!("generation: creating local Ed25519 key pair");
    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; ED25519_PRIVATE_KEY_LENGTH]>());
    let private_key = signing_key.to_bytes();
    let public_key = signing_key.verifying_key().to_bytes();
    println!("generation: public key derived");

    println!("generation: signing self-check challenge");
    let self_check_signature: Signature = signing_key.sign(SELF_CHECK_CHALLENGE);
    let nonce = rand::random::<[u8; AES_GCM_NONCE_LENGTH]>();
    println!("generation: encrypting private key with plaintext data key");
    let encrypted_private_key = encrypt_private_key(&plaintext_data_key, &nonce, &private_key)?;
    println!(
        "generation: encrypted private key length={} bytes",
        encrypted_private_key.len()
    );

    Ok(KeyMaterial {
        version: 1,
        private_key_algorithm: PRIVATE_KEY_ALGORITHM.to_string(),
        private_key_encryption: PRIVATE_KEY_ENCRYPTION.to_string(),
        kms_key_id: output
            .key_id()
            .unwrap_or(settings.kms_key_id.as_str())
            .to_string(),
        encrypted_data_key_base64: STANDARD.encode(encrypted_data_key),
        private_key_nonce_base64: STANDARD.encode(nonce),
        encrypted_private_key_base64: STANDARD.encode(encrypted_private_key),
        public_key_base64: STANDARD.encode(public_key),
        self_check_signature_base64: Some(STANDARD.encode(self_check_signature.to_bytes())),
    })
}

async fn restore_key_pair(
    kms_client: &KmsClient,
    settings: &Settings,
    stored: KeyMaterial,
) -> Result<RestoredKeyPair, Box<dyn std::error::Error>> {
    println!("restore: validating key material metadata");
    validate_key_material_header(&stored)?;

    println!("restore: decoding key material fields");
    let encrypted_data_key = decode_base64(
        "encrypted_data_key_base64",
        &stored.encrypted_data_key_base64,
    )?;
    let encrypted_private_key = decode_base64(
        "encrypted_private_key_base64",
        &stored.encrypted_private_key_base64,
    )?;
    let nonce = decode_fixed_base64::<AES_GCM_NONCE_LENGTH>(
        "private_key_nonce_base64",
        &stored.private_key_nonce_base64,
    )?;
    let expected_public_key =
        decode_fixed_base64::<32>("public_key_base64", &stored.public_key_base64)?;
    let stored_signature = decode_self_check_signature(&stored)?;
    let verifying_key = VerifyingKey::from_bytes(&expected_public_key)?;
    println!("restore: verifying stored self-check signature");
    verifying_key.verify(SELF_CHECK_CHALLENGE, &stored_signature)?;
    println!("restore: stored self-check signature is valid");

    println!("restore: calling KMS Decrypt for encrypted data key");
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

    let output = request.send().await?;
    println!("restore: KMS Decrypt completed");
    let plaintext_data_key = output
        .plaintext()
        .ok_or("KMS Decrypt response did not include plaintext data key")?
        .as_ref()
        .to_vec();

    validate_data_key_len(&plaintext_data_key)?;
    println!(
        "restore: plaintext data key length={} bytes",
        plaintext_data_key.len()
    );

    println!("restore: decrypting private key");
    let private_key = decrypt_private_key(&plaintext_data_key, &nonce, &encrypted_private_key)?;
    let private_key = fixed_bytes::<ED25519_PRIVATE_KEY_LENGTH>("private key", &private_key)?;
    println!("restore: private key decrypted");

    println!("restore: deriving public key from restored private key");
    let signing_key = SigningKey::from_bytes(&private_key);
    let actual_public_key = signing_key.verifying_key().to_bytes();

    if actual_public_key != expected_public_key {
        return Err("restored private key does not match stored public key".into());
    }
    println!("restore: derived public key matches stored public key");

    println!("restore: signing self-check challenge with restored private key");
    let restored_signature: Signature = signing_key.sign(SELF_CHECK_CHALLENGE);
    if restored_signature.to_bytes() != stored_signature.to_bytes() {
        return Err(
            "restored private key signature does not match stored self-check signature".into(),
        );
    }
    verifying_key.verify(SELF_CHECK_CHALLENGE, &restored_signature)?;
    println!("restore: restored self-check signature verified");

    Ok(RestoredKeyPair {
        public_key: actual_public_key,
    })
}

async fn load_key_material(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
) -> Result<Option<KeyMaterial>, Box<dyn std::error::Error>> {
    println!("s3: get_object s3://{bucket}/{key}");
    let output = match s3_client.get_object().bucket(bucket).key(key).send().await {
        Ok(output) => output,
        Err(SdkError::ServiceError(error)) if error.err().is_no_such_key() => {
            println!("s3: object not found");
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };

    let bytes = output.body.collect().await?.into_bytes();
    println!("s3: downloaded {} bytes", bytes.len());
    let material = serde_json::from_slice::<KeyMaterial>(&bytes)?;
    println!("s3: key material parsed");
    Ok(Some(material))
}

async fn save_key_material(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
    material: &KeyMaterial,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::to_vec_pretty(material)?;
    println!("s3: put_object s3://{bucket}/{key}");
    println!("s3: upload body length={} bytes", body.len());

    s3_client
        .put_object()
        .bucket(bucket)
        .key(key)
        .content_type("application/json")
        .body(ByteStream::from(body))
        .send()
        .await?;

    println!("s3: upload completed");
    Ok(())
}

fn encrypt_private_key(
    data_key: &[u8],
    nonce: &[u8; AES_GCM_NONCE_LENGTH],
    private_key: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match data_key.len() {
        16 => {
            let nonce = Nonce::from(*nonce);
            Ok(Aes128Gcm::new_from_slice(data_key)?.encrypt(&nonce, private_key)?)
        }
        32 => {
            let nonce = Nonce::from(*nonce);
            Ok(Aes256Gcm::new_from_slice(data_key)?.encrypt(&nonce, private_key)?)
        }
        len => Err(
            format!("unsupported plaintext data key length {len}; expected 16 or 32 bytes").into(),
        ),
    }
}

fn decrypt_private_key(
    data_key: &[u8],
    nonce: &[u8; AES_GCM_NONCE_LENGTH],
    encrypted_private_key: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match data_key.len() {
        16 => {
            let nonce = Nonce::from(*nonce);
            Ok(Aes128Gcm::new_from_slice(data_key)?.decrypt(&nonce, encrypted_private_key)?)
        }
        32 => {
            let nonce = Nonce::from(*nonce);
            Ok(Aes256Gcm::new_from_slice(data_key)?.decrypt(&nonce, encrypted_private_key)?)
        }
        len => Err(
            format!("unsupported plaintext data key length {len}; expected 16 or 32 bytes").into(),
        ),
    }
}

fn validate_data_key_len(data_key: &[u8]) -> Result<(), String> {
    match data_key.len() {
        16 | 32 => Ok(()),
        len => Err(format!(
            "unsupported plaintext data key length {len}; use KMS_KEY_SPEC=AES_128/AES_256 or KMS_NUMBER_OF_BYTES=16/32"
        )),
    }
}

fn validate_key_material_header(material: &KeyMaterial) -> Result<(), String> {
    if material.version != 1 {
        return Err(format!(
            "unsupported key material version {}",
            material.version
        ));
    }
    if material.private_key_algorithm != PRIVATE_KEY_ALGORITHM {
        return Err(format!(
            "unsupported private key algorithm {}",
            material.private_key_algorithm
        ));
    }
    if material.private_key_encryption != PRIVATE_KEY_ENCRYPTION {
        return Err(format!(
            "unsupported private key encryption {}",
            material.private_key_encryption
        ));
    }

    Ok(())
}

fn decode_self_check_signature(material: &KeyMaterial) -> Result<Signature, String> {
    let value = material.self_check_signature_base64.as_deref().ok_or_else(|| {
        "missing self_check_signature_base64; delete the old S3 object and regenerate key material"
            .to_string()
    })?;
    let bytes =
        decode_fixed_base64::<ED25519_SIGNATURE_LENGTH>("self_check_signature_base64", value)?;

    Signature::try_from(bytes.as_slice()).map_err(|error| {
        format!("self_check_signature_base64 is not a valid Ed25519 signature: {error}")
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyMaterial {
    version: u32,
    private_key_algorithm: String,
    private_key_encryption: String,
    kms_key_id: String,
    encrypted_data_key_base64: String,
    private_key_nonce_base64: String,
    encrypted_private_key_base64: String,
    public_key_base64: String,
    self_check_signature_base64: Option<String>,
}

struct RestoredKeyPair {
    public_key: [u8; 32],
}

struct Settings {
    kms_key_id: String,
    s3_bucket: String,
    s3_key: String,
    key_spec: Option<DataKeySpec>,
    number_of_bytes: Option<i32>,
    encryption_context: Option<HashMap<String, String>>,
    grant_tokens: Vec<String>,
    dry_run: Option<bool>,
}

impl Settings {
    fn from_env() -> Result<Self, String> {
        let kms_key_id = required_env("KMS_KEY_ID")?;
        let s3_bucket = required_env("S3_BUCKET")?;
        let key_spec = optional_env("KMS_KEY_SPEC")
            .or_else(|| optional_env("KEY_SPEC"))
            .map(|value| parse_key_spec(&value))
            .transpose()?;
        let number_of_bytes = optional_env("KMS_NUMBER_OF_BYTES")
            .map(|value| parse_number_of_bytes(&value))
            .transpose()?;

        if key_spec.is_some() && number_of_bytes.is_some() {
            return Err("set only one of KMS_KEY_SPEC or KMS_NUMBER_OF_BYTES".to_string());
        }

        let key_spec = if key_spec.is_none() && number_of_bytes.is_none() {
            Some(DataKeySpec::Aes256)
        } else {
            key_spec
        };

        Ok(Self {
            kms_key_id,
            s3_bucket,
            s3_key: S3_KEY.to_string(),
            key_spec,
            number_of_bytes,
            encryption_context: optional_env("KMS_ENCRYPTION_CONTEXT")
                .map(|value| parse_encryption_context(&value))
                .transpose()?,
            grant_tokens: optional_env("KMS_GRANT_TOKENS")
                .map(|value| parse_csv(&value))
                .unwrap_or_default(),
            dry_run: optional_env("KMS_DRY_RUN")
                .map(|value| parse_bool("KMS_DRY_RUN", &value))
                .transpose()?,
        })
    }
}

fn required_env(name: &str) -> Result<String, String> {
    optional_env(name).ok_or_else(|| format!("missing {name}"))
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn parse_key_spec(value: &str) -> Result<DataKeySpec, String> {
    match value {
        "AES_128" => Ok(DataKeySpec::Aes128),
        "AES_256" => Ok(DataKeySpec::Aes256),
        other => Err(format!(
            "unsupported KMS_KEY_SPEC '{other}', expected AES_128 or AES_256"
        )),
    }
}

fn parse_number_of_bytes(value: &str) -> Result<i32, String> {
    let parsed = value
        .parse::<i32>()
        .map_err(|_| format!("KMS_NUMBER_OF_BYTES must be an integer, got '{value}'"))?;

    if parsed != 16 && parsed != 32 {
        return Err("KMS_NUMBER_OF_BYTES must be 16 or 32".to_string());
    }

    Ok(parsed)
}

fn parse_encryption_context(value: &str) -> Result<HashMap<String, String>, String> {
    let mut context = HashMap::new();

    for item in parse_csv(value) {
        let (key, value) = item.split_once('=').ok_or_else(|| {
            format!("invalid KMS_ENCRYPTION_CONTEXT item '{item}', expected key=value")
        })?;
        let key = key.trim();
        let value = value.trim();

        if key.is_empty() || value.is_empty() {
            return Err(format!(
                "invalid KMS_ENCRYPTION_CONTEXT item '{item}', key and value must be non-empty"
            ));
        }

        context.insert(key.to_string(), value.to_string());
    }

    Ok(context)
}

fn parse_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn parse_bool(name: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" | "1" | "yes" | "y" => Ok(true),
        "false" | "0" | "no" | "n" => Ok(false),
        other => Err(format!("{name} must be true or false, got '{other}'")),
    }
}

fn decode_base64(name: &str, value: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(value)
        .map_err(|error| format!("{name} is not valid base64: {error}"))
}

fn decode_fixed_base64<const N: usize>(name: &str, value: &str) -> Result<[u8; N], String> {
    fixed_bytes(name, &decode_base64(name, value)?)
}

fn fixed_bytes<const N: usize>(name: &str, bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{name} must be {N} bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests {
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
            fixed_bytes::<ED25519_PRIVATE_KEY_LENGTH>("private key", &restored_private_key)
                .unwrap();
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
}
