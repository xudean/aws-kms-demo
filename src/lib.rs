use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use aws_config::BehaviorVersion;
use aws_credential_types::provider::ProvideCredentials;
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
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::UNIX_EPOCH;
use zeroize::{Zeroize, Zeroizing};

pub mod bin_support;
#[cfg(feature = "nitro-enclave")]
mod nitro_kms;

pub const DEFAULT_CONFIG_ENDPOINT: &str = "tcp:127.0.0.1:7001";
pub const DEFAULT_PROXY_ENDPOINT: &str = "tcp:127.0.0.1:7002";
pub const DEFAULT_ENCLAVE_RPC_ENDPOINT: &str = "tcp:127.0.0.1:7003";
pub const DEFAULT_NITRO_KMS_PROXY_PORT: u32 = 8000;
pub const DEFAULT_PARENT_CID: u32 = 3;
pub const DEFAULT_S3_KEY: &str = "kms-keypair.json";

const PRIVATE_KEY_ALGORITHM: &str = "ED25519";
const PRIVATE_KEY_ENCRYPTION: &str = "AES-GCM";
const SELF_CHECK_CHALLENGE: &[u8] = b"aws-kms-demo:keypair-self-check:v1";
const ED25519_PRIVATE_KEY_LENGTH: usize = 32;
const AES_GCM_NONCE_LENGTH: usize = 12;
const ED25519_SIGNATURE_LENGTH: usize = 64;
const MAX_JSON_FRAME_LENGTH: usize = 1024 * 1024;

pub type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentSettings {
    pub kms_key_id: String,
    pub s3_bucket: String,
    pub s3_key: String,
    pub key_spec: Option<String>,
    pub number_of_bytes: Option<i32>,
    pub encryption_context: Option<HashMap<String, String>>,
    pub grant_tokens: Vec<String>,
    pub dry_run: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AwsCredentials {
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub expires_at_epoch_seconds: Option<u64>,
}

impl std::fmt::Debug for AwsCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AwsCredentials")
            .field("region", &self.region)
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

impl Drop for AwsCredentials {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        if let Some(session_token) = self.session_token.as_mut() {
            session_token.zeroize();
        }
    }
}

impl ParentSettings {
    pub fn from_env() -> Result<Self, String> {
        let key_spec = optional_env("KMS_KEY_SPEC").or_else(|| optional_env("KEY_SPEC"));
        let number_of_bytes = optional_env("KMS_NUMBER_OF_BYTES")
            .map(|value| parse_number_of_bytes(&value))
            .transpose()?;

        if key_spec.is_some() && number_of_bytes.is_some() {
            return Err("set only one of KMS_KEY_SPEC or KMS_NUMBER_OF_BYTES".to_string());
        }

        Ok(Self {
            kms_key_id: required_env("KMS_KEY_ID")?,
            s3_bucket: required_env("S3_BUCKET")?,
            s3_key: optional_env("S3_KEY").unwrap_or_else(|| DEFAULT_S3_KEY.to_string()),
            key_spec: key_spec.or_else(|| Some("AES_256".to_string())),
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

    fn into_settings(self) -> Result<Settings, String> {
        Ok(Settings {
            kms_key_id: self.kms_key_id,
            s3_bucket: self.s3_bucket,
            s3_key: self.s3_key,
            key_spec: self
                .key_spec
                .map(|value| parse_key_spec(&value))
                .transpose()?,
            number_of_bytes: self.number_of_bytes,
            encryption_context: self.encryption_context,
            grant_tokens: self.grant_tokens,
            dry_run: self.dry_run,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ParentRequest {
    GetSettings,
    GetAwsCredentials,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ParentResponse {
    Settings(ParentSettings),
    AwsCredentials(AwsCredentials),
    Error { message: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ProxyRequest {
    LoadKeyMaterial {
        bucket: String,
        key: String,
    },
    SaveKeyMaterial {
        bucket: String,
        key: String,
        material: KeyMaterial,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ProxyResponse {
    KeyMaterial(Option<KeyMaterial>),
    Saved,
    Error { message: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EnclaveRequest {
    Hello,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EnclaveResponse {
    Hello { message: String },
    Error { message: String },
}

#[derive(Debug, Clone)]
pub enum Endpoint {
    Tcp(String),
    Vsock { cid: u32, port: u32 },
}

impl Endpoint {
    pub fn parse(value: &str) -> Result<Self, String> {
        if let Some(addr) = value.strip_prefix("tcp:") {
            if addr.is_empty() {
                return Err("tcp endpoint must be tcp:host:port".to_string());
            }
            return Ok(Self::Tcp(addr.to_string()));
        }

        if let Some(rest) = value.strip_prefix("vsock:") {
            let (cid, port) = rest
                .split_once(':')
                .ok_or_else(|| "vsock endpoint must be vsock:cid:port".to_string())?;
            return Ok(Self::Vsock {
                cid: cid
                    .parse()
                    .map_err(|_| format!("invalid vsock cid '{cid}'"))?,
                port: port
                    .parse()
                    .map_err(|_| format!("invalid vsock port '{port}'"))?,
            });
        }

        Err(format!(
            "unsupported endpoint '{value}', expected tcp:host:port or vsock:cid:port"
        ))
    }
}

pub trait ReadWrite: Read + Write + Send {
    fn try_clone_stream(&self) -> AppResult<Box<dyn ReadWrite>>;
}

impl ReadWrite for TcpStream {
    fn try_clone_stream(&self) -> AppResult<Box<dyn ReadWrite>> {
        Ok(Box::new(self.try_clone()?))
    }
}

pub fn connect_endpoint(endpoint: &Endpoint) -> AppResult<Box<dyn ReadWrite>> {
    match endpoint {
        Endpoint::Tcp(addr) => Ok(Box::new(TcpStream::connect(addr)?)),
        Endpoint::Vsock { cid, port } => connect_vsock(*cid, *port),
    }
}

pub fn listen_endpoint(endpoint: &Endpoint) -> AppResult<Listener> {
    match endpoint {
        Endpoint::Tcp(addr) => Ok(Listener::Tcp(TcpListener::bind(addr)?)),
        Endpoint::Vsock { cid, port } => listen_vsock(*cid, *port),
    }
}

pub enum Listener {
    Tcp(TcpListener),
    Vsock(VsockListener),
}

pub struct AcceptedConnection {
    pub stream: Box<dyn ReadWrite>,
    pub peer_cid: Option<u32>,
}

impl Listener {
    pub fn accept(&self) -> AppResult<AcceptedConnection> {
        match self {
            Listener::Tcp(listener) => Ok(AcceptedConnection {
                stream: Box::new(listener.accept()?.0),
                peer_cid: None,
            }),
            Listener::Vsock(listener) => listener.accept(),
        }
    }
}

pub enum VsockListener {
    Unsupported,
    #[cfg(target_os = "linux")]
    Linux(std::os::fd::OwnedFd),
}

impl VsockListener {
    fn accept(&self) -> AppResult<AcceptedConnection> {
        match self {
            Self::Unsupported => Err("vsock is only supported on Linux targets".into()),
            #[cfg(target_os = "linux")]
            Self::Linux(fd) => linux_vsock_accept(fd),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn connect_vsock(_cid: u32, _port: u32) -> AppResult<Box<dyn ReadWrite>> {
    Err("vsock is only supported on Linux targets".into())
}

#[cfg(not(target_os = "linux"))]
fn listen_vsock(_cid: u32, _port: u32) -> AppResult<Listener> {
    Err("vsock is only supported on Linux targets".into())
}

#[cfg(target_os = "linux")]
fn connect_vsock(cid: u32, port: u32) -> AppResult<Box<dyn ReadWrite>> {
    linux_vsock_connect(cid, port)
}

#[cfg(target_os = "linux")]
fn listen_vsock(cid: u32, port: u32) -> AppResult<Listener> {
    linux_vsock_listen(cid, port)
}

#[cfg(target_os = "linux")]
mod linux_vsock {
    use super::{AcceptedConnection, AppResult, Listener, ReadWrite, VsockListener};
    use std::fs::File;
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const AF_VSOCK: i32 = 40;
    const SOCK_STREAM: i32 = 1;
    const VMADDR_CID_ANY: u32 = 0xffff_ffff;

    #[repr(C)]
    struct SockAddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    unsafe extern "C" {
        fn socket(domain: i32, type_: i32, protocol: i32) -> i32;
        fn connect(sockfd: i32, addr: *const SockAddrVm, addrlen: u32) -> i32;
        fn bind(sockfd: i32, addr: *const SockAddrVm, addrlen: u32) -> i32;
        fn listen(sockfd: i32, backlog: i32) -> i32;
        fn accept(sockfd: i32, addr: *mut SockAddrVm, addrlen: *mut u32) -> i32;
    }

    fn sockaddr(cid: u32, port: u32) -> SockAddrVm {
        SockAddrVm {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: cid,
            svm_zero: [0; 4],
        }
    }

    pub fn connect_vsock(cid: u32, port: u32) -> AppResult<Box<dyn ReadWrite>> {
        let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let addr = sockaddr(cid, port);
        let rc = unsafe { connect(fd, &addr, mem::size_of::<SockAddrVm>() as u32) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                drop(File::from_raw_fd(fd));
            }
            return Err(error.into());
        }

        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Box::new(file))
    }

    pub fn listen_vsock(cid: u32, port: u32) -> AppResult<Listener> {
        let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let bind_cid = if cid == 0 { VMADDR_CID_ANY } else { cid };
        let addr = sockaddr(bind_cid, port);
        let rc = unsafe { bind(fd, &addr, mem::size_of::<SockAddrVm>() as u32) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                drop(File::from_raw_fd(fd));
            }
            return Err(error.into());
        }

        let rc = unsafe { listen(fd, 128) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                drop(File::from_raw_fd(fd));
            }
            return Err(error.into());
        }

        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Listener::Vsock(VsockListener::Linux(owned)))
    }

    pub fn accept_vsock(fd: &OwnedFd) -> AppResult<AcceptedConnection> {
        let mut addr = sockaddr(0, 0);
        let mut len = mem::size_of::<SockAddrVm>() as u32;
        let client = unsafe { accept(fd.as_raw_fd(), &mut addr, &mut len) };
        if client < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let file = unsafe { File::from_raw_fd(client) };
        Ok(AcceptedConnection {
            stream: Box::new(file),
            peer_cid: Some(addr.svm_cid),
        })
    }

    impl super::ReadWrite for File {
        fn try_clone_stream(&self) -> AppResult<Box<dyn super::ReadWrite>> {
            Ok(Box::new(self.try_clone()?))
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_vsock_connect(cid: u32, port: u32) -> AppResult<Box<dyn ReadWrite>> {
    linux_vsock::connect_vsock(cid, port)
}

#[cfg(target_os = "linux")]
fn linux_vsock_listen(cid: u32, port: u32) -> AppResult<Listener> {
    linux_vsock::listen_vsock(cid, port)
}

#[cfg(target_os = "linux")]
fn linux_vsock_accept(fd: &std::os::fd::OwnedFd) -> AppResult<AcceptedConnection> {
    linux_vsock::accept_vsock(fd)
}

pub fn write_json_frame<T: Serialize, W: Write + ?Sized>(
    writer: &mut W,
    value: &T,
) -> AppResult<()> {
    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_JSON_FRAME_LENGTH {
        return Err(format!(
            "JSON frame is {} bytes; maximum is {MAX_JSON_FRAME_LENGTH}",
            payload.len()
        )
        .into());
    }
    let len = u32::try_from(payload.len())?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_json_frame<T: for<'de> Deserialize<'de>, R: Read + ?Sized>(
    reader: &mut R,
) -> AppResult<T> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_JSON_FRAME_LENGTH {
        return Err(
            format!("JSON frame is {len} bytes; maximum is {MAX_JSON_FRAME_LENGTH}").into(),
        );
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

pub fn request_parent_settings(endpoint: &Endpoint) -> AppResult<ParentSettings> {
    let mut stream = connect_endpoint(endpoint)?;
    write_json_frame(&mut *stream, &ParentRequest::GetSettings)?;
    match read_json_frame::<ParentResponse, _>(&mut *stream)? {
        ParentResponse::Settings(settings) => Ok(settings),
        ParentResponse::Error { message } => Err(message.into()),
        _ => Err("parent-instance returned credentials for a settings request".into()),
    }
}

pub fn request_parent_credentials(endpoint: &Endpoint) -> AppResult<AwsCredentials> {
    let mut stream = connect_endpoint(endpoint)?;
    write_json_frame(&mut *stream, &ParentRequest::GetAwsCredentials)?;
    match read_json_frame::<ParentResponse, _>(&mut *stream)? {
        ParentResponse::AwsCredentials(credentials) => Ok(credentials),
        ParentResponse::Error { message } => Err(message.into()),
        _ => Err("parent-instance returned settings for a credentials request".into()),
    }
}

pub fn request_enclave_hello(endpoint: &Endpoint) -> AppResult<String> {
    let mut stream = connect_endpoint(endpoint)?;
    write_json_frame(&mut *stream, &EnclaveRequest::Hello)?;
    match read_json_frame::<EnclaveResponse, _>(&mut *stream)? {
        EnclaveResponse::Hello { message } => Ok(message),
        EnclaveResponse::Error { message } => Err(message.into()),
    }
}

pub fn serve_enclave_rpc(endpoint: Endpoint) -> AppResult<()> {
    let listener = listen_endpoint(&endpoint)?;
    println!("decrypt-server-tee: enclave RPC listening on {endpoint:?}");

    loop {
        let connection = listener.accept()?;
        let mut stream = connection.stream;
        thread::spawn(move || {
            let response = match read_json_frame::<EnclaveRequest, _>(&mut *stream) {
                Ok(request) => handle_enclave_request(request),
                Err(error) => EnclaveResponse::Error {
                    message: error.to_string(),
                },
            };
            let _ = write_json_frame(&mut *stream, &response);
        });
    }
}

fn handle_enclave_request(request: EnclaveRequest) -> EnclaveResponse {
    match request {
        EnclaveRequest::Hello => EnclaveResponse::Hello {
            message: "hello from enclave".to_string(),
        },
    }
}

pub async fn serve_parent_config(
    endpoint: Endpoint,
    settings: ParentSettings,
    allowed_enclave_cid: Option<u32>,
) -> AppResult<()> {
    let sdk_config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let credentials_provider = sdk_config
        .credentials_provider()
        .ok_or("AWS credential provider is not configured on parent-instance")?;
    let region = sdk_config
        .region()
        .map(ToString::to_string)
        .ok_or("AWS region is not configured on parent-instance")?;
    let listener = listen_endpoint(&endpoint)?;
    println!("parent-instance: config/credentials listening on {endpoint:?}");

    loop {
        let connection = listener.accept()?;
        let mut stream = connection.stream;
        let peer_cid = connection.peer_cid;
        let settings = settings.clone();
        let credentials_provider = credentials_provider.clone();
        let region = region.clone();
        thread::spawn(move || {
            let response = match read_json_frame::<ParentRequest, _>(&mut *stream) {
                Ok(ParentRequest::GetSettings) => ParentResponse::Settings(settings),
                Ok(ParentRequest::GetAwsCredentials)
                    if allowed_enclave_cid.is_some() && peer_cid != allowed_enclave_cid =>
                {
                    ParentResponse::Error {
                        message: format!(
                            "credential request from vsock CID {peer_cid:?} was rejected"
                        ),
                    }
                }
                Ok(ParentRequest::GetAwsCredentials) => {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    match runtime
                        .map_err(|error| error.to_string())
                        .and_then(|runtime| {
                            runtime
                                .block_on(credentials_provider.provide_credentials())
                                .map_err(|error| error.to_string())
                        }) {
                        Ok(credentials) => ParentResponse::AwsCredentials(AwsCredentials {
                            region,
                            access_key_id: credentials.access_key_id().to_string(),
                            secret_access_key: credentials.secret_access_key().to_string(),
                            session_token: credentials.session_token().map(ToString::to_string),
                            expires_at_epoch_seconds: credentials.expiry().and_then(|expiry| {
                                expiry
                                    .duration_since(UNIX_EPOCH)
                                    .ok()
                                    .map(|duration| duration.as_secs())
                            }),
                        }),
                        Err(message) => ParentResponse::Error { message },
                    }
                }
                Err(error) => ParentResponse::Error {
                    message: error.to_string(),
                },
            };
            let _ = write_json_frame(&mut *stream, &response);
        });
    }
}

pub async fn serve_s3_proxy(
    endpoint: Endpoint,
    allowed_bucket: String,
    allowed_key: String,
) -> AppResult<()> {
    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let s3_client = S3Client::new(&config);
    let listener = listen_endpoint(&endpoint)?;
    println!("s3-proxy: listening on {endpoint:?}");

    loop {
        let connection = listener.accept()?;
        let mut stream = connection.stream;
        let s3_client = s3_client.clone();
        let allowed_bucket = allowed_bucket.clone();
        let allowed_key = allowed_key.clone();
        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = write_json_frame(&mut *stream, &ProxyResponse::Error {
                        message: error.to_string(),
                    });
                    return;
                }
            };

            let response = runtime.block_on(async {
                match read_json_frame::<ProxyRequest, _>(&mut *stream) {
                    Ok(request) => {
                        handle_s3_proxy_request(&s3_client, &allowed_bucket, &allowed_key, request)
                            .await
                    }
                    Err(error) => ProxyResponse::Error {
                        message: error.to_string(),
                    },
                }
            });
            let _ = write_json_frame(&mut *stream, &response);
        });
    }
}

async fn handle_s3_proxy_request(
    s3_client: &S3Client,
    allowed_bucket: &str,
    allowed_key: &str,
    request: ProxyRequest,
) -> ProxyResponse {
    match handle_s3_proxy_request_result(s3_client, allowed_bucket, allowed_key, request).await {
        Ok(response) => response,
        Err(error) => ProxyResponse::Error {
            message: error.to_string(),
        },
    }
}

async fn handle_s3_proxy_request_result(
    s3_client: &S3Client,
    allowed_bucket: &str,
    allowed_key: &str,
    request: ProxyRequest,
) -> AppResult<ProxyResponse> {
    match request {
        ProxyRequest::LoadKeyMaterial { bucket, key } => {
            validate_s3_target(&bucket, &key, allowed_bucket, allowed_key)?;
            Ok(ProxyResponse::KeyMaterial(
                load_key_material(s3_client, &bucket, &key).await?,
            ))
        }
        ProxyRequest::SaveKeyMaterial {
            bucket,
            key,
            material,
        } => {
            validate_s3_target(&bucket, &key, allowed_bucket, allowed_key)?;
            save_key_material(s3_client, &bucket, &key, &material).await?;
            Ok(ProxyResponse::Saved)
        }
    }
}

fn validate_s3_target(
    bucket: &str,
    key: &str,
    allowed_bucket: &str,
    allowed_key: &str,
) -> AppResult<()> {
    if bucket != allowed_bucket || key != allowed_key {
        return Err(format!(
            "s3-proxy rejected s3://{bucket}/{key}; only s3://{allowed_bucket}/{allowed_key} is allowed"
        )
        .into());
    }
    Ok(())
}

pub async fn run_decrypt_server_tee(
    settings: ParentSettings,
    config_endpoint: Endpoint,
    s3_proxy_endpoint: Endpoint,
) -> AppResult<()> {
    let s3_client = S3ProxyClient::new(s3_proxy_endpoint);
    let kms_client = KmsDataKeyClient::from_env(config_endpoint).await?;
    let runtime_settings = settings.clone().into_settings()?;
    println!("config: loaded from parent-instance");
    println!("config: kms_key_id={}", runtime_settings.kms_key_id);
    println!("config: s3_bucket={}", runtime_settings.s3_bucket);
    println!("config: s3_key={}", runtime_settings.s3_key);

    println!(
        "startup: checking key material at s3://{}/{}",
        runtime_settings.s3_bucket, runtime_settings.s3_key
    );
    match s3_client
        .load_key_material(&runtime_settings.s3_bucket, &runtime_settings.s3_key)
        .await?
    {
        Some(stored) => {
            println!(
                "found key material in s3://{}/{}; restoring key pair",
                runtime_settings.s3_bucket, runtime_settings.s3_key
            );
            let restored = restore_key_pair(&kms_client, settings, stored).await?;

            println!("mode: restore");
            println!(
                "public_key_base64: {}",
                STANDARD.encode(restored.public_key)
            );
        }
        None => {
            println!(
                "no key material found in s3://{}/{}; generating key pair",
                runtime_settings.s3_bucket, runtime_settings.s3_key
            );
            let generated = generate_key_pair(&kms_client, settings.clone()).await?;
            s3_client
                .save_key_material(
                    &runtime_settings.s3_bucket,
                    &runtime_settings.s3_key,
                    &generated,
                )
                .await?;

            println!("mode: generate");
            println!("public_key_base64: {}", generated.public_key_base64);
            println!(
                "uploaded: s3://{}/{}",
                runtime_settings.s3_bucket, runtime_settings.s3_key
            );
        }
    }

    Ok(())
}

struct S3ProxyClient {
    endpoint: Endpoint,
}

impl S3ProxyClient {
    fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    async fn load_key_material(&self, bucket: &str, key: &str) -> AppResult<Option<KeyMaterial>> {
        match self.request(ProxyRequest::LoadKeyMaterial {
            bucket: bucket.to_string(),
            key: key.to_string(),
        })? {
            ProxyResponse::KeyMaterial(material) => Ok(material),
            response => Err(format!("unexpected proxy response: {response:?}").into()),
        }
    }

    async fn save_key_material(
        &self,
        bucket: &str,
        key: &str,
        material: &KeyMaterial,
    ) -> AppResult<()> {
        match self.request(ProxyRequest::SaveKeyMaterial {
            bucket: bucket.to_string(),
            key: key.to_string(),
            material: material.clone(),
        })? {
            ProxyResponse::Saved => Ok(()),
            response => Err(format!("unexpected proxy response: {response:?}").into()),
        }
    }

    fn request(&self, request: ProxyRequest) -> AppResult<ProxyResponse> {
        let mut stream = connect_endpoint(&self.endpoint)?;
        write_json_frame(&mut *stream, &request)?;
        match read_json_frame::<ProxyResponse, _>(&mut *stream)? {
            ProxyResponse::Error { message } => Err(message.into()),
            response => Ok(response),
        }
    }
}

enum KmsDataKeyClient {
    Local(KmsClient),
    #[cfg(feature = "nitro-enclave")]
    Nitro {
        client: nitro_kms::NitroKmsClient,
        config_endpoint: Endpoint,
    },
}

impl KmsDataKeyClient {
    async fn from_env(config_endpoint: Endpoint) -> AppResult<Self> {
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
            let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
            return Ok(Self::Local(KmsClient::new(&config)));
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
                config_endpoint,
            })
        }
        #[cfg(not(feature = "nitro-enclave"))]
        {
            let _ = config_endpoint;
            Err(
                "RUNNING_IN_ENCLAVE=true requires building decrypt-server-tee with --features nitro-enclave"
                    .into(),
            )
        }
    }

    async fn generate_data_key(&self, settings: ParentSettings) -> AppResult<GeneratedDataKey> {
        match self {
            Self::Local(client) => {
                let runtime_settings = settings.into_settings()?;
                call_generate_data_key(client, &runtime_settings).await
            }
            #[cfg(feature = "nitro-enclave")]
            Self::Nitro {
                client,
                config_endpoint,
            } => {
                let credentials = request_parent_credentials(config_endpoint)?;
                client.generate_data_key(settings, credentials).await
            }
        }
    }

    async fn decrypt_data_key(
        &self,
        settings: ParentSettings,
        encrypted_data_key: Vec<u8>,
    ) -> AppResult<Zeroizing<Vec<u8>>> {
        match self {
            Self::Local(client) => {
                let runtime_settings = settings.into_settings()?;
                call_decrypt_data_key(client, &runtime_settings, encrypted_data_key).await
            }
            #[cfg(feature = "nitro-enclave")]
            Self::Nitro {
                client,
                config_endpoint,
            } => {
                let credentials = request_parent_credentials(config_endpoint)?;
                client
                    .decrypt_data_key(settings, credentials, encrypted_data_key)
                    .await
            }
        }
    }
}

pub(crate) struct GeneratedDataKey {
    plaintext_data_key: Zeroizing<Vec<u8>>,
    encrypted_data_key: Vec<u8>,
    kms_key_id: String,
}

async fn generate_key_pair(
    kms_client: &KmsDataKeyClient,
    settings: ParentSettings,
) -> AppResult<KeyMaterial> {
    println!("generation: calling KMS GenerateDataKey");
    let output = kms_client.generate_data_key(settings).await?;
    let plaintext_data_key = output.plaintext_data_key;
    let encrypted_data_key = output.encrypted_data_key;

    validate_data_key_len(&plaintext_data_key)?;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; ED25519_PRIVATE_KEY_LENGTH]>());
    let private_key = signing_key.to_bytes();
    let public_key = signing_key.verifying_key().to_bytes();
    let self_check_signature: Signature = signing_key.sign(SELF_CHECK_CHALLENGE);
    let nonce = rand::random::<[u8; AES_GCM_NONCE_LENGTH]>();
    let encrypted_private_key = encrypt_private_key(&plaintext_data_key, &nonce, &private_key)?;

    Ok(KeyMaterial {
        version: 1,
        private_key_algorithm: PRIVATE_KEY_ALGORITHM.to_string(),
        private_key_encryption: PRIVATE_KEY_ENCRYPTION.to_string(),
        kms_key_id: output.kms_key_id,
        encrypted_data_key_base64: STANDARD.encode(encrypted_data_key),
        private_key_nonce_base64: STANDARD.encode(nonce),
        encrypted_private_key_base64: STANDARD.encode(encrypted_private_key),
        public_key_base64: STANDARD.encode(public_key),
        self_check_signature_base64: Some(STANDARD.encode(self_check_signature.to_bytes())),
    })
}

async fn restore_key_pair(
    kms_client: &KmsDataKeyClient,
    settings: ParentSettings,
    stored: KeyMaterial,
) -> AppResult<RestoredKeyPair> {
    validate_key_material_header(&stored)?;

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
    verifying_key.verify(SELF_CHECK_CHALLENGE, &stored_signature)?;

    let plaintext_data_key = kms_client
        .decrypt_data_key(settings, encrypted_data_key)
        .await?;

    validate_data_key_len(&plaintext_data_key)?;

    let private_key = decrypt_private_key(&plaintext_data_key, &nonce, &encrypted_private_key)?;
    let private_key = fixed_bytes::<ED25519_PRIVATE_KEY_LENGTH>("private key", &private_key)?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let actual_public_key = signing_key.verifying_key().to_bytes();

    if actual_public_key != expected_public_key {
        return Err("restored private key does not match stored public key".into());
    }

    let restored_signature: Signature = signing_key.sign(SELF_CHECK_CHALLENGE);
    if restored_signature.to_bytes() != stored_signature.to_bytes() {
        return Err(
            "restored private key signature does not match stored self-check signature".into(),
        );
    }
    verifying_key.verify(SELF_CHECK_CHALLENGE, &restored_signature)?;

    Ok(RestoredKeyPair {
        public_key: actual_public_key,
    })
}

async fn load_key_material(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
) -> AppResult<Option<KeyMaterial>> {
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
    let material = serde_json::from_slice::<KeyMaterial>(&bytes)?;
    Ok(Some(material))
}

async fn save_key_material(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
    material: &KeyMaterial,
) -> AppResult<()> {
    let body = serde_json::to_vec_pretty(material)?;
    println!("s3: put_object s3://{bucket}/{key}");

    s3_client
        .put_object()
        .bucket(bucket)
        .key(key)
        .content_type("application/json")
        .body(ByteStream::from(body))
        .send()
        .await?;

    Ok(())
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
    let kms_key_id = output
        .key_id()
        .unwrap_or(settings.kms_key_id.as_str())
        .to_string();

    Ok(GeneratedDataKey {
        plaintext_data_key: Zeroizing::new(plaintext_data_key),
        encrypted_data_key,
        kms_key_id,
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

pub(crate) fn encrypt_private_key(
    data_key: &[u8],
    nonce: &[u8; AES_GCM_NONCE_LENGTH],
    private_key: &[u8],
) -> AppResult<Vec<u8>> {
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

pub(crate) fn decrypt_private_key(
    data_key: &[u8],
    nonce: &[u8; AES_GCM_NONCE_LENGTH],
    encrypted_private_key: &[u8],
) -> AppResult<Vec<u8>> {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMaterial {
    pub version: u32,
    pub private_key_algorithm: String,
    pub private_key_encryption: String,
    pub kms_key_id: String,
    pub encrypted_data_key_base64: String,
    pub private_key_nonce_base64: String,
    pub encrypted_private_key_base64: String,
    pub public_key_base64: String,
    pub self_check_signature_base64: Option<String>,
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

pub(crate) fn fixed_bytes<const N: usize>(name: &str, bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{name} must be {N} bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests;
