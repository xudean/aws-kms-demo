use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::config::Region;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::ByteStream;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::UNIX_EPOCH;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use zeroize::{Zeroize, Zeroizing};

pub mod bin_support;
mod key_material;
#[cfg(feature = "nitro-enclave")]
mod nitro_kms;

#[cfg(feature = "nitro-enclave")]
pub(crate) use key_material::GeneratedDataKey;
pub use key_material::run_decrypt_server_tee;
use key_material::{load_s3_object, save_s3_object_if_absent};

pub mod enclave_rpc {
    tonic::include_proto!("enclave.v1");
}

use enclave_rpc::enclave_service_server::{EnclaveService, EnclaveServiceServer};
use enclave_rpc::{HelloRequest, HelloResponse};

pub const DEFAULT_BROKER_ENDPOINT: &str = "tcp:127.0.0.1:7001";
pub const DEFAULT_ENCLAVE_RPC_ENDPOINT: &str = "tcp:127.0.0.1:7003";
pub const DEFAULT_NITRO_KMS_PROXY_PORT: u32 = 8000;
pub const DEFAULT_PARENT_CID: u32 = 3;
pub const DEFAULT_S3_PREFIX: &str = "kms-keypair";

const PRIVATE_KEY_ALGORITHM: &str = "ED25519";
const PRIVATE_KEY_ENCRYPTION: &str = "AES-GCM";
const ED25519_PRIVATE_KEY_LENGTH: usize = 32;
const AES_GCM_NONCE_LENGTH: usize = 12;
const MAX_JSON_FRAME_LENGTH: usize = 1024 * 1024;
const KEY_MATERIAL_VERSION: u32 = 2;
const MANIFEST_FILE_NAME: &str = "key_manifest.json";

pub type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentSettings {
    pub kms_keys: Vec<KmsKeySettings>,
    pub s3_bucket: String,
    pub s3_prefix: String,
    pub startup_mode: StartupMode,
    pub key_spec: Option<String>,
    pub number_of_bytes: Option<i32>,
    pub encryption_context: Option<HashMap<String, String>>,
    pub grant_tokens: Vec<String>,
    pub dry_run: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartupMode {
    Serve,
    InitKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KmsSlot {
    Primary,
    Backup,
}

impl KmsSlot {
    fn label(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Backup => "backup",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsKeySettings {
    pub slot: KmsSlot,
    pub key_arn: String,
    pub region: String,
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

        let primary_key_arn = required_env("KMS_PRIMARY_KEY_ARN")?;
        let backup_key_arn = required_env("KMS_BACKUP_KEY_ARN")?;

        Ok(Self {
            kms_keys: vec![
                KmsKeySettings::from_arn(KmsSlot::Primary, primary_key_arn)?,
                KmsKeySettings::from_arn(KmsSlot::Backup, backup_key_arn)?,
            ],
            s3_bucket: required_env("S3_BUCKET")?,
            s3_prefix: normalize_s3_prefix(
                optional_env("S3_PREFIX").unwrap_or_else(|| DEFAULT_S3_PREFIX.to_string()),
            )?,
            startup_mode: optional_env("DECRYPT_SERVER_TEE_MODE")
                .map(|value| parse_startup_mode(&value))
                .transpose()?
                .unwrap_or(StartupMode::Serve),
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

    fn kms_request_settings(&self, key_arn: &str) -> Result<Settings, String> {
        Ok(Settings {
            kms_key_id: key_arn.to_string(),
            key_spec: self
                .key_spec
                .clone()
                .map(|value| parse_key_spec(&value))
                .transpose()?,
            number_of_bytes: self.number_of_bytes,
            encryption_context: self.encryption_context.clone(),
            grant_tokens: self.grant_tokens.clone(),
            dry_run: self.dry_run,
        })
    }
}

impl KmsKeySettings {
    fn from_arn(slot: KmsSlot, key_arn: String) -> Result<Self, String> {
        let region = kms_region_from_arn(&key_arn)?;
        Ok(Self {
            slot,
            key_arn,
            region,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BrokerRequest {
    GetSettings,
    GetAwsCredentials {
        slot: KmsSlot,
    },
    LoadObject {
        bucket: String,
        key: String,
    },
    SaveObjectIfAbsent {
        bucket: String,
        key: String,
        body: Vec<u8>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BrokerResponse {
    Settings(ParentSettings),
    AwsCredentials(AwsCredentials),
    Object(Option<Vec<u8>>),
    Saved,
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

pub fn request_broker_settings(endpoint: &Endpoint) -> AppResult<ParentSettings> {
    match request_broker(endpoint, &BrokerRequest::GetSettings)? {
        BrokerResponse::Settings(settings) => Ok(settings),
        response => Err(format!("unexpected enclave-broker response: {response:?}").into()),
    }
}

pub fn request_broker_credentials(endpoint: &Endpoint, slot: KmsSlot) -> AppResult<AwsCredentials> {
    match request_broker(endpoint, &BrokerRequest::GetAwsCredentials { slot })? {
        BrokerResponse::AwsCredentials(credentials) => Ok(credentials),
        response => Err(format!("unexpected enclave-broker response: {response:?}").into()),
    }
}

fn request_broker(endpoint: &Endpoint, request: &BrokerRequest) -> AppResult<BrokerResponse> {
    let mut stream = connect_endpoint(endpoint)?;
    write_json_frame(&mut *stream, request)?;
    match read_json_frame::<BrokerResponse, _>(&mut *stream)? {
        BrokerResponse::Error { message } => Err(message.into()),
        response => Ok(response),
    }
}

#[derive(Debug, Default)]
pub struct EnclaveGrpcService;

#[tonic::async_trait]
impl EnclaveService for EnclaveGrpcService {
    async fn hello(
        &self,
        _request: Request<HelloRequest>,
    ) -> Result<Response<HelloResponse>, Status> {
        Ok(Response::new(HelloResponse {
            message: "hello from enclave".to_string(),
        }))
    }
}

pub async fn request_enclave_hello(endpoint: &Endpoint) -> AppResult<String> {
    use enclave_rpc::enclave_service_client::EnclaveServiceClient;

    let mut client = match endpoint {
        Endpoint::Tcp(addr) => EnclaveServiceClient::connect(format!("http://{addr}")).await?,
        Endpoint::Vsock { cid, port } => connect_enclave_vsock_client(*cid, *port).await?,
    };
    let response = client.hello(HelloRequest {}).await?.into_inner();
    Ok(response.message)
}

pub async fn serve_enclave_rpc(endpoint: Endpoint) -> AppResult<()> {
    println!("decrypt-server-tee: enclave gRPC listening on {endpoint:?}");
    let service = EnclaveServiceServer::new(EnclaveGrpcService);

    match endpoint {
        Endpoint::Tcp(addr) => {
            Server::builder()
                .add_service(service)
                .serve(addr.parse()?)
                .await?;
        }
        Endpoint::Vsock { cid, port } => {
            serve_enclave_grpc_vsock(cid, port, service).await?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn connect_enclave_vsock_client(
    cid: u32,
    port: u32,
) -> AppResult<enclave_rpc::enclave_service_client::EnclaveServiceClient<tonic::transport::Channel>>
{
    use tokio_vsock::{VsockAddr, VsockStream};
    use tower::service_fn;

    let addr = VsockAddr::new(cid, port);
    let channel = tonic::transport::Endpoint::from_static("http://enclave.vsock")
        .connect_with_connector(service_fn(move |_| async move {
            let stream = VsockStream::connect(addr).await?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
        }))
        .await?;
    Ok(enclave_rpc::enclave_service_client::EnclaveServiceClient::new(channel))
}

#[cfg(not(target_os = "linux"))]
async fn connect_enclave_vsock_client(
    _cid: u32,
    _port: u32,
) -> AppResult<enclave_rpc::enclave_service_client::EnclaveServiceClient<tonic::transport::Channel>>
{
    Err("vsock is only supported on Linux targets".into())
}

#[cfg(target_os = "linux")]
async fn serve_enclave_grpc_vsock(
    cid: u32,
    port: u32,
    service: EnclaveServiceServer<EnclaveGrpcService>,
) -> AppResult<()> {
    use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

    let cid = if cid == 0 { VMADDR_CID_ANY } else { cid };
    let incoming = VsockListener::bind(VsockAddr::new(cid, port))?.incoming();
    Server::builder()
        .add_service(service)
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn serve_enclave_grpc_vsock(
    _cid: u32,
    _port: u32,
    _service: EnclaveServiceServer<EnclaveGrpcService>,
) -> AppResult<()> {
    Err("vsock is only supported on Linux targets".into())
}

pub async fn serve_enclave_broker(
    endpoint: Endpoint,
    settings: ParentSettings,
    allowed_enclave_cid: Option<u32>,
) -> AppResult<()> {
    let sdk_config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let default_credentials_provider = sdk_config
        .credentials_provider()
        .ok_or("AWS credential provider is not configured on enclave-broker")?;
    let primary_credentials_provider =
        explicit_kms_credentials_provider("KMS_PRIMARY")?.unwrap_or(default_credentials_provider);
    let backup_credentials_provider = explicit_kms_credentials_provider("KMS_BACKUP")?;
    let credentials_providers = vec![
        (KmsSlot::Primary, Some(primary_credentials_provider)),
        (KmsSlot::Backup, backup_credentials_provider),
    ];
    let s3_client = S3Client::new(&sdk_config);
    let listener = listen_endpoint(&endpoint)?;
    println!("enclave-broker: listening on {endpoint:?}");

    loop {
        let connection = listener.accept()?;
        let mut stream = connection.stream;
        let peer_cid = connection.peer_cid;
        let settings = settings.clone();
        let credentials_providers = credentials_providers.clone();
        let s3_client = s3_client.clone();
        thread::spawn(move || {
            let response = match read_json_frame::<BrokerRequest, _>(&mut *stream) {
                Ok(_) if allowed_enclave_cid.is_some() && peer_cid != allowed_enclave_cid => {
                    BrokerResponse::Error {
                        message: format!("request from vsock CID {peer_cid:?} was rejected"),
                    }
                }
                Ok(BrokerRequest::GetSettings) => BrokerResponse::Settings(settings),
                Ok(request) => {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    match runtime.map_err(|error| error.to_string()) {
                        Ok(runtime) => {
                            let result: AppResult<BrokerResponse> = runtime.block_on(async {
                                match request {
                                    BrokerRequest::GetAwsCredentials { slot } => {
                                        let provider = find_credentials_provider(
                                            &credentials_providers,
                                            slot,
                                        )?;
                                        let credentials = provider.provide_credentials().await?;
                                        let region = settings
                                            .kms_keys
                                            .iter()
                                            .find(|key| key.slot == slot)
                                            .ok_or("KMS credential slot has no key settings")?
                                            .region
                                            .clone();
                                        Ok(BrokerResponse::AwsCredentials(AwsCredentials {
                                            region,
                                            access_key_id: credentials.access_key_id().to_string(),
                                            secret_access_key: credentials
                                                .secret_access_key()
                                                .to_string(),
                                            session_token: credentials
                                                .session_token()
                                                .map(ToString::to_string),
                                            expires_at_epoch_seconds: credentials
                                                .expiry()
                                                .and_then(|expiry| {
                                                    expiry
                                                        .duration_since(UNIX_EPOCH)
                                                        .ok()
                                                        .map(|duration| duration.as_secs())
                                                }),
                                        }))
                                    }
                                    BrokerRequest::LoadObject { bucket, key } => {
                                        validate_s3_target(
                                            &bucket,
                                            &key,
                                            &settings.s3_bucket,
                                            &settings.s3_prefix,
                                        )?;
                                        Ok(BrokerResponse::Object(
                                            load_s3_object(&s3_client, &bucket, &key).await?,
                                        ))
                                    }
                                    BrokerRequest::SaveObjectIfAbsent { bucket, key, body } => {
                                        if settings.startup_mode != StartupMode::InitKey {
                                            return Err(
                                                "enclave-broker rejects S3 writes outside init-key mode"
                                                    .into(),
                                            );
                                        }
                                        validate_s3_target(
                                            &bucket,
                                            &key,
                                            &settings.s3_bucket,
                                            &settings.s3_prefix,
                                        )?;
                                        save_s3_object_if_absent(&s3_client, &bucket, &key, body)
                                            .await?;
                                        Ok(BrokerResponse::Saved)
                                    }
                                    BrokerRequest::GetSettings => {
                                        Ok(BrokerResponse::Settings(settings))
                                    }
                                }
                            });
                            result.unwrap_or_else(|error| BrokerResponse::Error {
                                message: error.to_string(),
                            })
                        }
                        Err(message) => BrokerResponse::Error { message },
                    }
                }
                Err(error) => BrokerResponse::Error {
                    message: error.to_string(),
                },
            };
            let _ = write_json_frame(&mut *stream, &response);
        });
    }
}

fn explicit_kms_credentials_provider(
    prefix: &str,
) -> Result<Option<SharedCredentialsProvider>, String> {
    let access_key_name = format!("{prefix}_ACCESS_KEY_ID");
    let secret_key_name = format!("{prefix}_SECRET_ACCESS_KEY");
    let session_token_name = format!("{prefix}_SESSION_TOKEN");
    let access_key_id = optional_env(&access_key_name);
    let secret_access_key = optional_env(&secret_key_name);

    match (access_key_id, secret_access_key) {
        (None, None) => Ok(None),
        (Some(access_key_id), Some(secret_access_key)) => {
            let credentials = Credentials::new(
                access_key_id,
                secret_access_key,
                optional_env(&session_token_name),
                None,
                "explicit-kms-credentials",
            );
            Ok(Some(SharedCredentialsProvider::new(credentials)))
        }
        _ => Err(format!(
            "set both {access_key_name} and {secret_key_name}, or neither"
        )),
    }
}

fn find_credentials_provider(
    providers: &[(KmsSlot, Option<SharedCredentialsProvider>)],
    slot: KmsSlot,
) -> AppResult<&SharedCredentialsProvider> {
    providers
        .iter()
        .find(|(candidate, _)| *candidate == slot)
        .and_then(|(_, provider)| provider.as_ref())
        .ok_or_else(|| {
            format!(
                "no credentials provider configured for {} KMS; set KMS_{}_ACCESS_KEY_ID and KMS_{}_SECRET_ACCESS_KEY",
                slot.label(),
                slot.label().to_ascii_uppercase(),
                slot.label().to_ascii_uppercase()
            )
            .into()
        })
}

fn validate_s3_target(
    bucket: &str,
    key: &str,
    allowed_bucket: &str,
    allowed_prefix: &str,
) -> AppResult<()> {
    let allowed_object_prefix = format!("{allowed_prefix}/");
    if bucket != allowed_bucket || !key.starts_with(&allowed_object_prefix) {
        return Err(format!(
            "enclave-broker rejected s3://{bucket}/{key}; only objects below s3://{allowed_bucket}/{allowed_prefix}/ are allowed"
        )
        .into());
    }
    Ok(())
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

struct Settings {
    kms_key_id: String,
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

fn parse_startup_mode(value: &str) -> Result<StartupMode, String> {
    match value {
        "serve" => Ok(StartupMode::Serve),
        "init-key" => Ok(StartupMode::InitKey),
        other => Err(format!(
            "DECRYPT_SERVER_TEE_MODE must be serve or init-key, got '{other}'"
        )),
    }
}

fn normalize_s3_prefix(value: String) -> Result<String, String> {
    let prefix = value.trim_matches('/');
    if prefix.is_empty() {
        return Err("S3_PREFIX must not be empty".to_string());
    }
    if prefix.split('/').any(|component| component == "..") {
        return Err("S3_PREFIX must not contain '..' path components".to_string());
    }
    Ok(prefix.to_string())
}

fn kms_region_from_arn(key_arn: &str) -> Result<String, String> {
    let parts: Vec<_> = key_arn.splitn(6, ':').collect();
    if parts.len() != 6
        || parts[0] != "arn"
        || parts[2] != "kms"
        || parts[3].is_empty()
        || parts[4].is_empty()
        || !parts[5].starts_with("key/")
    {
        return Err(format!(
            "KMS key must be a full key ARN (arn:...:kms:<region>:<account>:key/<id>), got '{key_arn}'"
        ));
    }
    Ok(parts[3].to_string())
}

fn kms_account_from_arn(key_arn: &str) -> Result<String, String> {
    kms_region_from_arn(key_arn)?;
    Ok(key_arn
        .split(':')
        .nth(4)
        .expect("validated KMS ARN has an account component")
        .to_string())
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
