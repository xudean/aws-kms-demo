use crate::{AppResult, AwsCredentials, GeneratedDataKey, ParentSettings};
use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr;
use std::slice;
use tokio::task;
use zeroize::Zeroizing;

const ERROR_BUFFER_LENGTH: usize = 1024;

#[repr(C)]
struct NativeBuffer {
    data: *mut u8,
    len: usize,
}

unsafe extern "C" {
    fn nkms_generate_data_key(
        region: *const c_char,
        parent_cid: u32,
        proxy_port: u32,
        access_key_id: *const c_char,
        secret_access_key: *const c_char,
        session_token: *const c_char,
        key_id: *const c_char,
        key_bits: u32,
        plaintext: *mut NativeBuffer,
        ciphertext: *mut NativeBuffer,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;

    fn nkms_decrypt_data_key(
        region: *const c_char,
        parent_cid: u32,
        proxy_port: u32,
        access_key_id: *const c_char,
        secret_access_key: *const c_char,
        session_token: *const c_char,
        key_id: *const c_char,
        ciphertext: *const u8,
        ciphertext_len: usize,
        encryption_context_json: *const c_char,
        plaintext: *mut NativeBuffer,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;

    fn nkms_buffer_free(buffer: *mut NativeBuffer);
}

pub struct NitroKmsClient {
    parent_cid: u32,
    proxy_port: u32,
}

impl NitroKmsClient {
    pub fn new(parent_cid: u32, proxy_port: u32) -> Self {
        Self {
            parent_cid,
            proxy_port,
        }
    }

    pub async fn generate_data_key(
        &self,
        settings: ParentSettings,
        credentials: AwsCredentials,
    ) -> AppResult<GeneratedDataKey> {
        validate_common_options(&settings)?;
        if settings.encryption_context.is_some() {
            return Err(
                "KMS_ENCRYPTION_CONTEXT is not supported for GenerateDataKey by the Nitro C SDK high-level API"
                    .into(),
            );
        }
        let key_bits = data_key_bits(&settings)?;
        let parent_cid = self.parent_cid;
        let proxy_port = self.proxy_port;

        task::spawn_blocking(move || {
            let region = c_string("AWS region", &credentials.region)?;
            let access_key_id = c_string("AWS access key ID", &credentials.access_key_id)?;
            let secret_access_key =
                c_string("AWS secret access key", &credentials.secret_access_key)?;
            let session_token = c_string(
                "AWS session token",
                credentials.session_token.as_deref().unwrap_or(""),
            )?;
            let key_id = c_string("KMS key ID", &settings.kms_key_id)?;
            let mut plaintext = NativeBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            let mut ciphertext = NativeBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            let mut error = [0 as c_char; ERROR_BUFFER_LENGTH];

            let rc = unsafe {
                nkms_generate_data_key(
                    region.as_ptr(),
                    parent_cid,
                    proxy_port,
                    access_key_id.as_ptr(),
                    secret_access_key.as_ptr(),
                    session_token.as_ptr(),
                    key_id.as_ptr(),
                    key_bits,
                    &mut plaintext,
                    &mut ciphertext,
                    error.as_mut_ptr(),
                    error.len(),
                )
            };
            if rc != 0 {
                return Err(native_error(&error));
            }

            let plaintext_data_key = unsafe { take_native_buffer(&mut plaintext) };
            let encrypted_data_key = unsafe { take_native_buffer(&mut ciphertext) };
            Ok(GeneratedDataKey {
                plaintext_data_key: Zeroizing::new(plaintext_data_key),
                encrypted_data_key,
                kms_key_id: settings.kms_key_id,
            })
        })
        .await?
    }

    pub async fn decrypt_data_key(
        &self,
        settings: ParentSettings,
        credentials: AwsCredentials,
        encrypted_data_key: Vec<u8>,
    ) -> AppResult<Zeroizing<Vec<u8>>> {
        validate_common_options(&settings)?;
        let parent_cid = self.parent_cid;
        let proxy_port = self.proxy_port;

        task::spawn_blocking(move || {
            let region = c_string("AWS region", &credentials.region)?;
            let access_key_id = c_string("AWS access key ID", &credentials.access_key_id)?;
            let secret_access_key =
                c_string("AWS secret access key", &credentials.secret_access_key)?;
            let session_token = c_string(
                "AWS session token",
                credentials.session_token.as_deref().unwrap_or(""),
            )?;
            let key_id = c_string("KMS key ID", &settings.kms_key_id)?;
            let context_json = settings
                .encryption_context
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let context = context_json
                .as_deref()
                .map(|value| c_string("KMS encryption context", value))
                .transpose()?;
            let mut plaintext = NativeBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            let mut error = [0 as c_char; ERROR_BUFFER_LENGTH];

            let rc = unsafe {
                nkms_decrypt_data_key(
                    region.as_ptr(),
                    parent_cid,
                    proxy_port,
                    access_key_id.as_ptr(),
                    secret_access_key.as_ptr(),
                    session_token.as_ptr(),
                    key_id.as_ptr(),
                    encrypted_data_key.as_ptr(),
                    encrypted_data_key.len(),
                    context.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
                    &mut plaintext,
                    error.as_mut_ptr(),
                    error.len(),
                )
            };
            if rc != 0 {
                return Err(native_error(&error));
            }

            Ok(Zeroizing::new(unsafe {
                take_native_buffer(&mut plaintext)
            }))
        })
        .await?
    }
}

fn validate_common_options(settings: &ParentSettings) -> AppResult<()> {
    if !settings.grant_tokens.is_empty() {
        return Err(
            "KMS_GRANT_TOKENS is not supported by the Nitro C SDK high-level data-key API".into(),
        );
    }
    if settings.dry_run == Some(true) {
        return Err("KMS_DRY_RUN=true is not supported when RUNNING_IN_ENCLAVE=true".into());
    }
    Ok(())
}

fn data_key_bits(settings: &ParentSettings) -> AppResult<u32> {
    match (settings.key_spec.as_deref(), settings.number_of_bytes) {
        (Some("AES_128"), None) | (None, Some(16)) => Ok(128),
        (Some("AES_256"), None) | (None, Some(32)) => Ok(256),
        _ => Err("Nitro KMS data key must be AES_128/AES_256 or 16/32 bytes".into()),
    }
}

fn c_string(name: &str, value: &str) -> AppResult<CString> {
    CString::new(value).map_err(|_| format!("{name} contains a NUL byte").into())
}

fn native_error(buffer: &[c_char]) -> Box<dyn std::error::Error + Send + Sync> {
    let message = unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    if message.is_empty() {
        "Nitro KMS C SDK call failed".into()
    } else {
        message.into()
    }
}

unsafe fn take_native_buffer(buffer: &mut NativeBuffer) -> Vec<u8> {
    let bytes = if buffer.data.is_null() || buffer.len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(buffer.data, buffer.len) }.to_vec()
    };
    unsafe { nkms_buffer_free(buffer) };
    bytes
}
