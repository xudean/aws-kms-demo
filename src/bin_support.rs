use crate::{
    DEFAULT_CONFIG_ENDPOINT, DEFAULT_PROXY_ENDPOINT, Endpoint, ParentSettings,
    request_parent_settings, run_decrypt_server_tee, serve_parent_config, serve_s3_proxy,
};
use std::env;

pub async fn decrypt_server_tee_main() -> crate::AppResult<()> {
    let _ = dotenvy::dotenv();

    let endpoint =
        env::var("PARENT_CONFIG_ENDPOINT").unwrap_or_else(|_| DEFAULT_CONFIG_ENDPOINT.to_string());
    let endpoint = Endpoint::parse(&endpoint)?;
    let proxy_endpoint = env::var("S3_PROXY_ENDPOINT")
        .or_else(|_| env::var("VSOCK_PROXY_ENDPOINT"))
        .unwrap_or_else(|_| DEFAULT_PROXY_ENDPOINT.to_string());
    let proxy_endpoint = Endpoint::parse(&proxy_endpoint)?;
    let settings = request_parent_settings(&endpoint)?;
    run_decrypt_server_tee(settings, endpoint, proxy_endpoint).await
}

pub async fn parent_instance_main() -> crate::AppResult<()> {
    let _ = dotenvy::dotenv();

    let settings = ParentSettings::from_env()?;
    let config_endpoint =
        env::var("PARENT_CONFIG_ENDPOINT").unwrap_or_else(|_| DEFAULT_CONFIG_ENDPOINT.to_string());
    let config_endpoint = Endpoint::parse(&config_endpoint)?;
    let allowed_enclave_cid = env::var("PARENT_ALLOWED_ENCLAVE_CID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| "PARENT_ALLOWED_ENCLAVE_CID must be a u32")?;

    serve_parent_config(config_endpoint, settings, allowed_enclave_cid).await
}

pub async fn s3_proxy_main() -> crate::AppResult<()> {
    let _ = dotenvy::dotenv();

    let settings = ParentSettings::from_env()?;
    let endpoint = env::var("S3_PROXY_ENDPOINT")
        .or_else(|_| env::var("VSOCK_PROXY_ENDPOINT"))
        .unwrap_or_else(|_| DEFAULT_PROXY_ENDPOINT.to_string());
    serve_s3_proxy(
        Endpoint::parse(&endpoint)?,
        settings.s3_bucket,
        settings.s3_key,
    )
    .await
}
