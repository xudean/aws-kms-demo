use crate::{
    DEFAULT_CONFIG_ENDPOINT, DEFAULT_ENCLAVE_RPC_ENDPOINT, DEFAULT_PROXY_ENDPOINT, Endpoint,
    ParentSettings, request_enclave_hello, request_parent_settings, run_decrypt_server_tee,
    serve_config_server, serve_enclave_rpc, serve_s3_proxy,
};
use std::env;
use std::path::Path;

const EIF_ENV_PATH: &str = "/app/.env";

fn load_environment() -> crate::AppResult<()> {
    if let Ok(path) = env::var("APP_ENV_FILE") {
        dotenvy::from_path(&path)
            .map_err(|error| format!("failed to load APP_ENV_FILE '{path}': {error}"))?;
        return Ok(());
    }

    if dotenvy::dotenv().is_ok() {
        return Ok(());
    }

    if Path::new(EIF_ENV_PATH).is_file() {
        dotenvy::from_path(EIF_ENV_PATH)
            .map_err(|error| format!("failed to load {EIF_ENV_PATH}: {error}"))?;
    }
    Ok(())
}

pub async fn decrypt_server_tee_main() -> crate::AppResult<()> {
    load_environment()?;

    let endpoint =
        env::var("PARENT_CONFIG_ENDPOINT").unwrap_or_else(|_| DEFAULT_CONFIG_ENDPOINT.to_string());
    let endpoint = Endpoint::parse(&endpoint)?;
    let proxy_endpoint = env::var("S3_PROXY_ENDPOINT")
        .or_else(|_| env::var("VSOCK_PROXY_ENDPOINT"))
        .unwrap_or_else(|_| DEFAULT_PROXY_ENDPOINT.to_string());
    let proxy_endpoint = Endpoint::parse(&proxy_endpoint)?;
    println!("startup: parent_config_endpoint={endpoint:?}");
    println!("startup: s3_proxy_endpoint={proxy_endpoint:?}");
    let settings = request_parent_settings(&endpoint)?;
    run_decrypt_server_tee(settings, endpoint, proxy_endpoint).await?;

    let rpc_endpoint = env::var("ENCLAVE_RPC_LISTEN_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_ENCLAVE_RPC_ENDPOINT.to_string());
    serve_enclave_rpc(Endpoint::parse(&rpc_endpoint)?)
}

pub async fn config_server_main() -> crate::AppResult<()> {
    load_environment()?;

    match env::args().nth(1).as_deref() {
        Some("hello") => {
            let endpoint = env::var("ENCLAVE_RPC_ENDPOINT")
                .unwrap_or_else(|_| DEFAULT_ENCLAVE_RPC_ENDPOINT.to_string());
            let message = request_enclave_hello(&Endpoint::parse(&endpoint)?)?;
            println!("{message}");
            return Ok(());
        }
        Some(command) => {
            return Err(
                format!("unknown config-server command '{command}'; expected hello").into(),
            );
        }
        None => {}
    }

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

    serve_config_server(config_endpoint, settings, allowed_enclave_cid).await
}

pub async fn s3_proxy_main() -> crate::AppResult<()> {
    load_environment()?;

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
