use crate::{
    DEFAULT_BROKER_ENDPOINT, DEFAULT_ENCLAVE_RPC_ENDPOINT, Endpoint, ParentSettings, StartupMode,
    request_broker_settings, request_enclave_hello, run_decrypt_server_tee, serve_enclave_broker,
    serve_enclave_rpc,
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

    let broker_endpoint =
        env::var("ENCLAVE_BROKER_ENDPOINT").unwrap_or_else(|_| DEFAULT_BROKER_ENDPOINT.to_string());
    let broker_endpoint = Endpoint::parse(&broker_endpoint)?;
    println!("startup: enclave_broker_endpoint={broker_endpoint:?}");
    let mut settings = request_broker_settings(&broker_endpoint)?;
    match env::args().nth(1).as_deref() {
        Some("init-key") => settings.startup_mode = StartupMode::InitKey,
        Some("serve") => settings.startup_mode = StartupMode::Serve,
        Some(command) => {
            return Err(format!(
                "unknown decrypt-server-tee command '{command}'; expected serve or init-key"
            )
            .into());
        }
        None => {}
    }
    let startup_mode = settings.startup_mode;
    run_decrypt_server_tee(settings, broker_endpoint).await?;

    if startup_mode == StartupMode::InitKey {
        return Ok(());
    }

    let rpc_endpoint = env::var("ENCLAVE_RPC_LISTEN_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_ENCLAVE_RPC_ENDPOINT.to_string());
    serve_enclave_rpc(Endpoint::parse(&rpc_endpoint)?).await
}

pub async fn enclave_broker_main() -> crate::AppResult<()> {
    load_environment()?;

    match env::args().nth(1).as_deref() {
        Some("hello") => {
            let endpoint = env::var("ENCLAVE_RPC_ENDPOINT")
                .unwrap_or_else(|_| DEFAULT_ENCLAVE_RPC_ENDPOINT.to_string());
            let message = request_enclave_hello(&Endpoint::parse(&endpoint)?).await?;
            println!("{message}");
            return Ok(());
        }
        Some(command) => {
            return Err(
                format!("unknown enclave-broker command '{command}'; expected hello").into(),
            );
        }
        None => {}
    }

    let settings = ParentSettings::from_env()?;
    let listen_endpoint = env::var("ENCLAVE_BROKER_LISTEN_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_BROKER_ENDPOINT.to_string());
    let listen_endpoint = Endpoint::parse(&listen_endpoint)?;
    let allowed_enclave_cid = env::var("ENCLAVE_BROKER_ALLOWED_CID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| "ENCLAVE_BROKER_ALLOWED_CID must be a u32")?;

    serve_enclave_broker(listen_endpoint, settings, allowed_enclave_cid).await
}
