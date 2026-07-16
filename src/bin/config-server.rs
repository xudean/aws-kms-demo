#[tokio::main]
async fn main() -> aws_kms_demo::AppResult<()> {
    aws_kms_demo::bin_support::config_server_main().await
}
