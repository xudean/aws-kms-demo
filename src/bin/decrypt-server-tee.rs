#[tokio::main]
async fn main() -> aws_kms_demo::AppResult<()> {
    aws_kms_demo::bin_support::decrypt_server_tee_main().await
}
