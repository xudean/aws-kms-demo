#[tokio::main]
async fn main() -> aws_kms_demo::AppResult<()> {
    aws_kms_demo::bin_support::enclave_broker_main().await
}
