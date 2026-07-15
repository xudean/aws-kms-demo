#[tokio::main]
async fn main() -> aws_kms_demo::AppResult<()> {
    aws_kms_demo::bin_support::s3_proxy_main().await
}
