#[tokio::main]
async fn main() -> aws_kms_demo::AppResult<()> {
    aws_kms_demo::bin_support::parent_instance_main().await
}
