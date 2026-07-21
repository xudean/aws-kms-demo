# 启动运行手册

本手册分别说明一次性密钥初始化、正常启动、本地开发和真实 Nitro Enclave 部署。

## 运行规则

`decrypt-server-tee` 有两个模式：

- `init-key`：显式生成一次私钥，使用两个账号的 KMS data key 分别加密，写入 S3 后退出；
- `serve`：只恢复既有私钥。资源不存在或两个 KMS 都无法恢复时退出。

正常启动绝不会自动生成密钥。恢复顺序为 primary、backup，任意一套成功即可继续启动 gRPC。

## 配置

复制示例：

```bash
cp .env.example .env
```

最少业务配置：

```dotenv
AWS_REGION=ap-southeast-1
S3_BUCKET=your-real-bucket
S3_PREFIX=kms-keypair

KMS_PRIMARY_KEY_ARN=arn:aws:kms:ap-southeast-1:111122223333:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
KMS_BACKUP_KEY_ARN=arn:aws:kms:ap-southeast-1:444455556666:key/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy

KMS_KEY_SPEC=AES_256
DECRYPT_SERVER_TEE_MODE=serve
```

必须提供完整 key ARN。程序从 ARN 解析 Region 和账号 ID。为了共用一个 KMS vsock-proxy，两把 key 当前必须位于同一个 Region。推荐把两把 key 放在不同 AWS 账号；同账号也允许运行，但启动时会打印醒目的警告，并且无法提供账号级故障或权限隔离。

primary 默认使用 AWS SDK 默认凭证链。例如可以使用 EC2 instance profile、`AWS_PROFILE`，或者标准 `AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY`。也可以显式隔离：

```dotenv
KMS_PRIMARY_ACCESS_KEY_ID=...
KMS_PRIMARY_SECRET_ACCESS_KEY=...
# KMS_PRIMARY_SESSION_TOKEN=...
```

backup 凭证：

```dotenv
KMS_BACKUP_ACCESS_KEY_ID=...
KMS_BACKUP_SECRET_ACCESS_KEY=...
# KMS_BACKUP_SESSION_TOKEN=...
```

`serve` 模式允许其中一套凭证缺失或失效：程序会尝试另一套。`init-key` 必须同时访问两把 KMS key，否则不会写入最终 manifest。

## S3 文件

```text
<S3_PREFIX>/
├── key_manifest.json
├── public_key_sha256-<fingerprint>.json
├── kms-key-<primary-key-id-last8>-<kms-arn-hash12>/
│   └── encrypted_private_key_by_kms-key-<primary-key-id-last8>_sha256-<hash>.json
└── kms-key-<backup-key-id-last8>-<kms-arn-hash12>/
    └── encrypted_private_key_by_kms-key-<backup-key-id-last8>_sha256-<hash>.json
```

目录名包含完整 KMS Key ARN 的 SHA-256 前 12 位，避免跨账号同 key ID 冲突；完整 ARN 记录在 manifest 中。

`key_manifest.json` 最后写入。程序启动时只认 manifest 中声明且 SHA-256 校验通过的文件。S3 PutObject 使用 `If-None-Match: *`，不会覆盖同名对象。

旧版 `kms-keypair.json` 不会自动迁移。如果该文件包含必须保留的现有私钥，不要删除它，也不要用 `init-key` 生成替代私钥；应先实现并执行专门的 v1 → v2 重新封装流程。

## 本地开发

本地端口：

```text
enclave-broker      tcp:127.0.0.1:7001
decrypt-server-tee  tcp:127.0.0.1:7003
```

### 流程 A：首次执行 Init Key（只执行一次）

终端 1 以 `init-key` 模式启动 broker。只有该模式允许条件写入 S3：

```bash
DECRYPT_SERVER_TEE_MODE=init-key \
cargo run --bin enclave-broker
```

终端 2 只执行一次初始化：

```bash
RUNNING_IN_ENCLAVE=false \
cargo run --bin decrypt-server-tee -- init-key
```

如果 `<S3_PREFIX>/key_manifest.json` 已存在，命令会在调用 KMS 生成新私钥前退出。即使出现并发初始化，manifest 和其他对象的条件写入也会拒绝覆盖。初始化成功后停止 `init-key` broker，不要再次执行本流程。

### 流程 B：正常启动（每次运行）

初始化完成后，先停止 `init-key` broker，然后在终端 1 以 `serve` 模式重新启动：

```bash
DECRYPT_SERVER_TEE_MODE=serve \
cargo run --bin enclave-broker
```

终端 2 启动服务：

```bash
RUNNING_IN_ENCLAVE=false \
cargo run --bin decrypt-server-tee -- serve
```

不传参数时使用 broker 下发的 `DECRYPT_SERVER_TEE_MODE`，默认是 `serve`。

调用 Hello：

```bash
cargo run --bin enclave-broker -- hello
```

## 构建 Nitro EIF

Linux 构建机需要 Docker、Nitro CLI、Rust/C 工具链，以及 `aws-nitro-enclaves-sdk-c` 和 AWS CRT 依赖。项目提供安装脚本：

```bash
./scripts/install-nitro-sdk.sh
```

默认安装到 `$HOME/.local/nitro-sdk`。随后构建 EIF：

```bash
NITRO_SDK_PREFIX="$HOME/.local/nitro-sdk" \
IMAGE_TAG=aws-kms-demo-enclave:latest \
EIF_PATH=target/enclave/aws-kms-demo.eif \
./scripts/build-eif.sh
```

如果 SDK 已安装到 `/usr/local`：

```bash
NITRO_SDK_PREFIX=/usr/local ./scripts/build-eif.sh
```

构建脚本把 `.env.enclave` 放入 EIF 的 `/app/.env`。该文件只能包含 endpoint 和运行模式等非敏感配置，不能包含 AWS 凭证、KMS/S3 业务配置或其他秘密。

构建产物：

```text
target/enclave/aws-kms-demo.eif
target/enclave/aws-kms-demo.eif.build.json
target/enclave/aws-kms-demo.eif.describe.json
```

读取 PCR：

```bash
cat target/enclave/aws-kms-demo.eif.build.json
```

两个 AWS 账号中的 KMS key policy 都必须允许对应身份，并使用新 EIF 的 PCR0 限制 attestation：

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::111122223333:role/your-role"
  },
  "Action": [
    "kms:GenerateDataKey",
    "kms:Decrypt"
  ],
  "Resource": "*",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:ImageSha384": "<EIF-PCR0>"
    }
  }
}
```

初始化结束后应从运行身份和 key policy 中移除 `kms:GenerateDataKey`。

## Parent 服务

编译 broker：

```bash
cargo build --release --bin enclave-broker
```

端口约定：

| 端口 | 服务 | 方向 |
| ---: | --- | --- |
| 7001 | enclave-broker | Enclave → Parent |
| 7003 | Enclave gRPC | Parent → Enclave |
| 8000 | KMS vsock-proxy | Enclave → Parent |

启动 KMS proxy。两把 KMS key 位于同一 Region，因此只需要一个 endpoint：

```bash
AWS_REGION=ap-southeast-1
sudo env RUST_LOG=info \
  vsock-proxy -4 8000 "kms.${AWS_REGION}.amazonaws.com" 443
```

可以检查 Vsock 监听：

```bash
pgrep -af vsock-proxy
sudo ss --vsock -lpn
```

## 在 Enclave 中执行一次性初始化

EIF 的 Docker 入口固定为 `/app/decrypt-server-tee`。`nitro-cli run-enclave` 不能像普通 shell 一样在启动时追加 `init-key` 参数，所以初始化模式由本次 Parent broker 的 `GetSettings` 响应下发。

确认 KMS proxy 已启动，并在项目 `.env` 或当前 Parent 环境中配置 S3、两把 key ARN和两套凭证，然后运行：

```bash
./scripts/init-key-in-enclave.sh
```

常用覆盖参数：

```bash
EIF_PATH=/opt/enclave/aws-kms-demo.eif \
BROKER_BIN=/opt/enclave/enclave-broker \
ENCLAVE_CID=16 \
ENCLAVE_MEMORY_MIB=1024 \
ENCLAVE_CPU_COUNT=2 \
INIT_TIMEOUT_SECONDS=300 \
./scripts/init-key-in-enclave.sh
```

脚本执行：

1. 以 `DECRYPT_SERVER_TEE_MODE=init-key` 启动临时 broker；
2. 启动 EIF；
3. enclave 生成一次私钥和两套独立恢复包；
4. 两套 KMS 都完成回读解密校验后，最后写入 manifest；
5. 初始化进程退出，脚本停止临时 broker。

初始化脚本依赖 `jq`。它不会启动 KMS proxy，也不会覆盖任何已有 S3 对象。

初始化完成后确认：

```bash
aws s3api head-object \
  --bucket "$S3_BUCKET" \
  --key "${S3_PREFIX%/}/key_manifest.json"
```

## Enclave 正常启动

启动正常 broker：

```bash
DECRYPT_SERVER_TEE_MODE=serve \
ENCLAVE_BROKER_LISTEN_ENDPOINT=vsock:0:7001 \
ENCLAVE_BROKER_ALLOWED_CID=16 \
./target/release/enclave-broker
```

然后启动 enclave：

```bash
nitro-cli run-enclave \
  --eif-path target/enclave/aws-kms-demo.eif \
  --memory 1024 \
  --cpu-count 2 \
  --enclave-cid 16
```

Enclave 会加载 manifest 和公钥，优先尝试 primary。primary 的凭证不可用、恢复包缺失、hash 错误、KMS Decrypt 失败或 AES-GCM 解密失败时，会继续尝试 backup。任意一个成功后启动 gRPC；两个都失败则 enclave 主进程退出。

调用 Hello：

```bash
ENCLAVE_RPC_ENDPOINT=vsock:16:7003 \
./target/release/enclave-broker hello
```

## IAM 最小权限

正常运行身份：

- S3：目标 prefix 下的 `s3:GetObject`；
- primary KMS 身份：primary key 的 `kms:Decrypt`；
- backup KMS 身份：backup key 的 `kms:Decrypt`。

初始化期间额外需要：

- S3：目标 prefix 下的 `s3:PutObject`；
- 两个 KMS 身份：对应 key 的 `kms:GenerateDataKey`。

S3 `PutObject` 是条件写入，但 IAM 仍应在初始化结束后撤销。正常身份不应拥有 `s3:DeleteObject`。

## 安全与恢复

- plaintext data key 和私钥只在 enclave 内存中出现，并使用 `Zeroizing` 尽快清理；
- Parent broker 只接触 KMS ciphertext、加密私钥和公钥；
- 完整 Access Key ID 用作初始化时的 S3 目录标签；Secret Access Key 永远不会进入对象名或文件内容。启动时按 manifest 路径读取，不依赖当前凭证是否已经轮换；
- 两套 KMS 提供两条解密路径，但 S3 仍是密文存储点；应启用 Versioning、Object Lock、跨账号复制或其他删除保护；
- EIF 发生变化后 PCR0 会变化，必须同步更新两个 KMS key policy；
- 生产环境不要使用 `--debug-mode`。

## 验证代码

```bash
cargo fmt --all --check
cargo test --all-targets
bash -n scripts/build-eif.sh
bash -n scripts/init-key-in-enclave.sh
```
