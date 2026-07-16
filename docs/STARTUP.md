# 启动运行手册

本文分别说明本地开发环境和 AWS Nitro Enclave 生产环境的完整启动流程。

## 端口约定

| 端口 | 服务 | 连接方向 |
| ---: | --- | --- |
| 7001 | `parent-instance` 配置和临时凭证服务 | Enclave → Parent |
| 7002 | 项目的 `s3-proxy` | Enclave → Parent |
| 7003 | `decrypt-server-tee` Hello RPC | Parent → Enclave |
| 8000 | Nitro CLI 官方 `vsock-proxy`，转发 KMS TLS | Enclave → Parent |

Vsock 中 CID 标识通信主机而不是进程。Parent 在 Enclave 中固定表现为 CID `3`；Enclave CID 由 `nitro-cli run-enclave --enclave-cid` 指定，本文示例使用 `16`。

## 本地开发环境

本地模式使用 TCP：

```text
parent-instance     tcp:127.0.0.1:7001
s3-proxy            tcp:127.0.0.1:7002
decrypt-server-tee  tcp:127.0.0.1:7003
```

### 1. 准备配置

```bash
cp .env.example .env
```

编辑 `.env`，至少配置：

```dotenv
AWS_REGION=us-east-1

KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
S3_BUCKET=your-real-bucket
S3_KEY=kms-keypair.json
KMS_KEY_SPEC=AES_256

RUNNING_IN_ENCLAVE=false

PARENT_CONFIG_ENDPOINT=tcp:127.0.0.1:7001
S3_PROXY_ENDPOINT=tcp:127.0.0.1:7002
ENCLAVE_RPC_LISTEN_ENDPOINT=tcp:127.0.0.1:7003
ENCLAVE_RPC_ENDPOINT=tcp:127.0.0.1:7003
```

AWS 凭证可以来自环境变量、默认凭证链或本机 AWS profile，例如：

```bash
export AWS_PROFILE=your-profile
```

### 2. 启动 parent-instance

终端 1：

```bash
cargo run --bin parent-instance
```

### 3. 启动 S3 Proxy

终端 2：

```bash
cargo run --bin s3-proxy
```

### 4. 启动 decrypt-server-tee

终端 3：

```bash
RUNNING_IN_ENCLAVE=false cargo run --bin decrypt-server-tee
```

程序会先从 `parent-instance` 获取配置，通过 `s3-proxy` 检查 S3 对象，然后直接使用 Rust AWS SDK 调用 KMS，生成或恢复 Ed25519 私钥。看到以下日志后，Hello RPC 已经可以调用：

```text
decrypt-server-tee: enclave RPC listening on Tcp("127.0.0.1:7003")
```

### 5. 调用 Hello RPC

终端 4：

```bash
cargo run --bin parent-instance -- hello
```

预期输出：

```text
hello from enclave
```

## Nitro Enclave 生产环境

下面假设：

```text
AWS Region       us-east-1
Enclave CID      16
Parent CID       3
配置服务端口      7001
S3 Proxy 端口    7002
Hello RPC 端口   7003
KMS Proxy 端口   8000
```

### 1. 编译 Parent 侧程序

在 Nitro Parent EC2 上执行：

```bash
cargo build \
  --release \
  --bin parent-instance \
  --bin s3-proxy
```

### 2. 构建 EIF

Linux 构建机需要安装 Docker、Nitro CLI、Rust/C 编译环境，以及 `aws-nitro-enclaves-sdk-c` 和其依赖。

构建前可确认关键头文件和库的安装位置：

```bash
find /usr /usr/local -path '*/aws/auth/credentials.h' 2>/dev/null
find /usr /usr/local -path '*/aws/nitro_enclaves/kms.h' 2>/dev/null
find /usr /usr/local -name 'libaws-nitro-enclaves-sdk-c.so*' 2>/dev/null
```

`aws/auth/credentials.h` 属于 `aws-c-auth`。如果找不到它，说明 AWS CRT 开发依赖没有完整安装，仅安装 Nitro SDK 本体不足。

```bash
NITRO_SDK_PREFIX=/usr/local \
IMAGE_TAG=aws-kms-demo-enclave:latest \
EIF_PATH=target/enclave/aws-kms-demo.eif \
./scripts/build-eif.sh
```

如果头文件和库不在同一个默认前缀，可以分别指定：

```bash
NITRO_SDK_INCLUDE=/actual/include \
NITRO_SDK_LIB_DIR=/actual/lib64 \
./scripts/build-eif.sh
```

构建脚本会把项目根目录的 `.env.enclave` 复制为 EIF 内的 `/app/.env`。如需使用其他配置文件，可以指定：

```bash
ENCLAVE_ENV_FILE=/path/to/custom.env.enclave \
./scripts/build-eif.sh
```

`.env.enclave` 会进入 EIF 并影响 PCR，因此只能放运行模式和 Vsock endpoint 等非敏感配置，不能写入 AWS 凭证、密码或其他密钥。

默认相关产物：

```text
target/enclave/aws-kms-demo.eif
target/enclave/aws-kms-demo.eif.build.json
target/enclave/aws-kms-demo.eif.describe.json
```

查看构建生成的 PCR：

```bash
cat target/enclave/aws-kms-demo.eif.build.json
```

将 PCR0 更新到 KMS Key Policy：

```json
{
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:ImageSha384": "<EIF-PCR0>"
    }
  }
}
```

每次 EIF 内容变化后 PCR0 都可能变化，必须在发布时同步更新 KMS Key Policy。生产 EIF 不要使用 debug mode。

### 3. 配置 Parent 环境

生产环境应优先使用 EC2 instance profile，不要在 `.env` 中保存长期 AWS Access Key。

```bash
export AWS_REGION=us-east-1
export KMS_KEY_ID='arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
export S3_BUCKET='your-real-bucket'
export S3_KEY='kms-keypair.json'
export KMS_KEY_SPEC='AES_256'
export PARENT_ALLOWED_ENCLAVE_CID=16
```

Parent IAM role 至少需要把以下权限限制到目标资源：

- `kms:GenerateDataKey`
- `kms:Decrypt`
- `s3:GetObject`
- `s3:PutObject`

### 4. 启动 Parent 配置/凭证服务

终端 1：

```bash
PARENT_CONFIG_ENDPOINT=vsock:0:7001 \
PARENT_ALLOWED_ENCLAVE_CID=16 \
./target/release/parent-instance
```

`vsock:0:7001` 在监听场景中表示绑定当前 Parent 的任意本地 Vsock CID。

### 5. 启动 S3 Proxy

终端 2：

```bash
S3_PROXY_ENDPOINT=vsock:0:7002 \
./target/release/s3-proxy
```

`s3-proxy` 使用 Parent 的 AWS 凭证访问 S3，并在应用层限制只能访问配置的 `s3://$S3_BUCKET/$S3_KEY`。

### 6. 启动官方 KMS vsock-proxy

终端 3：

```bash
AWS_REGION=us-east-1
sudo vsock-proxy 8000 kms.${AWS_REGION}.amazonaws.com 443
```

该进程监听 Parent 的 Vsock 端口 `8000`，并把 Enclave 内 Nitro KMS SDK 发出的 TLS 流量转发到 AWS KMS。

如果使用 `nitro-enclaves-vsock-proxy.service`，需要确认 `/etc/nitro_enclaves/vsock-proxy.yaml` 的 allowlist 包含对应区域的 KMS endpoint，并确认服务监听端口 `8000`。

### 7. 启动 Enclave

终端 4：

```bash
nitro-cli run-enclave \
  --eif-path target/enclave/aws-kms-demo.eif \
  --memory 1024 \
  --cpu-count 2 \
  --enclave-cid 16
```

查看状态：

```bash
nitro-cli describe-enclaves
```

开发调试阶段可以查看控制台：

```bash
nitro-cli console --enclave-id <ENCLAVE_ID>
```

EIF 通过 `.env.enclave` 设置：

```text
RUNNING_IN_ENCLAVE=true
PARENT_CONFIG_ENDPOINT=vsock:3:7001
S3_PROXY_ENDPOINT=vsock:3:7002
NITRO_PARENT_CID=3
NITRO_KMS_PROXY_PORT=8000
ENCLAVE_RPC_LISTEN_ENDPOINT=vsock:0:7003
```

看到以下日志后，Hello RPC 已经可以调用：

```text
decrypt-server-tee: enclave RPC listening on Vsock(...)
```

### 8. 从 Parent 调用 Enclave Hello RPC

终端 5：

```bash
ENCLAVE_RPC_ENDPOINT=vsock:16:7003 \
./target/release/parent-instance hello
```

预期输出：

```text
hello from enclave
```

这里使用 Enclave CID `16`，因为连接方向是 Parent → Enclave。Enclave 访问 Parent 配置、S3和 KMS Proxy 时，目标 CID 则固定为 `3`。

### 9. 停止 Enclave

先查询 Enclave ID：

```bash
nitro-cli describe-enclaves
```

再停止指定 Enclave：

```bash
nitro-cli terminate-enclave --enclave-id <ENCLAVE_ID>
```

## 启动顺序汇总

本地开发：

```text
1. parent-instance
2. s3-proxy
3. decrypt-server-tee
4. parent-instance hello
```

真实 Enclave：

```text
1. 更新并确认 KMS PCR policy
2. parent-instance
3. s3-proxy
4. 官方 vsock-proxy
5. nitro-cli run-enclave
6. parent-instance hello
```
