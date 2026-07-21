# 启动运行手册

本文分别说明本地开发环境和 AWS Nitro Enclave 生产环境的完整启动流程。

## 端口约定

| 端口 | 服务 | 连接方向 |
| ---: | --- | --- |
| 7001 | `enclave-broker` 配置、临时凭证和 S3 服务 | Enclave → Parent |
| 7003 | `decrypt-server-tee` gRPC Hello | Parent → Enclave |
| 8000 | Nitro CLI 官方 `vsock-proxy`，转发 KMS TLS | Enclave → Parent |

Vsock 中 CID 标识通信主机而不是进程。Parent 在 Enclave 中固定表现为 CID `3`；Enclave CID 由 `nitro-cli run-enclave --enclave-cid` 指定，本文示例使用 `16`。

## 本地开发环境

本地模式使用 TCP：

```text
enclave-broker      tcp:127.0.0.1:7001
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

ENCLAVE_BROKER_LISTEN_ENDPOINT=tcp:127.0.0.1:7001
ENCLAVE_BROKER_ENDPOINT=tcp:127.0.0.1:7001
ENCLAVE_RPC_LISTEN_ENDPOINT=tcp:127.0.0.1:7003
ENCLAVE_RPC_ENDPOINT=tcp:127.0.0.1:7003
```

AWS 凭证可以来自环境变量、默认凭证链或本机 AWS profile，例如：

```bash
export AWS_PROFILE=your-profile
```

### 2. 启动 enclave-broker

终端 1：

```bash
cargo run --bin enclave-broker
```

### 3. 启动 decrypt-server-tee

终端 2：

```bash
RUNNING_IN_ENCLAVE=false cargo run --bin decrypt-server-tee
```

程序会先从 `enclave-broker` 获取配置并检查 S3 对象，然后直接使用 Rust AWS SDK 调用 KMS，生成或恢复 Ed25519 私钥。看到以下日志后，Hello RPC 已经可以调用：

```text
decrypt-server-tee: enclave gRPC listening on Tcp("127.0.0.1:7003")
```

### 4. 调用 Hello RPC

终端 3：

```bash
cargo run --bin enclave-broker -- hello
```

预期输出：

```text
hello from enclave
```

本地 TCP 模式也可以通过标准 gRPC 客户端调用：

```bash
grpcurl -plaintext \
  -import-path proto \
  -proto enclave.proto \
  127.0.0.1:7003 enclave.v1.EnclaveService/Hello
```

## Nitro Enclave 生产环境

下面假设：

```text
AWS Region       us-east-1
Enclave CID      16
Parent CID       3
Broker 端口       7001
Hello RPC 端口   7003
KMS Proxy 端口   8000
```

### 1. 编译 Parent 侧程序

在 Nitro Parent EC2 上执行：

```bash
cargo build \
  --release \
  --bin enclave-broker
```

### 2. 构建 EIF

Linux 构建机需要安装 Docker、Nitro CLI、Rust/C 编译环境，以及 `aws-nitro-enclaves-sdk-c` 和其依赖。

构建前可确认关键头文件和库的安装位置：

```bash
find /usr /usr/local -path '*/aws/auth/credentials.h' 2>/dev/null
find /usr /usr/local -path '*/aws/nitro_enclaves/kms.h' 2>/dev/null
find /usr /usr/local -name 'libaws-nitro-enclaves-sdk-c.*' 2>/dev/null
```

`aws/auth/credentials.h` 属于 `aws-c-auth`。如果找不到它，说明 AWS CRT 开发依赖没有完整安装，仅安装 Nitro SDK 本体不足。

官方 Builder 默认生成静态库，因此链接时还需要显式包含 `aws-c-compression`、`aws-c-cal`、`aws-c-sdkutils`、`s2n`、NSM、json-c 和 AWS-LC crypto 等传递依赖。项目的构建脚本会检查并自动传入完整默认列表。

在 Ubuntu 上运行项目提供的安装脚本。它会自动克隆 AWS 官方仓库、构建官方 Builder 镜像，并把完整 SDK 和 AWS CRT 依赖提取到当前用户目录：

```bash
cd ~/workspace/aws-kms-demo
./scripts/install-nitro-sdk.sh
```

默认安装到 `$HOME/.local/nitro-sdk`。可以覆盖安装目录、SDK Git ref 或 Builder 镜像名：

```bash
NITRO_SDK_PREFIX="$HOME/opt/nitro-sdk" \
NITRO_SDK_REF='<tag-or-branch>' \
NITRO_SDK_BUILDER_IMAGE='aws-nitro-enclaves-sdk-c-builder:custom' \
./scripts/install-nitro-sdk.sh
```

安装脚本不会覆盖已经存在的目录。如需重装，应先明确删除旧目录，或者选择新的 `NITRO_SDK_PREFIX`。

下面是安装脚本内部执行的等价手工流程，通常不需要手动执行：

```bash
cd ~/workspace
git clone --depth 1 \
  https://github.com/aws/aws-nitro-enclaves-sdk-c.git

cd aws-nitro-enclaves-sdk-c
docker build \
  -f containers/Dockerfile.al2 \
  --target builder \
  -t aws-nitro-enclaves-sdk-c-builder .

SDK_PREFIX="$HOME/.local/nitro-sdk"
SDK_CONTAINER="$(docker create aws-nitro-enclaves-sdk-c-builder)"

mkdir -p \
  "$SDK_PREFIX/include/aws" \
  "$SDK_PREFIX/include/json-c" \
  "$SDK_PREFIX/lib"

docker cp "$SDK_CONTAINER:/usr/include/aws/." "$SDK_PREFIX/include/aws"
docker cp "$SDK_CONTAINER:/usr/include/json-c/." "$SDK_PREFIX/include/json-c"
docker cp "$SDK_CONTAINER:/usr/include/nsm.h" "$SDK_PREFIX/include/nsm.h"

docker run --rm --entrypoint /bin/sh \
  aws-nitro-enclaves-sdk-c-builder -c '
    find /usr/lib64 -maxdepth 1 \
      \( -name "libaws*" -o -name "libs2n*" -o -name "libnsm*" \
      -o -name "libjson-c*" -o -name "libcrypto*" -o -name "libssl*" \) \
      -printf "%f\n" | sort -u
  ' | while read -r library; do
    docker cp -L \
      "$SDK_CONTAINER:/usr/lib64/$library" \
      "$SDK_PREFIX/lib/$library"
  done

docker rm "$SDK_CONTAINER"
```

确认提取成功：

```bash
test -f "$HOME/.local/nitro-sdk/include/aws/auth/credentials.h"
test -f "$HOME/.local/nitro-sdk/include/aws/nitro_enclaves/kms.h"
find "$HOME/.local/nitro-sdk/lib" \
  -name 'libaws-nitro-enclaves-sdk-c.*'
```

然后使用该前缀构建项目：

```bash
cd ~/workspace/aws-kms-demo

NITRO_SDK_PREFIX="$HOME/.local/nitro-sdk" \
IMAGE_TAG=aws-kms-demo-enclave:latest \
EIF_PATH=target/enclave/aws-kms-demo.eif \
./scripts/build-eif.sh
```

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

EIF 镜像设置 `APP_ENV_FILE=/app/.env`，应用会按绝对路径加载该文件，不依赖 Enclave 启动时的工作目录。如果应用日志显示 `Network is unreachable`，先确认启动日志中的 endpoint 是 `Vsock` 而不是默认的 `Tcp("127.0.0.1:...")`。

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
export ENCLAVE_BROKER_ALLOWED_CID=16
```

Parent IAM role 至少需要把以下权限限制到目标资源：

- `kms:GenerateDataKey`
- `kms:Decrypt`
- `s3:GetObject`
- `s3:PutObject`

### 4. 启动 Enclave Broker

终端 1：

```bash
ENCLAVE_BROKER_LISTEN_ENDPOINT=vsock:0:7001 \
ENCLAVE_BROKER_ALLOWED_CID=16 \
./target/release/enclave-broker
```

`vsock:0:7001` 在监听场景中表示绑定当前 Parent 的任意本地 Vsock CID。

`enclave-broker` 使用 Parent 的 AWS 凭证访问 S3，并在应用层限制只能访问配置的 `s3://$S3_BUCKET/$S3_KEY`。`ENCLAVE_BROKER_ALLOWED_CID` 会限制配置、凭证和 S3 请求都只能来自指定 Enclave。

### 5. 启动官方 KMS vsock-proxy

终端 2：

```bash
AWS_REGION=us-east-1
KMS_HOST="kms.${AWS_REGION}.amazonaws.com"

sudo env RUST_LOG=debug \
  vsock-proxy -4 8000 "$KMS_HOST" 443
```

该进程监听 Parent 的 Vsock 端口 `8000`，并把 Enclave 内 Nitro KMS SDK 发出的 TLS 流量转发到 AWS KMS。

如果使用 `nitro-enclaves-vsock-proxy.service`，需要确认 `/etc/nitro_enclaves/vsock-proxy.yaml` 的 allowlist 包含对应区域的 KMS endpoint，并确认服务监听端口 `8000`。

#### 检查 Vsock 端口和代理状态

`8000` 是 Vsock 端口，不是 TCP/UDP 端口。因此下面这些 TCP 检查不会显示该端口：

```bash
ss -lntp
netstat -lntp
curl localhost:8000
```

成功启动的 `vsock-proxy` 默认在前台持续运行，不会立即返回 Shell 提示符。建议在终端 A 使用详细日志启动：

```bash
AWS_REGION=us-east-1
KMS_HOST="kms.${AWS_REGION}.amazonaws.com"

sudo env RUST_LOG=debug \
  vsock-proxy -4 8000 "$KMS_HOST" 443
```

然后在终端 B 检查进程和 Vsock 监听端口：

```bash
pgrep -af vsock-proxy
sudo ss --vsock -lpn
```

部分 `ss` 版本使用另一种参数形式：

```bash
sudo ss -A vsock -lpn
```

只检查端口 `8000`：

```bash
sudo ss --vsock -lpn | grep 8000
```

如果 `vsock-proxy` 立即退出，使用 trace 日志并检查退出码：

```bash
AWS_REGION=us-east-1
KMS_HOST="kms.${AWS_REGION}.amazonaws.com"

sudo env RUST_LOG=trace \
  vsock-proxy -4 8000 "$KMS_HOST" 443

echo "exit code: $?"
```

检查默认 allowlist：

```bash
sudo sed -n '1,200p' \
  /etc/nitro_enclaves/vsock-proxy.yaml
```

它应允许当前 Region 的 KMS endpoint，例如：

```yaml
allowlist:
  - address: kms.us-east-1.amazonaws.com
    port: 443
```

可以显式指定配置文件启动：

```bash
sudo env RUST_LOG=debug \
  vsock-proxy \
  --config /etc/nitro_enclaves/vsock-proxy.yaml \
  -4 \
  8000 \
  kms.us-east-1.amazonaws.com \
  443
```

如果怀疑 systemd 服务已经占用端口或启动失败，执行：

```bash
sudo systemctl status \
  nitro-enclaves-vsock-proxy.service

sudo journalctl \
  -eu nitro-enclaves-vsock-proxy.service \
  --no-pager
```

使用 systemd 启动并设置开机自启：

```bash
sudo systemctl enable --now \
  nitro-enclaves-vsock-proxy.service
```

最后确认 Parent 能解析 KMS 域名：

```bash
getent ahostsv4 kms.us-east-1.amazonaws.com
```

### 6. 启动 Enclave

终端 3：

```bash
RUST_INFO=debug
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
链接控制台
```bash

```

开发调试阶段可以查看控制台：
```bash
  # 停止某个enclave
  sudo nitro-cli terminate-enclave \
    --enclave-id <ENCLAVE_ID>

  # 以debug模式运行某个enclave，方便查看console日志。如果没有--debug-mode是没法查看日志的
  sudo nitro-cli run-enclave \
    --eif-path target/enclave/aws-kms-demo.eif \
    --memory 1024 \
    --cpu-count 2 \
    --enclave-cid 16 \
    --debug-mode \
    --attach-console

```

```bash
nitro-cli console --enclave-id <ENCLAVE_ID>
```

EIF 通过 `.env.enclave` 设置：

```text
RUNNING_IN_ENCLAVE=true
ENCLAVE_BROKER_ENDPOINT=vsock:3:7001
NITRO_PARENT_CID=3
NITRO_KMS_PROXY_PORT=8000
ENCLAVE_RPC_LISTEN_ENDPOINT=vsock:0:7003
```

看到以下日志后，Hello RPC 已经可以调用：

```text
decrypt-server-tee: enclave gRPC listening on Vsock(...)
```

### 7. 从 Parent 调用 Enclave Hello RPC

终端 4：

```bash
ENCLAVE_RPC_ENDPOINT=vsock:16:7003 \
./target/release/enclave-broker hello
```

预期输出：

```text
hello from enclave
```

这里使用 Enclave CID `16`，因为连接方向是 Parent → Enclave。Enclave 访问 Parent 配置、S3和 KMS Proxy 时，目标 CID 则固定为 `3`。

### 8. 停止 Enclave

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
1. enclave-broker
2. decrypt-server-tee
3. enclave-broker hello
```

真实 Enclave：

```text
1. 更新并确认 KMS PCR policy
2. enclave-broker
3. 官方 vsock-proxy
4. nitro-cli run-enclave
5. enclave-broker hello
```
