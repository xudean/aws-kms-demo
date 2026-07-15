#!/usr/bin/env bash
set -Eeuo pipefail

# Build the Rust enclave application, package its runtime dependencies into a
# minimal Docker image, and convert that image to an AWS Nitro Enclave EIF.
#
# This script must run on Linux. The aws-nitro-enclaves-sdk-c libraries must
# already be installed and Docker plus nitro-cli must be available.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT_DIR}/target}"
if [[ "${TARGET_DIR}" != /* ]]; then
  TARGET_DIR="${ROOT_DIR}/${TARGET_DIR}"
fi
IMAGE_TAG="${IMAGE_TAG:-aws-kms-demo-enclave:latest}"
EIF_PATH="${EIF_PATH:-${TARGET_DIR}/enclave/aws-kms-demo.eif}"
BUILD_METADATA_PATH="${BUILD_METADATA_PATH:-${EIF_PATH}.build.json}"
DESCRIBE_PATH="${DESCRIBE_PATH:-${EIF_PATH}.describe.json}"
NITRO_SDK_PREFIX="${NITRO_SDK_PREFIX:-/usr/local}"

PARENT_CID="${NITRO_PARENT_CID:-3}"
PARENT_CONFIG_PORT="${PARENT_CONFIG_PORT:-7001}"
S3_PROXY_PORT="${S3_PROXY_PORT:-7002}"
KMS_PROXY_PORT="${NITRO_KMS_PROXY_PORT:-8000}"
ENCLAVE_RPC_PORT="${ENCLAVE_RPC_PORT:-7003}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

[[ "$(uname -s)" == "Linux" ]] || die "EIF builds require a Linux host"

require_command cargo
require_command docker
require_command ldd
require_command nitro-cli

docker info >/dev/null 2>&1 || die "Docker daemon is not available"

mkdir -p \
  "$(dirname "${EIF_PATH}")" \
  "$(dirname "${BUILD_METADATA_PATH}")" \
  "$(dirname "${DESCRIBE_PATH}")"

printf 'Building decrypt-server-tee with Nitro support...\n'
(
  cd "${ROOT_DIR}"
  NITRO_SDK_PREFIX="${NITRO_SDK_PREFIX}" \
    cargo build --release --locked \
      --bin decrypt-server-tee \
      --features nitro-enclave
)

BINARY_PATH="${TARGET_DIR}/release/decrypt-server-tee"
[[ -x "${BINARY_PATH}" ]] || die "built binary not found: ${BINARY_PATH}"

LDD_OUTPUT="$(ldd "${BINARY_PATH}" 2>&1)" || {
  printf '%s\n' "${LDD_OUTPUT}" >&2
  die "failed to inspect the enclave binary's shared libraries"
}
if printf '%s\n' "${LDD_OUTPUT}" | grep -q 'not found'; then
  printf '%s\n' "${LDD_OUTPUT}" >&2
  die "one or more shared libraries are unresolved"
fi

BUILD_CONTEXT="$(mktemp -d "${TMPDIR:-/tmp}/aws-kms-demo-eif.XXXXXX")"
TEMP_EIF="${EIF_PATH%.eif}.tmp.$$.eif"
cleanup() {
  rm -rf "${BUILD_CONTEXT}"
  rm -f "${TEMP_EIF}"
}
trap cleanup EXIT

mkdir -p "${BUILD_CONTEXT}/rootfs/app"
cp "${BINARY_PATH}" "${BUILD_CONTEXT}/rootfs/app/decrypt-server-tee"

# ldd returns the complete resolved dependency closure, including the ELF
# interpreter. Preserve absolute paths so the scratch image behaves like the
# build host at runtime.
while IFS= read -r library; do
  [[ -n "${library}" && -f "${library}" ]] || continue
  mkdir -p "${BUILD_CONTEXT}/rootfs$(dirname "${library}")"
  cp -L "${library}" "${BUILD_CONTEXT}/rootfs${library}"
done < <(
  printf '%s\n' "${LDD_OUTPUT}" \
    | awk '/=> \// { print $3 } /^[[:space:]]*\// { print $1 }' \
    | sort -u
)

CA_BUNDLE="${CA_BUNDLE:-}"
if [[ -z "${CA_BUNDLE}" ]]; then
  for candidate in \
    /etc/ssl/certs/ca-certificates.crt \
    /etc/pki/tls/certs/ca-bundle.crt \
    /etc/ssl/ca-bundle.pem; do
    if [[ -f "${candidate}" ]]; then
      CA_BUNDLE="${candidate}"
      break
    fi
  done
fi
[[ -n "${CA_BUNDLE}" && -f "${CA_BUNDLE}" ]] \
  || die "CA certificate bundle not found; set CA_BUNDLE=/path/to/ca-bundle"

mkdir -p \
  "${BUILD_CONTEXT}/rootfs/etc/ssl/certs" \
  "${BUILD_CONTEXT}/rootfs/etc/pki/tls/certs"
cp -L "${CA_BUNDLE}" "${BUILD_CONTEXT}/rootfs/etc/ssl/certs/ca-certificates.crt"
cp -L "${CA_BUNDLE}" "${BUILD_CONTEXT}/rootfs/etc/pki/tls/certs/ca-bundle.crt"

printf 'Building enclave container image %s...\n' "${IMAGE_TAG}"
docker build \
  --file "${ROOT_DIR}/enclave/Dockerfile" \
  --tag "${IMAGE_TAG}" \
  --build-arg "PARENT_CID=${PARENT_CID}" \
  --build-arg "PARENT_CONFIG_PORT=${PARENT_CONFIG_PORT}" \
  --build-arg "S3_PROXY_PORT=${S3_PROXY_PORT}" \
  --build-arg "KMS_PROXY_PORT=${KMS_PROXY_PORT}" \
  --build-arg "ENCLAVE_RPC_PORT=${ENCLAVE_RPC_PORT}" \
  "${BUILD_CONTEXT}"

printf 'Converting %s to EIF...\n' "${IMAGE_TAG}"
BUILD_OUTPUT="$(nitro-cli build-enclave \
  --docker-uri "${IMAGE_TAG}" \
  --output-file "${TEMP_EIF}")"

mv -f "${TEMP_EIF}" "${EIF_PATH}"
printf '%s\n' "${BUILD_OUTPUT}" >"${BUILD_METADATA_PATH}"
nitro-cli describe-eif \
  --eif-path "${EIF_PATH}" \
  >"${DESCRIBE_PATH}"

printf '\nEIF created: %s\n' "${EIF_PATH}"
printf 'Build measurements: %s\n' "${BUILD_METADATA_PATH}"
printf 'EIF description: %s\n' "${DESCRIBE_PATH}"
printf '\nPCR values from this build:\n%s\n' "${BUILD_OUTPUT}"
