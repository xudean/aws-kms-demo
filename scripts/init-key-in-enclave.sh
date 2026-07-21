#!/usr/bin/env bash
set -Eeuo pipefail

# Runs the one-time key initialization inside a Nitro Enclave. The script owns
# a temporary enclave-broker process whose settings explicitly select
# init-key mode. The KMS vsock-proxy must already be listening on port 8000.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EIF_PATH="${EIF_PATH:-${ROOT_DIR}/target/enclave/aws-kms-demo.eif}"
BROKER_BIN="${BROKER_BIN:-${ROOT_DIR}/target/release/enclave-broker}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
ENCLAVE_MEMORY_MIB="${ENCLAVE_MEMORY_MIB:-1024}"
ENCLAVE_CPU_COUNT="${ENCLAVE_CPU_COUNT:-2}"
INIT_TIMEOUT_SECONDS="${INIT_TIMEOUT_SECONDS:-300}"
BROKER_PORT="${ENCLAVE_BROKER_PORT:-7001}"
S3_PREFIX="${S3_PREFIX:-kms-keypair}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

[[ "$(uname -s)" == "Linux" ]] || die "Nitro Enclave initialization requires Linux"
[[ -f "${EIF_PATH}" ]] || die "EIF not found: ${EIF_PATH}"
[[ -x "${BROKER_BIN}" ]] || die "enclave-broker not found: ${BROKER_BIN}"
require_command jq
require_command nitro-cli

# Make broker dotenv discovery independent of the directory from which this
# script was invoked. Exported environment variables still take precedence.
cd "${ROOT_DIR}"

broker_pid=""
enclave_id=""
cleanup() {
  if [[ -n "${broker_pid}" ]] && kill -0 "${broker_pid}" 2>/dev/null; then
    kill "${broker_pid}" 2>/dev/null || true
    wait "${broker_pid}" 2>/dev/null || true
  fi
  if [[ -n "${enclave_id}" ]] && nitro-cli describe-enclaves \
      | jq -e --arg id "${enclave_id}" '.[] | select(.EnclaveID == $id)' \
      >/dev/null; then
    nitro-cli terminate-enclave --enclave-id "${enclave_id}" >/dev/null || true
  fi
}
trap cleanup EXIT

printf 'Starting temporary enclave-broker in init-key mode...\n'
DECRYPT_SERVER_TEE_MODE=init-key \
ENCLAVE_BROKER_LISTEN_ENDPOINT="vsock:0:${BROKER_PORT}" \
ENCLAVE_BROKER_ALLOWED_CID="${ENCLAVE_CID}" \
"${BROKER_BIN}" &
broker_pid="$!"

sleep 1
kill -0 "${broker_pid}" 2>/dev/null \
  || die "temporary enclave-broker exited before the enclave started"

printf 'Starting one-time initialization enclave...\n'
run_output="$(nitro-cli run-enclave \
  --eif-path "${EIF_PATH}" \
  --memory "${ENCLAVE_MEMORY_MIB}" \
  --cpu-count "${ENCLAVE_CPU_COUNT}" \
  --enclave-cid "${ENCLAVE_CID}")"
printf '%s\n' "${run_output}"
enclave_id="$(printf '%s\n' "${run_output}" | jq -r '.EnclaveID // empty')"
[[ -n "${enclave_id}" ]] || die "nitro-cli did not return an EnclaveID"

deadline="$((SECONDS + INIT_TIMEOUT_SECONDS))"
while nitro-cli describe-enclaves \
    | jq -e --arg id "${enclave_id}" '.[] | select(.EnclaveID == $id)' \
    >/dev/null; do
  ((SECONDS < deadline)) \
    || die "key initialization did not finish within ${INIT_TIMEOUT_SECONDS} seconds"
  kill -0 "${broker_pid}" 2>/dev/null \
    || die "temporary enclave-broker exited during key initialization"
  sleep 2
done
enclave_id=""

printf 'Initialization enclave exited. Verify that this object exists before starting serve mode:\n'
printf '  s3://%s/%s/key_manifest.json\n' "${S3_BUCKET:-<configured-bucket>}" "${S3_PREFIX%/}"
