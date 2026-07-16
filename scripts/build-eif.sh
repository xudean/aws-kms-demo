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
NITRO_SDK_INCLUDE="${NITRO_SDK_INCLUDE:-${NITRO_SDK_PREFIX}/include}"
if [[ -n "${NITRO_SDK_LIB_DIR:-}" ]]; then
  NITRO_SDK_LIB_DIR="${NITRO_SDK_LIB_DIR}"
elif compgen -G "${NITRO_SDK_PREFIX}/lib/libaws-nitro-enclaves-sdk-c.*" >/dev/null; then
  NITRO_SDK_LIB_DIR="${NITRO_SDK_PREFIX}/lib"
else
  NITRO_SDK_LIB_DIR="${NITRO_SDK_PREFIX}/lib64"
fi
NITRO_SDK_LIBS="${NITRO_SDK_LIBS:-aws-nitro-enclaves-sdk-c,aws-c-auth,aws-c-http,aws-c-io,aws-c-compression,aws-c-cal,aws-c-sdkutils,aws-c-common,s2n,nsm,json-c,crypto}"
ENCLAVE_ENV_FILE="${ENCLAVE_ENV_FILE:-${ROOT_DIR}/.env.enclave}"

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
[[ -f "${ENCLAVE_ENV_FILE}" ]] \
  || die "enclave environment file not found: ${ENCLAVE_ENV_FILE}"
if grep -Eq \
  '^[[:space:]]*(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)[[:space:]]*=' \
  "${ENCLAVE_ENV_FILE}"; then
  die "do not embed AWS credentials in ${ENCLAVE_ENV_FILE}; credentials must come from parent-instance"
fi

required_nitro_headers=(
  aws/auth/credentials.h
  aws/common/byte_buf.h
  aws/io/socket.h
  aws/nitro_enclaves/kms.h
  aws/nitro_enclaves/nitro_enclaves.h
)
missing_nitro_headers=()
for header in "${required_nitro_headers[@]}"; do
  if [[ ! -f "${NITRO_SDK_INCLUDE}/${header}" && ! -f "/usr/include/${header}" ]]; then
    missing_nitro_headers+=("${header}")
  fi
done
if ((${#missing_nitro_headers[@]} > 0)); then
  printf 'error: Nitro C SDK development headers are incomplete. Missing:\n' >&2
  printf '  %s\n' "${missing_nitro_headers[@]}" >&2
  printf 'searched: %s and /usr/include\n' "${NITRO_SDK_INCLUDE}" >&2
  die "install aws-nitro-enclaves-sdk-c and all AWS CRT development dependencies, or set NITRO_SDK_INCLUDE"
fi

if ! compgen -G "${NITRO_SDK_LIB_DIR}/libaws-nitro-enclaves-sdk-c.*" >/dev/null; then
  die "Nitro C SDK library not found in ${NITRO_SDK_LIB_DIR}; set NITRO_SDK_LIB_DIR"
fi

missing_nitro_libraries=()
IFS=',' read -r -a required_nitro_libraries <<<"${NITRO_SDK_LIBS}"
for library in "${required_nitro_libraries[@]}"; do
  library="${library//[[:space:]]/}"
  [[ -n "${library}" ]] || continue
  if ! compgen -G "${NITRO_SDK_LIB_DIR}/lib${library}.*" >/dev/null; then
    missing_nitro_libraries+=("${library}")
  fi
done
if ((${#missing_nitro_libraries[@]} > 0)); then
  printf 'error: Nitro C SDK link dependencies are incomplete. Missing:\n' >&2
  printf '  lib%s\n' "${missing_nitro_libraries[@]}" >&2
  die "re-run scripts/install-nitro-sdk.sh or set NITRO_SDK_LIBS/NITRO_SDK_LIB_DIR"
fi

mkdir -p \
  "$(dirname "${EIF_PATH}")" \
  "$(dirname "${BUILD_METADATA_PATH}")" \
  "$(dirname "${DESCRIBE_PATH}")"

printf 'Building decrypt-server-tee with Nitro support...\n'
(
  cd "${ROOT_DIR}"
  NITRO_SDK_PREFIX="${NITRO_SDK_PREFIX}" \
    NITRO_SDK_INCLUDE="${NITRO_SDK_INCLUDE}" \
    NITRO_SDK_LIB_DIR="${NITRO_SDK_LIB_DIR}" \
    NITRO_SDK_LIBS="${NITRO_SDK_LIBS}" \
    cargo build --release --locked \
      --bin decrypt-server-tee \
      --features nitro-enclave
)

BINARY_PATH="${TARGET_DIR}/release/decrypt-server-tee"
[[ -x "${BINARY_PATH}" ]] || die "built binary not found: ${BINARY_PATH}"

LDD_OUTPUT="$(LD_LIBRARY_PATH="${NITRO_SDK_LIB_DIR}:${LD_LIBRARY_PATH:-}" ldd "${BINARY_PATH}" 2>&1)" || {
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

mkdir -p \
  "${BUILD_CONTEXT}/rootfs/app" \
  "${BUILD_CONTEXT}/rootfs/opt/enclave/lib"
cp "${BINARY_PATH}" "${BUILD_CONTEXT}/rootfs/app/decrypt-server-tee"
cp "${ENCLAVE_ENV_FILE}" "${BUILD_CONTEXT}/rootfs/app/.env"

# ldd returns the complete resolved dependency closure, including the ELF
# interpreter. Put libraries in a fixed directory selected by LD_LIBRARY_PATH;
# the ELF interpreter itself must also remain at its original absolute path.
while IFS= read -r library; do
  [[ -n "${library}" && -f "${library}" ]] || continue
  library_name="$(basename "${library}")"
  cp -L "${library}" "${BUILD_CONTEXT}/rootfs/opt/enclave/lib/${library_name}"
  case "${library_name}" in
    ld-linux* | ld-musl*)
      mkdir -p "${BUILD_CONTEXT}/rootfs$(dirname "${library}")"
      cp -L "${library}" "${BUILD_CONTEXT}/rootfs${library}"
      ;;
  esac
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
