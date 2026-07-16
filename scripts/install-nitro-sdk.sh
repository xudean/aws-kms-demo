#!/usr/bin/env bash
set -Eeuo pipefail

# Build the official AWS Nitro Enclaves SDK for C builder image and extract the
# SDK plus its AWS CRT dependencies into a user-writable installation prefix.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_REPOSITORY="${NITRO_SDK_REPOSITORY:-https://github.com/aws/aws-nitro-enclaves-sdk-c.git}"
SDK_REF="${NITRO_SDK_REF:-}"
SDK_SOURCE_DIR="${NITRO_SDK_SOURCE_DIR:-${ROOT_DIR}/target/nitro-sdk-src}"
SDK_PREFIX="${NITRO_SDK_PREFIX:-${HOME}/.local/nitro-sdk}"
SDK_BUILDER_IMAGE="${NITRO_SDK_BUILDER_IMAGE:-aws-nitro-enclaves-sdk-c-builder:latest}"

SDK_CONTAINER=""
STAGING_DIR=""

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

cleanup() {
  if [[ -n "${SDK_CONTAINER}" ]]; then
    docker rm -f "${SDK_CONTAINER}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${STAGING_DIR}" && -d "${STAGING_DIR}" ]]; then
    rm -rf "${STAGING_DIR}"
  fi
}
trap cleanup EXIT

[[ "$(uname -s)" == "Linux" ]] || die "Nitro SDK installation requires a Linux host"

require_command docker
require_command git
require_command mktemp

docker info >/dev/null 2>&1 || die "Docker daemon is not available"

if [[ -e "${SDK_PREFIX}" ]]; then
  die "installation prefix already exists: ${SDK_PREFIX}; remove it explicitly or choose another NITRO_SDK_PREFIX"
fi

if [[ -d "${SDK_SOURCE_DIR}/.git" ]]; then
  printf 'Using existing Nitro SDK source: %s\n' "${SDK_SOURCE_DIR}"
  if [[ -n "${SDK_REF}" ]]; then
    printf 'Updating cached source to ref %s...\n' "${SDK_REF}"
    git -C "${SDK_SOURCE_DIR}" fetch --depth 1 origin "${SDK_REF}"
    git -C "${SDK_SOURCE_DIR}" checkout --detach FETCH_HEAD
  fi
elif [[ -e "${SDK_SOURCE_DIR}" ]]; then
  die "SDK source path exists but is not a Git repository: ${SDK_SOURCE_DIR}"
else
  mkdir -p "$(dirname "${SDK_SOURCE_DIR}")"
  printf 'Cloning AWS Nitro Enclaves SDK for C...\n'
  clone_args=(--depth 1)
  if [[ -n "${SDK_REF}" ]]; then
    clone_args+=(--branch "${SDK_REF}")
  fi
  git clone "${clone_args[@]}" "${SDK_REPOSITORY}" "${SDK_SOURCE_DIR}"
fi

[[ -f "${SDK_SOURCE_DIR}/containers/Dockerfile.al2" ]] \
  || die "official SDK Dockerfile not found in ${SDK_SOURCE_DIR}"
SDK_COMMIT="$(git -C "${SDK_SOURCE_DIR}" rev-parse HEAD)"

printf 'Building official SDK builder image %s...\n' "${SDK_BUILDER_IMAGE}"
docker build \
  --file "${SDK_SOURCE_DIR}/containers/Dockerfile.al2" \
  --target builder \
  --tag "${SDK_BUILDER_IMAGE}" \
  "${SDK_SOURCE_DIR}"

SDK_CONTAINER="$(docker create "${SDK_BUILDER_IMAGE}")"
mkdir -p "$(dirname "${SDK_PREFIX}")"
STAGING_DIR="$(mktemp -d "$(dirname "${SDK_PREFIX}")/.nitro-sdk.XXXXXX")"

mkdir -p \
  "${STAGING_DIR}/include/aws" \
  "${STAGING_DIR}/include/json-c" \
  "${STAGING_DIR}/lib"

printf 'Extracting SDK headers and libraries...\n'
docker cp "${SDK_CONTAINER}:/usr/include/aws/." "${STAGING_DIR}/include/aws"
docker cp "${SDK_CONTAINER}:/usr/include/json-c/." "${STAGING_DIR}/include/json-c"
docker cp "${SDK_CONTAINER}:/usr/include/nsm.h" "${STAGING_DIR}/include/nsm.h"

# Do not copy all of /usr/lib64: the official AL2 builder contains unrelated
# dangling links (for example cracklib_dict.*), which make docker cp abort.
# Resolve and copy only the Nitro SDK/AWS CRT libraries required by this app.
mapfile -t sdk_libraries < <(
  docker run --rm --entrypoint /bin/sh "${SDK_BUILDER_IMAGE}" -c '
    find /usr/lib64 -maxdepth 1 \
      \( -name "libaws*" \
      -o -name "libs2n*" \
      -o -name "libnsm*" \
      -o -name "libjson-c*" \
      -o -name "libcrypto*" \
      -o -name "libssl*" \) \
      -printf "%f\n" | sort -u
  '
)
if ((${#sdk_libraries[@]} == 0)); then
  die "official builder image did not contain any Nitro SDK/AWS CRT libraries"
fi
for library in "${sdk_libraries[@]}"; do
  docker cp -L \
    "${SDK_CONTAINER}:/usr/lib64/${library}" \
    "${STAGING_DIR}/lib/${library}"
done

required_headers=(
  aws/auth/credentials.h
  aws/common/byte_buf.h
  aws/io/socket.h
  aws/nitro_enclaves/kms.h
  aws/nitro_enclaves/nitro_enclaves.h
)
for header in "${required_headers[@]}"; do
  [[ -f "${STAGING_DIR}/include/${header}" ]] \
    || die "official builder image did not contain required header: ${header}"
done

if ! compgen -G "${STAGING_DIR}/lib/libaws-nitro-enclaves-sdk-c.*" >/dev/null; then
  die "official builder image did not contain libaws-nitro-enclaves-sdk-c"
fi

mv "${STAGING_DIR}" "${SDK_PREFIX}"
STAGING_DIR=""
docker rm "${SDK_CONTAINER}" >/dev/null
SDK_CONTAINER=""

printf '\nNitro C SDK installed successfully.\n'
printf 'Install prefix: %s\n' "${SDK_PREFIX}"
printf 'Builder image: %s\n' "${SDK_BUILDER_IMAGE}"
printf 'SDK commit: %s\n' "${SDK_COMMIT}"
printf '\nBuild the EIF with:\n'
printf 'NITRO_SDK_PREFIX=%q ./scripts/build-eif.sh\n' "${SDK_PREFIX}"
