#!/usr/bin/env bash
set -euo pipefail

rust_target="${1:?Rust target is required}"
case "${rust_target}" in
  x86_64-unknown-linux-gnu|x86_64-unknown-linux-musl)
    target_arch=x86_64
    package_arch=amd64
    ;;
  aarch64-unknown-linux-gnu|aarch64-unknown-linux-musl)
    target_arch=aarch64
    package_arch=arm64
    ;;
  *) echo "Unsupported Linux target: ${rust_target}" >&2; exit 1 ;;
esac

packages=(gcc pkg-config)
host_arch="$(dpkg --print-architecture)"
if [[ "${host_arch}" != "${package_arch}" ]]; then
  if [[ "${host_arch}" != arm64 || "${package_arch}" != amd64 ]]; then
    echo "Unsupported cross compilation: ${host_arch} to ${package_arch}" >&2
    exit 1
  fi

  # shellcheck source=/dev/null
  source /etc/os-release
  sudo dpkg --add-architecture amd64
  grep -q '^Architectures:' /etc/apt/sources.list.d/ubuntu.sources \
    || sudo sed -i '/^Types: deb$/a Architectures: arm64' /etc/apt/sources.list.d/ubuntu.sources
  {
    printf 'deb [arch=amd64] http://archive.ubuntu.com/ubuntu %s main universe\n' \
      "${VERSION_CODENAME}" "${VERSION_CODENAME}-updates"
    printf 'deb [arch=amd64] http://security.ubuntu.com/ubuntu %s main universe\n' \
      "${VERSION_CODENAME}-security"
  } | sudo tee /etc/apt/sources.list.d/ubuntu-amd64.list > /dev/null
  packages+=(gcc-x86-64-linux-gnu)
fi

compiler="${target_arch}-linux-gnu-gcc"
if [[ "${rust_target}" == *-musl ]]; then
  # musl-dev provides the target-prefixed GCC driver, headers, and libc.
  packages+=("musl-dev:${package_arch}")
  compiler="${target_arch}-linux-musl-gcc"
else
  packages+=("libssl-dev:${package_arch}")
fi

sudo apt-get update
sudo apt-get install --yes "${packages[@]}"

build_rustflags="-Z unstable-options -C linker-flavor=gnu-lld-cc -C link-self-contained=+linker"
if [[ "${rust_target}" == *-musl ]]; then
  # Dynamic musl std requests gcc_s; use Rust's musl LLVM unwinder instead
  # of the glibc-built GCC runtime from the Ubuntu cross compiler.
  rust_sysroot="$(rustc --print sysroot)"
  unwind_archive="${rust_sysroot}/lib/rustlib/${rust_target}/lib/self-contained/libunwind.a"
  if [[ ! -f "${unwind_archive}" ]]; then
    echo "Missing Rust musl unwinder: ${unwind_archive}" >&2
    exit 1
  fi
  runtime_lib_dir="${RUNNER_TEMP}/komac-${rust_target}-libs"
  mkdir -p "${runtime_lib_dir}"
  ln -sf "${unwind_archive}" "${runtime_lib_dir}/libgcc_s.a"
  build_rustflags+=" -L native=${runtime_lib_dir}"
fi

target_env_key="${rust_target//-/_}"
{
  echo "CARGO_TARGET_${target_env_key^^}_LINKER=${compiler}"
  echo "CC_${target_env_key}=${compiler}"
  echo "AR_${target_env_key}=${target_arch}-linux-gnu-ar"
  echo "RANLIB_${target_env_key}=${target_arch}-linux-gnu-ranlib"
  if [[ "${target_arch}" == x86_64 ]]; then
    echo "CFLAGS_${target_env_key}=-march=x86-64-v3"
    echo "CXXFLAGS_${target_env_key}=-march=x86-64-v3"
  fi
  # NAPI sets RUSTFLAGS itself; retain the LLD driver selection there too.
  echo "CARGO_BUILD_RUSTFLAGS=${build_rustflags}"
} >> "${GITHUB_ENV}"

if [[ "${rust_target}" == *-gnu ]]; then
  # Keep the architecture-specific OpenSSL configuration with its headers.
  openssl_include_dir="${RUNNER_TEMP}/komac-openssl-include"
  mkdir -p "${openssl_include_dir}"
  cp --recursive /usr/include/openssl "${openssl_include_dir}/"
  cp "/usr/include/${target_arch}-linux-gnu/openssl/"* "${openssl_include_dir}/openssl/"
  {
    echo "${target_env_key^^}_OPENSSL_INCLUDE_DIR=${openssl_include_dir}"
    echo "${target_env_key^^}_OPENSSL_LIB_DIR=/usr/lib/${target_arch}-linux-gnu"
  } >> "${GITHUB_ENV}"
fi
