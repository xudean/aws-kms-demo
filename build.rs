use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=native/nitro_kms_shim.c");
    println!("cargo:rerun-if-changed=native/nitro_kms_shim.h");
    println!("cargo:rerun-if-env-changed=NITRO_SDK_PREFIX");
    println!("cargo:rerun-if-env-changed=NITRO_SDK_INCLUDE");
    println!("cargo:rerun-if-env-changed=NITRO_SDK_LIB_DIR");
    println!("cargo:rerun-if-env-changed=NITRO_SDK_LIBS");

    if env::var_os("CARGO_FEATURE_NITRO_ENCLAVE").is_none() {
        return;
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        panic!("the nitro-enclave feature is supported only for Linux targets");
    }

    let prefix =
        PathBuf::from(env::var("NITRO_SDK_PREFIX").unwrap_or_else(|_| "/usr/local".into()));
    let include = env::var_os("NITRO_SDK_INCLUDE")
        .map(PathBuf::from)
        .unwrap_or_else(|| prefix.join("include"));
    let lib_dir = env::var_os("NITRO_SDK_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| prefix.join("lib"));

    cc::Build::new()
        .file("native/nitro_kms_shim.c")
        .include(include)
        .warnings(true)
        .compile("nitro_kms_shim");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    let libraries = env::var("NITRO_SDK_LIBS").unwrap_or_else(|_| {
        "aws-nitro-enclaves-sdk-c,aws-c-auth,aws-c-http,aws-c-io,aws-c-compression,aws-c-cal,aws-c-sdkutils,aws-c-common,s2n,nsm,json-c,crypto"
            .into()
    });
    for library in libraries
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        println!("cargo:rustc-link-lib={library}");
    }
}
