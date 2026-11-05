use cynic_codegen::registration::SchemaRegistration;

const ICON: &str = "assets/branding/logo.ico";

fn main() {
    // cynic emits rerun-if-changed for the schema, which stops Cargo from rerunning this script
    // when any other file changes, so the icon has to be listed explicitly
    println!("cargo:rerun-if-changed={ICON}");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let static_crt = std::env::var("CARGO_CFG_TARGET_FEATURE")
        .unwrap_or_default()
        .split(',')
        .any(|feature| feature == "crt-static");

    // Pack relocation metadata. GNU builds require glibc 2.36+;
    // static musl builds use the toolchain's RELR-capable CRT.
    // Leave dynamic musl addons compatible with older system loaders.
    if target_os == "linux" && (target_env == "gnu" || (target_env == "musl" && static_crt)) {
        // Enable the ELF linker's string merging and branch-chain optimizations.
        println!("cargo:rustc-link-arg=-Wl,-O2");
        println!("cargo:rustc-link-arg=-Wl,-z,pack-relative-relocs");
    }

    if target_os == "linux" {
        // Keep folding scoped to the CLI to preserve addon performance.
        println!("cargo:rustc-link-arg-bin=komac=-Wl,--icf=safe");

        if target_env == "musl" && static_crt {
            // musl-gcc injects an interpreter even for non-PIE static links.
            // The standalone CLI must also run on hosts without musl installed.
            println!("cargo:rustc-link-arg-bin=komac=-Wl,--no-dynamic-linker");
        }
    }

    cynic_codegen::register_schema("github")
        .from_sdl_file("assets/github.graphql")
        .and_then(SchemaRegistration::as_default)
        .expect("failed to register the GitHub GraphQL schema");
    windows_exe_info::icon::icon_ico(ICON);
    windows_exe_info::versioninfo::link_cargo_env();
    // Anthelion Start
    napi_build::setup();
    // Anthelion End
}
