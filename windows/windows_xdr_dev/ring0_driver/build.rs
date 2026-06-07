fn main() -> Result<(), wdk_build::ConfigError> {
    // Required for WDM driver model
    std::env::set_var("CARGO_CFG_TARGET_FEATURE", "crt-static");
    // /DRIVER:WDM sets the correct PE subsystem + stack / heap defaults
    println!("cargo:rustc-link-arg=/DRIVER");
    // /INTEGRITYCHECK is mandatory for ObRegisterCallbacks (object callbacks)
    println!("cargo:rustc-link-arg=/INTEGRITYCHECK");
    wdk_build::configure_wdk_binary_build()?;
    Ok(())
}
