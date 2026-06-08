// Thin library surface exposing wire-contract model types to integration
// tests (tests/test_sensor_pipeline.rs imports `linux_sentinel::siem::models`).
// `main.rs` remains the binary entry point with its own private module tree;
// `models` has no crate-internal dependencies, so re-declaring it here is a
// zero-risk duplication that lets `cargo test` resolve the crate as a library.
pub mod siem {
    pub mod models;
}
