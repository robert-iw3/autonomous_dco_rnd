# suricata test workbench

Tests the suricata_eve sensor against the core_ingress contract. Single Rust
binary crate.

- **tier0** (pure Python) — schema + transmission: the Parquet column layout
  mirrored from `eve_schema()` vs `[schema_mappings.suricata_eve]`, `sensor_type =
  "suricata_eve"` absent from the CrossOsCollision map, default gateway URL, and
  the HMAC formula + required headers via a mock-ingress round trip.
- **tier1** (container) — `cargo check && cargo test`: the crate compiles and its
  `#[cfg(test)]` suite exercises the real `eve_schema()`, `events_to_parquet()`
  (Arrow→Parquet round trip), `mitre_field()`, and `Stamper::stamp()`.

Run: `./test/run.sh [--all | --tier 1]`
