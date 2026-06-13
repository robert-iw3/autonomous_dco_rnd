# SEC-ENDPOINT-ID — Endpoint identity injection defense

*Implementation: `libs/lib_siem_core/src/models.rs`*

**Execution chain:** Logic

**1. Logic** — Endpoint identifiers are regex-validated at the Rust type boundary before reaching Qdrant/Parquet, defeating identity-injection / path-traversal via a malformed endpoint_id.

`libs/lib_siem_core/src/models.rs:L14-L20`

```rust
pub struct DynamicUebaVector {
    #[validate(regex(path = "*RE_ENDPOINT", message = "Invalid endpoint_id format"))]
    pub endpoint_id: String,
    pub timestamp: String,
    #[validate(regex(path = "*RE_SOURCE_TYPE", message = "Invalid source_type format"))]
    pub source_type: String,
    pub vector_name: String,
```
