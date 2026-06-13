# SEC-ENDPOINT-ID — Endpoint identity injection defense

*Implementation: `libs/lib_siem_core/src/models.rs`*

Endpoint identifiers are validated against a strict regex at the type boundary, defeating identity-injection via malformed endpoint_id.

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
