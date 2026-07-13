pub mod schema;

use arrow::array::*;
use arrow::datatypes::DataType;
use arrow::record_batch::RecordBatch;
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use serde_json::{Map, Value};
use std::collections::HashMap;
use tracing::{debug, warn};

pub fn read_parquet_batches(payload: &Bytes) -> Result<Vec<RecordBatch>, String> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(payload.clone())
        .map_err(|e| format!("Parquet metadata read failed: {}", e))?;
    let reader = builder.build()
        .map_err(|e| format!("Parquet batch reader build failed: {}", e))?;
    let mut batches = Vec::new();
    for batch_result in reader {
        match batch_result {
            Ok(batch) => batches.push(batch),
            Err(e) => { warn!("Skipping corrupt RecordBatch: {}", e); continue; }
        }
    }
    Ok(batches)
}

/// Convert a single row from an Arrow RecordBatch into a JSON Map.
pub fn row_to_json(batch: &RecordBatch, row: usize) -> Map<String, Value> {
    let schema = batch.schema();
    let mut event = Map::with_capacity(schema.fields().len());

    for (col_idx, field) in schema.fields().iter().enumerate() {
        let col = batch.column(col_idx);
        let name = field.name().clone();

        if col.is_null(row) {
            event.insert(name, Value::Null);
            continue;
        }

        let value = match field.data_type() {
            DataType::Boolean => Value::Bool(col.as_any().downcast_ref::<BooleanArray>().unwrap().value(row)),
            DataType::Int8 => Value::Number(col.as_any().downcast_ref::<Int8Array>().unwrap().value(row).into()),
            DataType::Int16 => Value::Number(col.as_any().downcast_ref::<Int16Array>().unwrap().value(row).into()),
            DataType::Int32 => Value::Number(col.as_any().downcast_ref::<Int32Array>().unwrap().value(row).into()),
            DataType::Int64 => Value::Number(col.as_any().downcast_ref::<Int64Array>().unwrap().value(row).into()),
            DataType::UInt8 => Value::Number(col.as_any().downcast_ref::<UInt8Array>().unwrap().value(row).into()),
            DataType::UInt16 => Value::Number(col.as_any().downcast_ref::<UInt16Array>().unwrap().value(row).into()),
            DataType::UInt32 => Value::Number(col.as_any().downcast_ref::<UInt32Array>().unwrap().value(row).into()),
            DataType::UInt64 => Value::Number(col.as_any().downcast_ref::<UInt64Array>().unwrap().value(row).into()),
            DataType::Float32 => {
                let v = col.as_any().downcast_ref::<Float32Array>().unwrap().value(row);
                match serde_json::Number::from_f64(v as f64) {
                    Some(n) => Value::Number(n),
                    None => { debug!("NaN/Inf in column '{}' row {}, coercing to null", name, row); Value::Null } // #16
                }
            }
            DataType::Float64 => {
                let v = col.as_any().downcast_ref::<Float64Array>().unwrap().value(row);
                match serde_json::Number::from_f64(v) {
                    Some(n) => Value::Number(n),
                    None => { debug!("NaN/Inf in column '{}' row {}, coercing to null", name, row); Value::Null } // #16
                }
            }
            DataType::Utf8 => Value::String(col.as_any().downcast_ref::<StringArray>().unwrap().value(row).to_string()),
            DataType::LargeUtf8 => Value::String(col.as_any().downcast_ref::<LargeStringArray>().unwrap().value(row).to_string()),
            DataType::Timestamp(_, _) => {
                if let Some(a) = col.as_any().downcast_ref::<TimestampMicrosecondArray>() { Value::Number((a.value(row) / 1_000_000).into()) }
                else if let Some(a) = col.as_any().downcast_ref::<TimestampMillisecondArray>() { Value::Number((a.value(row) / 1_000).into()) }
                else if let Some(a) = col.as_any().downcast_ref::<TimestampSecondArray>() { Value::Number(a.value(row).into()) }
                else if let Some(a) = col.as_any().downcast_ref::<TimestampNanosecondArray>() { Value::Number((a.value(row) / 1_000_000_000).into()) }
                else { Value::Null }
            }
            other => {
                // #15: log the type, not the entire column array
                warn!("Unsupported Arrow type {:?} in column '{}', emitting null", other, name);
                Value::Null
            }
        };
        event.insert(name, value);
    }
    event
}

pub fn apply_mapping(event: &Map<String, Value>, mapping: &HashMap<String, String>) -> Map<String, Value> {
    let mut output = Map::with_capacity(mapping.len());
    for (out_field, source) in mapping {
        let value = if source.starts_with('"') && source.ends_with('"') {
            Value::String(source.trim_matches('"').to_string())
        } else {
            event.get(source).cloned().unwrap_or(Value::Null)
        };
        output.insert(out_field.clone(), value);
    }
    output
}

pub fn validate_columns(batch: &RecordBatch, mapping: &HashMap<String, String>) -> Vec<String> {
    let schema = batch.schema();
    let actual: std::collections::HashSet<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
    mapping.values()
        .filter(|v| !v.starts_with('"'))
        .filter(|v| !actual.contains(v.as_str()))
        .cloned()
        .collect()
}
