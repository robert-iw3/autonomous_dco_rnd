use arrow::array::{
    Float64Builder, StringBuilder, Int64Builder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::{WriterProperties, WriterVersion};
use std::sync::Arc;
use crate::C2TelemetryRow;

pub fn serialize_to_parquet(rows: &[C2TelemetryRow]) -> Result<Vec<u8>, String> {
    // 1. Define strict Arrow Schema -- c2_math 8D vector fully populated.
    // "Image" is the identifier_column for windows_c2 duck-typing in worker_qdrant.
    let schema = Arc::new(Schema::new(vec![
        Field::new("id",               DataType::Int64,   false),
        Field::new("event_id",         DataType::Utf8,    true),
        Field::new("timestamp",        DataType::Int64,   true),  // epoch_ms
        Field::new("host",             DataType::Utf8,    true),
        Field::new("user",             DataType::Utf8,    true),
        Field::new("host_ip",          DataType::Utf8,    true),
        Field::new("Image",            DataType::Utf8,    true),  // identifier_column (process path)
        Field::new("process",          DataType::Utf8,    true),
        Field::new("destination",      DataType::Utf8,    true),
        Field::new("domain",           DataType::Utf8,    true),
        Field::new("alert_reason",     DataType::Utf8,    true),
        Field::new("confidence",       DataType::Int64,   true),
        Field::new("event_type",       DataType::Utf8,    true),
        Field::new("severity",         DataType::Utf8,    true),
        Field::new("payload_raw",      DataType::Utf8,    true),
        // -- c2_math 8D vector columns (mirrors linux_c2 space) ----------------
        Field::new("outbound_ratio",   DataType::Float64, true),  // [0]
        Field::new("packet_size_mean", DataType::Float64, true),  // [1]
        Field::new("packet_size_std",  DataType::Float64, true),  // [2]
        Field::new("interval",         DataType::Float64, true),  // [3]
        Field::new("cv",               DataType::Float64, true),  // [4]
        Field::new("entropy",          DataType::Float64, true),  // [5]
        Field::new("cmd_entropy",      DataType::Float64, true),  // [6]
        Field::new("score",            DataType::Float64, true),  // [7]
    ]));

    let cap = rows.len();
    let mut id_b          = Int64Builder::with_capacity(cap);
    let mut ev_id_b       = StringBuilder::with_capacity(cap, cap * 36);
    let mut ts_b          = Int64Builder::with_capacity(cap);
    let mut host_b        = StringBuilder::with_capacity(cap, cap * 16);
    let mut user_b        = StringBuilder::with_capacity(cap, cap * 32);
    let mut host_ip_b     = StringBuilder::with_capacity(cap, cap * 16);
    let mut image_b       = StringBuilder::with_capacity(cap, cap * 64);
    let mut process_b     = StringBuilder::with_capacity(cap, cap * 64);
    let mut dest_b        = StringBuilder::with_capacity(cap, cap * 32);
    let mut dom_b         = StringBuilder::with_capacity(cap, cap * 64);
    let mut reason_b      = StringBuilder::with_capacity(cap, cap * 128);
    let mut conf_b        = Int64Builder::with_capacity(cap);
    let mut evt_type_b    = StringBuilder::with_capacity(cap, cap * 32);
    let mut sev_b         = StringBuilder::with_capacity(cap, cap * 16);
    let mut payload_b     = StringBuilder::with_capacity(cap, cap * 512);
    let mut out_ratio_b   = Float64Builder::with_capacity(cap);
    let mut pkt_mean_b    = Float64Builder::with_capacity(cap);
    let mut pkt_std_b     = Float64Builder::with_capacity(cap);
    let mut interval_b    = Float64Builder::with_capacity(cap);
    let mut cv_b          = Float64Builder::with_capacity(cap);
    let mut entropy_b     = Float64Builder::with_capacity(cap);
    let mut cmd_ent_b     = Float64Builder::with_capacity(cap);
    let mut score_b       = Float64Builder::with_capacity(cap);

    for r in rows {
        id_b.append_value(r.id);
        ev_id_b.append_value(&r.event_id);
        ts_b.append_value(r.timestamp);
        host_b.append_value(&r.host);
        user_b.append_value(&r.user);
        host_ip_b.append_value(&r.host_ip);
        image_b.append_value(&r.process);   // Image = process path (identifier_column)
        process_b.append_value(&r.process);
        dest_b.append_value(&r.destination);
        dom_b.append_value(&r.domain);
        reason_b.append_value(&r.alert_reason);
        conf_b.append_value(r.confidence);
        evt_type_b.append_value(&r.event_type);
        sev_b.append_value(&r.severity);
        payload_b.append_value(&r.payload_raw);
        out_ratio_b.append_value(r.outbound_ratio);
        pkt_mean_b.append_value(r.packet_size_mean);
        pkt_std_b.append_value(r.packet_size_std);
        interval_b.append_value(r.interval);
        cv_b.append_value(r.cv);
        entropy_b.append_value(r.entropy);
        cmd_ent_b.append_value(r.cmd_entropy);
        score_b.append_value(r.score);
    }

    let batch = match RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(id_b.finish()),
            Arc::new(ev_id_b.finish()),
            Arc::new(ts_b.finish()),
            Arc::new(host_b.finish()),
            Arc::new(user_b.finish()),
            Arc::new(host_ip_b.finish()),
            Arc::new(image_b.finish()),
            Arc::new(process_b.finish()),
            Arc::new(dest_b.finish()),
            Arc::new(dom_b.finish()),
            Arc::new(reason_b.finish()),
            Arc::new(conf_b.finish()),
            Arc::new(evt_type_b.finish()),
            Arc::new(sev_b.finish()),
            Arc::new(payload_b.finish()),
            Arc::new(out_ratio_b.finish()),
            Arc::new(pkt_mean_b.finish()),
            Arc::new(pkt_std_b.finish()),
            Arc::new(interval_b.finish()),
            Arc::new(cv_b.finish()),
            Arc::new(entropy_b.finish()),
            Arc::new(cmd_ent_b.finish()),
            Arc::new(score_b.finish()),
        ],
    ) {
        Ok(b) => b,
        Err(e) => return Err(format!("Arrow RecordBatch Error: {}", e)),
    };

    let mut buffer = Vec::new();
    let props = WriterProperties::builder()
        .set_writer_version(WriterVersion::PARQUET_2_0)
        .set_compression(Compression::ZSTD(Default::default()))
        .build();

    let mut writer = match ArrowWriter::try_new(&mut buffer, schema, Some(props)) {
        Ok(w) => w,
        Err(e) => return Err(format!("Parquet Writer Init Error: {}", e)),
    };

    if let Err(e) = writer.write(&batch) {
        return Err(format!("Parquet Row Write Error: {}", e));
    }
    if let Err(e) = writer.close() {
        return Err(format!("Parquet Stream Close Error: {}", e));
    }

    Ok(buffer)
}
