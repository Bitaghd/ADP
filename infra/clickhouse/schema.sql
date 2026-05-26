CREATE TABLE IF NOT EXISTS zeek_conn_events
(
    ts DateTime64(3),
    uid String,
    src_ip String,
    src_port UInt16,
    dst_ip String,
    dst_port UInt16,
    proto LowCardinality(String),
    service LowCardinality(String),
    duration Float64,
    orig_bytes Float64,
    resp_bytes Float64,
    orig_pkts Float64,
    resp_pkts Float64,
    orig_ip_bytes Float64,
    resp_ip_bytes Float64,
    conn_state LowCardinality(String),
    history String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, src_ip, dst_ip, dst_port, proto);

CREATE TABLE IF NOT EXISTS anomaly_detections
(
    ts DateTime64(3),
    src_ip String,
    dst_ip String,
    dst_port UInt16,
    proto LowCardinality(String),
    reconstruction_error Float64,
    threshold Float64,
    is_anomaly UInt8,
    threshold_method LowCardinality(String),
    model_version LowCardinality(String),
    context_key String,
    parent_context_key String,
    p_value Nullable(Float64),
    calibration_decision LowCardinality(String),
    calibration_mode LowCardinality(String),
    effective_sample_size Nullable(Float64),
    p_min Nullable(Float64),
    bank_size Nullable(UInt32),
    trusted_bank_size Nullable(UInt32),
    adaptive_bank_size Nullable(UInt32),
    bank_frozen UInt8,
    freeze_reason String,
    window_size UInt16,
    stride UInt16
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, is_anomaly, src_ip, dst_ip, dst_port);

ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS context_key String DEFAULT '';
ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS parent_context_key String DEFAULT '';
ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS p_value Nullable(Float64);
ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS calibration_decision LowCardinality(String) DEFAULT '';
ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS calibration_mode LowCardinality(String) DEFAULT '';
ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS effective_sample_size Nullable(Float64);
ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS p_min Nullable(Float64);
ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS bank_size Nullable(UInt32);
ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS trusted_bank_size Nullable(UInt32);
ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS adaptive_bank_size Nullable(UInt32);
ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS bank_frozen UInt8 DEFAULT 0;
ALTER TABLE anomaly_detections ADD COLUMN IF NOT EXISTS freeze_reason String DEFAULT '';

CREATE TABLE IF NOT EXISTS anomaly_alerts
(
    ts DateTime64(3),
    severity LowCardinality(String),
    src_ip String,
    dst_ip String,
    dst_port UInt16,
    proto LowCardinality(String),
    reconstruction_error Float64,
    threshold Float64,
    message String,
    acknowledged UInt8
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, severity, src_ip);
