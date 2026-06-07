/*============================================================================
 * SENTINEL NEXUS -- Middleware SQL Server Telemetry Store
 * Script 2/4: Tables, Indexes, Compression
 *
 * Three fact tables partitioned by event_timestamp:
 *   - Endpoint telemetry  (Linux C2, Windows DeepSensor, Windows C2)
 *   - Cloud telemetry     (VPC Flow, NSG, CloudTrail, Activity, Entra, GuardDuty)
 *   - Network telemetry   (Arkime session data)
 * Plus a staging table for raw JSON landing.
 *============================================================================*/

USE Sensor_Telemetry;
GO

/*══════════════════════════════════════════════════════════════════════════════
 * STAGING TABLE -- raw JSON batches land here, parsed by sproc
 *══════════════════════════════════════════════════════════════════════════════*/

CREATE TABLE dbo.IngestStaging (
    staging_id      BIGINT IDENTITY(1,1)    NOT NULL,
    received_utc    DATETIME2(3)            NOT NULL DEFAULT SYSUTCDATETIME(),
    sensor_type     VARCHAR(64)             NOT NULL,
    batch_json      NVARCHAR(MAX)           NOT NULL,
    row_count       INT                     NULL,
    processed       BIT                     NOT NULL DEFAULT 0,
    error_message   NVARCHAR(1000)          NULL,
    CONSTRAINT PK_IngestStaging PRIMARY KEY CLUSTERED (staging_id)
) WITH (DATA_COMPRESSION = ROW);
GO

CREATE NONCLUSTERED INDEX IX_IngestStaging_Unprocessed
    ON dbo.IngestStaging (processed, received_utc)
    WHERE processed = 0;
GO


/*══════════════════════════════════════════════════════════════════════════════
 * ENDPOINT TELEMETRY -- Linux C2, Windows DeepSensor, Windows C2
 * Unified schema covering all endpoint sensor types.
 *══════════════════════════════════════════════════════════════════════════════*/

CREATE TABLE dbo.EndpointTelemetry (
    event_id            BIGINT IDENTITY(1,1)    NOT NULL,
    event_timestamp     DATETIME2(3)            NOT NULL,
    sensor_type         VARCHAR(32)             NOT NULL,
    sensor_id           VARCHAR(128)            NULL,
    hostname            VARCHAR(128)            NULL,

    -- Process context
    process_name        NVARCHAR(256)           NULL,
    pid                 INT                     NULL,
    parent_pid          INT                     NULL,
    uid                 INT                     NULL,
    tid                 INT                     NULL,
    process_hash        VARCHAR(128)            NULL,
    command_line        NVARCHAR(2000)          NULL,
    parent_image        NVARCHAR(512)           NULL,
    process_tree        NVARCHAR(2000)          NULL,
    cmd_snippet         NVARCHAR(2000)          NULL,

    -- User context
    event_user          NVARCHAR(128)           NULL,

    -- Network context
    event_type          VARCHAR(64)             NULL,
    dst_ip              VARCHAR(45)             NULL,
    dst_port            INT                     NULL,
    src_ip              VARCHAR(45)             NULL,

    -- DNS
    dns_query           NVARCHAR(512)           NULL,
    dns_flags           INT                     NULL,

    -- Packet statistics
    packet_count        BIGINT                  NULL,
    packet_size_mean    FLOAT                   NULL,
    packet_size_std     FLOAT                   NULL,
    packet_size_min     INT                     NULL,
    packet_size_max     INT                     NULL,
    outbound_ratio      FLOAT                   NULL,

    -- Behavioral analysis
    interval_sec        FLOAT                   NULL,
    cv                  FLOAT                   NULL,
    entropy             FLOAT                   NULL,
    cmd_entropy         FLOAT                   NULL,

    -- Threat intelligence
    score               INT                     NULL,
    severity            VARCHAR(16)             NULL,
    category            VARCHAR(64)             NULL,
    mitre_tactic        VARCHAR(64)             NULL,
    mitre_technique     VARCHAR(32)             NULL,
    mitre_name          NVARCHAR(128)           NULL,
    signature_name      NVARCHAR(256)           NULL,
    description         NVARCHAR(2000)          NULL,
    reasons             NVARCHAR(MAX)           NULL,
    ml_result           VARCHAR(32)             NULL,

    -- Detection flags
    suppressed          INT                     NULL DEFAULT 0,
    masquerade_detected INT                     NULL DEFAULT 0,
    confidence          INT                     NULL,

    -- TLS / JA3
    ja3_hash            VARCHAR(64)             NULL,

    -- C2 sensor specific
    alert_reason        NVARCHAR(512)           NULL,
    destination         NVARCHAR(256)           NULL,
    domain              NVARCHAR(256)           NULL,
    host_ip             VARCHAR(45)             NULL,

    -- Raw payload for deep analysis
    payload_raw         NVARCHAR(MAX)           NULL,

    CONSTRAINT PK_EndpointTelemetry PRIMARY KEY NONCLUSTERED (event_id, event_timestamp)
) ON ps_MonthlyTelemetry(event_timestamp);
GO

-- Clustered columnstore for analytical queries (partitioned)
CREATE CLUSTERED COLUMNSTORE INDEX CCI_EndpointTelemetry
    ON dbo.EndpointTelemetry
    ON ps_MonthlyTelemetry(event_timestamp);
GO

-- B-tree indexes for operational lookups
CREATE NONCLUSTERED INDEX IX_Endpoint_SensorType_Time
    ON dbo.EndpointTelemetry (sensor_type, event_timestamp)
    INCLUDE (dst_ip, score, mitre_tactic)
    ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE NONCLUSTERED INDEX IX_Endpoint_Score
    ON dbo.EndpointTelemetry (score DESC, event_timestamp)
    WHERE score >= 50
    ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE NONCLUSTERED INDEX IX_Endpoint_DstIP
    ON dbo.EndpointTelemetry (dst_ip, event_timestamp)
    INCLUDE (sensor_type, process_name, score)
    ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE NONCLUSTERED INDEX IX_Endpoint_ProcessName
    ON dbo.EndpointTelemetry (process_name, event_timestamp)
    INCLUDE (pid, dst_ip, score, mitre_tactic)
    ON ps_MonthlyTelemetry(event_timestamp);
GO


/*══════════════════════════════════════════════════════════════════════════════
 * CLOUD TELEMETRY -- all 6 cloud connectors (UnifiedFlowRecord)
 * VPC Flow, NSG Flow, CloudTrail, Azure Activity, Entra ID, GuardDuty
 *══════════════════════════════════════════════════════════════════════════════*/

CREATE TABLE dbo.CloudTelemetry (
    event_id            BIGINT IDENTITY(1,1)    NOT NULL,
    event_timestamp     DATETIME2(3)            NOT NULL,
    sensor_type         VARCHAR(48)             NOT NULL,
    sensor_id           VARCHAR(128)            NULL,

    -- The cloud connectors use UnifiedFlowRecord which maps
    -- cloud-native fields into the C2 schema convention.
    -- process_name holds the action/resource name.
    -- process_hash holds the principal/caller identity.
    -- dst_ip holds the target resource or IP.

    -- Action / resource
    action_name         NVARCHAR(256)           NULL,
    caller_identity     NVARCHAR(256)           NULL,
    target_resource     NVARCHAR(512)           NULL,

    -- Network
    dst_ip              VARCHAR(45)             NULL,
    dst_port            INT                     NULL,
    src_ip              VARCHAR(45)             NULL,
    src_port            INT                     NULL,

    -- Flow statistics
    packet_count        BIGINT                  NULL,
    packet_size_mean    FLOAT                   NULL,
    outbound_ratio      FLOAT                   NULL,
    interval_sec        FLOAT                   NULL,

    -- Behavioral
    entropy             FLOAT                   NULL,
    cv                  FLOAT                   NULL,

    -- Cloud event type (vpc_flow, cloudtrail_api, guardduty_finding, etc.)
    event_type          VARCHAR(64)             NOT NULL,

    -- Threat / scoring
    score               INT                     NULL,
    mitre_tactic        VARCHAR(64)             NULL,
    mitre_technique     VARCHAR(32)             NULL,
    mitre_name          NVARCHAR(128)           NULL,
    description         NVARCHAR(2000)          NULL,
    reasons             NVARCHAR(MAX)           NULL,
    ml_result           VARCHAR(32)             NULL,

    -- Suppression
    suppressed          INT                     NULL DEFAULT 0,

    -- DNS
    dns_query           NVARCHAR(512)           NULL,

    -- Raw fields preserved
    ja3_hash            VARCHAR(64)             NULL,

    CONSTRAINT PK_CloudTelemetry PRIMARY KEY NONCLUSTERED (event_id, event_timestamp)
) ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE CLUSTERED COLUMNSTORE INDEX CCI_CloudTelemetry
    ON dbo.CloudTelemetry
    ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE NONCLUSTERED INDEX IX_Cloud_EventType_Time
    ON dbo.CloudTelemetry (event_type, event_timestamp)
    INCLUDE (action_name, score)
    ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE NONCLUSTERED INDEX IX_Cloud_CallerIdentity
    ON dbo.CloudTelemetry (caller_identity, event_timestamp)
    INCLUDE (event_type, action_name, score)
    ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE NONCLUSTERED INDEX IX_Cloud_Score
    ON dbo.CloudTelemetry (score DESC, event_timestamp)
    WHERE score >= 50
    ON ps_MonthlyTelemetry(event_timestamp);
GO


/*══════════════════════════════════════════════════════════════════════════════
 * NETWORK TELEMETRY -- Arkime NetTap session data (42+ fields)
 *══════════════════════════════════════════════════════════════════════════════*/

CREATE TABLE dbo.NetworkTelemetry (
    event_id                BIGINT IDENTITY(1,1)    NOT NULL,
    event_timestamp         DATETIME2(3)            NOT NULL,
    sensor_type             VARCHAR(32)             NOT NULL DEFAULT 'network_tap',
    sensor_name             VARCHAR(128)            NULL,

    -- Session identification
    session_id              VARCHAR(64)             NULL,

    -- 5-tuple
    src_ip                  VARCHAR(45)             NOT NULL,
    dst_ip                  VARCHAR(45)             NOT NULL,
    src_port                INT                     NULL,
    dst_port                INT                     NULL,
    protocol                INT                     NULL,
    protocol_name           VARCHAR(16)             NULL,

    -- Session timing
    timestamp_start         BIGINT                  NULL,
    timestamp_end           BIGINT                  NULL,
    session_duration_ms     INT                     NULL,

    -- Volume
    bytes_src               BIGINT                  NULL,
    bytes_dst               BIGINT                  NULL,
    data_bytes_src          BIGINT                  NULL,
    data_bytes_dst          BIGINT                  NULL,
    packets_src             INT                     NULL,
    packets_dst             INT                     NULL,

    -- Statistical features
    byte_ratio              FLOAT                   NULL,
    avg_inter_arrival       FLOAT                   NULL,
    variance_inter_arrival  FLOAT                   NULL,
    ratio_small_packets     FLOAT                   NULL,
    ratio_large_packets     FLOAT                   NULL,
    payload_entropy         FLOAT                   NULL,

    -- TCP flags
    tcp_syn                 INT                     NULL,
    tcp_rst                 INT                     NULL,
    tcp_fin                 INT                     NULL,

    -- DNS
    dns_query               NVARCHAR(512)           NULL,
    dns_status              VARCHAR(32)             NULL,

    -- HTTP
    http_method             VARCHAR(16)             NULL,
    http_uri                NVARCHAR(2000)          NULL,
    http_useragent          NVARCHAR(512)           NULL,
    http_status_code        INT                     NULL,

    -- TLS / Certificates
    tls_ja3                 VARCHAR(64)             NULL,
    tls_ja3s                VARCHAR(64)             NULL,
    tls_version             VARCHAR(16)             NULL,
    tls_cipher              VARCHAR(64)             NULL,
    cert_cn                 NVARCHAR(256)           NULL,
    cert_issuer_cn          NVARCHAR(256)           NULL,
    cert_self_signed        BIT                     NULL,
    cert_valid_days         INT                     NULL,

    -- Geo / ASN
    hostname                NVARCHAR(256)           NULL,
    src_geo_country         VARCHAR(64)             NULL,
    dst_geo_country         VARCHAR(64)             NULL,
    dst_asn_org             NVARCHAR(256)           NULL,

    CONSTRAINT PK_NetworkTelemetry PRIMARY KEY NONCLUSTERED (event_id, event_timestamp)
) ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE CLUSTERED COLUMNSTORE INDEX CCI_NetworkTelemetry
    ON dbo.NetworkTelemetry
    ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE NONCLUSTERED INDEX IX_Network_SrcDst
    ON dbo.NetworkTelemetry (src_ip, dst_ip, event_timestamp)
    INCLUDE (dst_port, protocol_name, session_duration_ms)
    ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE NONCLUSTERED INDEX IX_Network_JA3
    ON dbo.NetworkTelemetry (tls_ja3, event_timestamp)
    WHERE tls_ja3 IS NOT NULL
    ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE NONCLUSTERED INDEX IX_Network_DnsQuery
    ON dbo.NetworkTelemetry (dns_query, event_timestamp)
    WHERE dns_query IS NOT NULL
    ON ps_MonthlyTelemetry(event_timestamp);
GO

CREATE NONCLUSTERED INDEX IX_Network_SelfSignedCerts
    ON dbo.NetworkTelemetry (cert_self_signed, event_timestamp)
    INCLUDE (dst_ip, cert_cn, cert_issuer_cn)
    WHERE cert_self_signed = 1
    ON ps_MonthlyTelemetry(event_timestamp);
GO


/*══════════════════════════════════════════════════════════════════════════════
 * INGEST TRACKING -- batch-level audit trail
 *══════════════════════════════════════════════════════════════════════════════*/

CREATE TABLE dbo.IngestLog (
    log_id              BIGINT IDENTITY(1,1)    NOT NULL,
    batch_utc           DATETIME2(3)            NOT NULL DEFAULT SYSUTCDATETIME(),
    sensor_type         VARCHAR(64)             NOT NULL,
    events_received     INT                     NOT NULL DEFAULT 0,
    events_inserted     INT                     NOT NULL DEFAULT 0,
    events_rejected     INT                     NOT NULL DEFAULT 0,
    duration_ms         INT                     NULL,
    error_message       NVARCHAR(2000)          NULL,
    CONSTRAINT PK_IngestLog PRIMARY KEY CLUSTERED (log_id)
) WITH (DATA_COMPRESSION = PAGE);
GO


PRINT 'All tables, columnstore indexes, and B-tree indexes created.';
GO
