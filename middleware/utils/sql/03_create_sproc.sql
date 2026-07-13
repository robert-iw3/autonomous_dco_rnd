/*============================================================================
 * SENTINEL NEXUS -- Middleware SQL Server Telemetry Store
 * Script 3/4: dbo.sp_IngestSensorTelemetry
 *
 * Called by middleware worker_sql:
 *   EXEC dbo.sp_IngestSensorTelemetry @json = @p1
 *
 * @json contains a JSON array of events. Each event has a "sensor_type"
 * field injected by the middleware from the X-Sensor-Type NATS header.
 * Events are routed to the correct partitioned table based on sensor_type.
 *
 * Routing:
 *   linux-c2-sensor, Linux-Sentinel, windows_deepsensor, c2sensor        →  EndpointTelemetry
 *
 *   *-connector, *_flow, cloudtrail_*, azure_*, entraid_*, guardduty_*   →  CloudTelemetry
 *
 *   network_tap                                                       →  NetworkTelemetry
 *============================================================================*/

USE Sensor_Telemetry;
GO

IF OBJECT_ID('dbo.sp_IngestSensorTelemetry', 'P') IS NOT NULL
    DROP PROCEDURE dbo.sp_IngestSensorTelemetry;
GO

CREATE PROCEDURE dbo.sp_IngestSensorTelemetry
    @json NVARCHAR(MAX)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @start DATETIME2(3) = SYSUTCDATETIME();
    DECLARE @total_received INT = 0;
    DECLARE @endpoint_inserted INT = 0;
    DECLARE @cloud_inserted INT = 0;
    DECLARE @network_inserted INT = 0;
    DECLARE @rejected INT = 0;
    DECLARE @error_msg NVARCHAR(2000) = NULL;

    BEGIN TRY

        /*──────────────────────────────────────────────────────────
         * STEP 1: Parse JSON array into a temp table
         * Each row = one event with its raw JSON + sensor_type
         *──────────────────────────────────────────────────────────*/

        CREATE TABLE #Events (
            row_num     INT IDENTITY(1,1) NOT NULL,
            sensor_type VARCHAR(64)       NULL,
            event_json  NVARCHAR(MAX)     NOT NULL
        );

        INSERT INTO #Events (sensor_type, event_json)
        SELECT
            JSON_VALUE(j.[value], '$.sensor_type'),
            j.[value]
        FROM OPENJSON(@json) AS j;

        SET @total_received = @@ROWCOUNT;

        IF @total_received = 0
        BEGIN
            -- Empty array: log and exit
            INSERT INTO dbo.IngestLog (sensor_type, events_received, events_inserted, duration_ms)
            VALUES ('empty', 0, 0, DATEDIFF(MILLISECOND, @start, SYSUTCDATETIME()));
            RETURN;
        END

        /*──────────────────────────────────────────────────────────
         * STEP 2: Route ENDPOINT events
         * (linux-c2-sensor, Linux-Sentinel, windows_deepsensor, c2sensor)
         *──────────────────────────────────────────────────────────*/

        INSERT INTO dbo.EndpointTelemetry (
            event_timestamp, sensor_type, sensor_id, hostname,
            process_name, pid, parent_pid, uid, tid,
            process_hash, command_line, parent_image, process_tree, cmd_snippet,
            event_user, event_type, dst_ip, dst_port, src_ip,
            dns_query, dns_flags,
            packet_count, packet_size_mean, packet_size_std,
            packet_size_min, packet_size_max, outbound_ratio,
            interval_sec, cv, entropy, cmd_entropy,
            score, severity, category,
            mitre_tactic, mitre_technique, mitre_name,
            signature_name, description, reasons, ml_result,
            suppressed, masquerade_detected, confidence,
            ja3_hash, alert_reason, destination, domain, host_ip,
            payload_raw
        )
        SELECT
            -- Timestamp: float epoch → datetime, or ISO string, or fallback to now
            CASE
                WHEN ISNUMERIC(JSON_VALUE(e.event_json, '$.timestamp')) = 1
                    THEN DATEADD(SECOND,
                         CAST(JSON_VALUE(e.event_json, '$.timestamp') AS BIGINT),
                         '1970-01-01')
                WHEN TRY_CAST(JSON_VALUE(e.event_json, '$.timestamp') AS DATETIME2) IS NOT NULL
                    THEN TRY_CAST(JSON_VALUE(e.event_json, '$.timestamp') AS DATETIME2)
                ELSE SYSUTCDATETIME()
            END,
            e.sensor_type,
            JSON_VALUE(e.event_json, '$.sensor_id'),
            JSON_VALUE(e.event_json, '$.hostname'),

            COALESCE(
                JSON_VALUE(e.event_json, '$.process_name'),
                JSON_VALUE(e.event_json, '$.path'),
                JSON_VALUE(e.event_json, '$.process')
            ),
            JSON_VALUE(e.event_json, '$.pid'),
            JSON_VALUE(e.event_json, '$.parent_pid'),
            JSON_VALUE(e.event_json, '$.uid'),
            JSON_VALUE(e.event_json, '$.tid'),
            JSON_VALUE(e.event_json, '$.process_hash'),
            JSON_VALUE(e.event_json, '$.command_line'),
            JSON_VALUE(e.event_json, '$.parent_image'),
            JSON_VALUE(e.event_json, '$.process_tree'),
            JSON_VALUE(e.event_json, '$.cmd_snippet'),

            COALESCE(
                JSON_VALUE(e.event_json, '$.event_user'),
                JSON_VALUE(e.event_json, '$.user')
            ),
            JSON_VALUE(e.event_json, '$.event_type'),
            COALESCE(
                JSON_VALUE(e.event_json, '$.dst_ip'),
                JSON_VALUE(e.event_json, '$.destination_ip'),
                JSON_VALUE(e.event_json, '$.destination')
            ),
            COALESCE(
                JSON_VALUE(e.event_json, '$.dst_port'),
                JSON_VALUE(e.event_json, '$.port')
            ),
            COALESCE(
                JSON_VALUE(e.event_json, '$.src_ip'),
                JSON_VALUE(e.event_json, '$.host_ip')
            ),
            JSON_VALUE(e.event_json, '$.dns_query'),
            JSON_VALUE(e.event_json, '$.dns_flags'),

            JSON_VALUE(e.event_json, '$.packet_count'),
            JSON_VALUE(e.event_json, '$.packet_size_mean'),
            JSON_VALUE(e.event_json, '$.packet_size_std'),
            JSON_VALUE(e.event_json, '$.packet_size_min'),
            JSON_VALUE(e.event_json, '$.packet_size_max'),
            JSON_VALUE(e.event_json, '$.outbound_ratio'),

            JSON_VALUE(e.event_json, '$.interval'),
            JSON_VALUE(e.event_json, '$.cv'),
            JSON_VALUE(e.event_json, '$.entropy'),
            JSON_VALUE(e.event_json, '$.cmd_entropy'),

            JSON_VALUE(e.event_json, '$.score'),
            JSON_VALUE(e.event_json, '$.severity'),
            JSON_VALUE(e.event_json, '$.category'),
            COALESCE(
                JSON_VALUE(e.event_json, '$.mitre_tactic'),
                JSON_VALUE(e.event_json, '$.tactic')
            ),
            COALESCE(
                JSON_VALUE(e.event_json, '$.mitre_technique'),
                JSON_VALUE(e.event_json, '$.technique')
            ),
            JSON_VALUE(e.event_json, '$.mitre_name'),
            JSON_VALUE(e.event_json, '$.signature_name'),
            JSON_VALUE(e.event_json, '$.description'),
            JSON_VALUE(e.event_json, '$.reasons'),
            JSON_VALUE(e.event_json, '$.ml_result'),

            JSON_VALUE(e.event_json, '$.suppressed'),
            JSON_VALUE(e.event_json, '$.masquerade_detected'),
            JSON_VALUE(e.event_json, '$.confidence'),
            JSON_VALUE(e.event_json, '$.ja3_hash'),
            JSON_VALUE(e.event_json, '$.alert_reason'),
            JSON_VALUE(e.event_json, '$.destination'),
            JSON_VALUE(e.event_json, '$.domain'),
            JSON_VALUE(e.event_json, '$.host_ip'),
            JSON_VALUE(e.event_json, '$.payload_raw')
        FROM #Events e
        WHERE e.sensor_type IN ('linux-c2-sensor', 'Linux-Sentinel', 'windows_deepsensor', 'c2sensor');

        SET @endpoint_inserted = @@ROWCOUNT;


        /*──────────────────────────────────────────────────────────
         * STEP 3: Route CLOUD events
         * (all 6 cloud connector types)
         *──────────────────────────────────────────────────────────*/

        INSERT INTO dbo.CloudTelemetry (
            event_timestamp, sensor_type, sensor_id,
            action_name, caller_identity, target_resource,
            dst_ip, dst_port, src_ip, src_port,
            packet_count, packet_size_mean, outbound_ratio, interval_sec,
            entropy, cv, event_type,
            score, mitre_tactic, mitre_technique, mitre_name,
            description, reasons, ml_result, suppressed,
            dns_query, ja3_hash
        )
        SELECT
            CASE
                WHEN ISNUMERIC(JSON_VALUE(e.event_json, '$.timestamp')) = 1
                    THEN DATEADD(SECOND,
                         CAST(JSON_VALUE(e.event_json, '$.timestamp') AS BIGINT),
                         '1970-01-01')
                ELSE SYSUTCDATETIME()
            END,
            e.sensor_type,
            JSON_VALUE(e.event_json, '$.sensor_id'),

            -- Cloud connectors pack action into process_name
            JSON_VALUE(e.event_json, '$.process_name'),
            -- Caller identity into process_hash
            JSON_VALUE(e.event_json, '$.process_hash'),
            -- Target resource often in description or dst_ip
            JSON_VALUE(e.event_json, '$.description'),

            JSON_VALUE(e.event_json, '$.dst_ip'),
            JSON_VALUE(e.event_json, '$.dst_port'),
            NULL, -- src_ip not in UnifiedFlowRecord
            NULL, -- src_port not in UnifiedFlowRecord

            JSON_VALUE(e.event_json, '$.packet_count'),
            JSON_VALUE(e.event_json, '$.packet_size_mean'),
            JSON_VALUE(e.event_json, '$.outbound_ratio'),
            JSON_VALUE(e.event_json, '$.interval'),

            JSON_VALUE(e.event_json, '$.entropy'),
            JSON_VALUE(e.event_json, '$.cv'),
            JSON_VALUE(e.event_json, '$.event_type'),

            JSON_VALUE(e.event_json, '$.score'),
            JSON_VALUE(e.event_json, '$.mitre_tactic'),
            JSON_VALUE(e.event_json, '$.mitre_technique'),
            JSON_VALUE(e.event_json, '$.mitre_name'),
            JSON_VALUE(e.event_json, '$.description'),
            JSON_VALUE(e.event_json, '$.reasons'),
            JSON_VALUE(e.event_json, '$.ml_result'),
            JSON_VALUE(e.event_json, '$.suppressed'),
            JSON_VALUE(e.event_json, '$.dns_query'),
            JSON_VALUE(e.event_json, '$.ja3_hash')
        FROM #Events e
        WHERE e.sensor_type IN (
            'aws-vpc-flow-connector',
            'aws-cloudtrail-connector',
            'aws-guardduty-connector',
            'azure-nsg-flow-connector',
            'azure-activity-connector',
            'azure-entraid-connector'
        )
        -- Fallback: match by event_type if sensor_type wasn't injected
        OR JSON_VALUE(e.event_json, '$.event_type') IN (
            'vpc_flow', 'nsg_flow', 'cloudtrail_api',
            'azure_activity', 'entraid_signin', 'guardduty_finding'
        );

        SET @cloud_inserted = @@ROWCOUNT;


        /*──────────────────────────────────────────────────────────
         * STEP 4: Route NETWORK TAP events (Arkime)
         *──────────────────────────────────────────────────────────*/

        INSERT INTO dbo.NetworkTelemetry (
            event_timestamp, sensor_type, sensor_name, session_id,
            src_ip, dst_ip, src_port, dst_port, protocol, protocol_name,
            timestamp_start, timestamp_end, session_duration_ms,
            bytes_src, bytes_dst, data_bytes_src, data_bytes_dst,
            packets_src, packets_dst,
            byte_ratio, avg_inter_arrival, variance_inter_arrival,
            ratio_small_packets, ratio_large_packets, payload_entropy,
            tcp_syn, tcp_rst, tcp_fin,
            dns_query, dns_status,
            http_method, http_uri, http_useragent, http_status_code,
            tls_ja3, tls_ja3s, tls_version, tls_cipher,
            cert_cn, cert_issuer_cn, cert_self_signed, cert_valid_days,
            hostname, src_geo_country, dst_geo_country, dst_asn_org
        )
        SELECT
            CASE
                WHEN JSON_VALUE(e.event_json, '$.timestamp_start') IS NOT NULL
                    THEN DATEADD(SECOND,
                         CAST(JSON_VALUE(e.event_json, '$.timestamp_start') AS BIGINT),
                         '1970-01-01')
                ELSE SYSUTCDATETIME()
            END,
            COALESCE(e.sensor_type, 'network_tap'),
            JSON_VALUE(e.event_json, '$.sensor_name'),
            JSON_VALUE(e.event_json, '$.session_id'),

            COALESCE(JSON_VALUE(e.event_json, '$.src_ip'), '0.0.0.0'),
            COALESCE(JSON_VALUE(e.event_json, '$.dst_ip'), '0.0.0.0'),
            JSON_VALUE(e.event_json, '$.src_port'),
            JSON_VALUE(e.event_json, '$.dst_port'),
            JSON_VALUE(e.event_json, '$.protocol'),
            JSON_VALUE(e.event_json, '$.protocol_name'),

            JSON_VALUE(e.event_json, '$.timestamp_start'),
            JSON_VALUE(e.event_json, '$.timestamp_end'),
            JSON_VALUE(e.event_json, '$.session_duration_ms'),

            JSON_VALUE(e.event_json, '$.bytes_src'),
            JSON_VALUE(e.event_json, '$.bytes_dst'),
            JSON_VALUE(e.event_json, '$.data_bytes_src'),
            JSON_VALUE(e.event_json, '$.data_bytes_dst'),
            JSON_VALUE(e.event_json, '$.packets_src'),
            JSON_VALUE(e.event_json, '$.packets_dst'),

            JSON_VALUE(e.event_json, '$.byte_ratio'),
            JSON_VALUE(e.event_json, '$.avg_inter_arrival'),
            JSON_VALUE(e.event_json, '$.variance_inter_arrival'),
            JSON_VALUE(e.event_json, '$.ratio_small_packets'),
            JSON_VALUE(e.event_json, '$.ratio_large_packets'),
            JSON_VALUE(e.event_json, '$.payload_entropy'),

            JSON_VALUE(e.event_json, '$.tcp_syn'),
            JSON_VALUE(e.event_json, '$.tcp_rst'),
            JSON_VALUE(e.event_json, '$.tcp_fin'),

            JSON_VALUE(e.event_json, '$.dns_query'),
            JSON_VALUE(e.event_json, '$.dns_status'),

            JSON_VALUE(e.event_json, '$.http_method'),
            JSON_VALUE(e.event_json, '$.http_uri'),
            JSON_VALUE(e.event_json, '$.http_useragent'),
            JSON_VALUE(e.event_json, '$.http_status_code'),

            JSON_VALUE(e.event_json, '$.tls_ja3'),
            JSON_VALUE(e.event_json, '$.tls_ja3s'),
            JSON_VALUE(e.event_json, '$.tls_version'),
            JSON_VALUE(e.event_json, '$.tls_cipher'),
            JSON_VALUE(e.event_json, '$.cert_cn'),
            JSON_VALUE(e.event_json, '$.cert_issuer_cn'),
            CASE JSON_VALUE(e.event_json, '$.cert_self_signed')
                WHEN 'true' THEN 1 WHEN '1' THEN 1 ELSE 0 END,
            JSON_VALUE(e.event_json, '$.cert_valid_days'),

            JSON_VALUE(e.event_json, '$.hostname'),
            JSON_VALUE(e.event_json, '$.src_geo_country'),
            JSON_VALUE(e.event_json, '$.dst_geo_country'),
            JSON_VALUE(e.event_json, '$.dst_asn_org')
        FROM #Events e
        WHERE e.sensor_type = 'network_tap'
           OR JSON_VALUE(e.event_json, '$.session_id') IS NOT NULL;

        SET @network_inserted = @@ROWCOUNT;


        /*──────────────────────────────────────────────────────────
         * STEP 5: Count unrouted events
         *──────────────────────────────────────────────────────────*/

        SET @rejected = @total_received
                      - @endpoint_inserted
                      - @cloud_inserted
                      - @network_inserted;

        -- If there are unrouted events, log them for debugging
        IF @rejected > 0
        BEGIN
            DECLARE @unrouted_types NVARCHAR(500);
            SELECT @unrouted_types = STRING_AGG(COALESCE(sensor_type, 'NULL'), ', ')
            FROM #Events e
            WHERE e.sensor_type NOT IN (
                'linux-c2-sensor','Linux-Sentinel','windows_deepsensor','c2sensor',
                'aws-vpc-flow-connector','aws-cloudtrail-connector','aws-guardduty-connector',
                'azure-nsg-flow-connector','azure-activity-connector','azure-entraid-connector',
                'network_tap'
            )
            AND JSON_VALUE(e.event_json, '$.session_id') IS NULL
            AND JSON_VALUE(e.event_json, '$.event_type') NOT IN (
                'vpc_flow','nsg_flow','cloudtrail_api',
                'azure_activity','entraid_signin','guardduty_finding'
            );

            SET @error_msg = 'Unrouted sensor types: ' + ISNULL(@unrouted_types, 'unknown');
        END

        DROP TABLE #Events;

    END TRY
    BEGIN CATCH
        SET @error_msg = ERROR_MESSAGE();
        SET @rejected = @total_received;

        IF OBJECT_ID('tempdb..#Events') IS NOT NULL
            DROP TABLE #Events;
    END CATCH

    /*──────────────────────────────────────────────────────────
     * STEP 6: Audit log
     *──────────────────────────────────────────────────────────*/

    DECLARE @primary_type VARCHAR(64) = CASE
        WHEN @endpoint_inserted > @cloud_inserted
             AND @endpoint_inserted > @network_inserted THEN 'endpoint'
        WHEN @cloud_inserted > @network_inserted THEN 'cloud'
        WHEN @network_inserted > 0 THEN 'network'
        ELSE 'mixed'
    END;

    INSERT INTO dbo.IngestLog (
        sensor_type, events_received, events_inserted,
        events_rejected, duration_ms, error_message
    )
    VALUES (
        @primary_type,
        @total_received,
        @endpoint_inserted + @cloud_inserted + @network_inserted,
        @rejected,
        DATEDIFF(MILLISECOND, @start, SYSUTCDATETIME()),
        @error_msg
    );

    -- Return summary to caller for metrics
    SELECT
        @total_received     AS events_received,
        @endpoint_inserted  AS endpoint_inserted,
        @cloud_inserted     AS cloud_inserted,
        @network_inserted   AS network_inserted,
        @rejected           AS rejected,
        DATEDIFF(MILLISECOND, @start, SYSUTCDATETIME()) AS duration_ms;

END
GO

PRINT 'dbo.sp_IngestSensorTelemetry created.';
GO