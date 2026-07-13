/*============================================================================
 * SENTINEL NEXUS -- Middleware SQL Server Telemetry Store
 * Script 4/4: Maintenance -- Partition Management, Retention, Statistics
 *
 * Schedule these via SQL Agent:
 *   sp_MaintainPartitions     -- monthly, 1st of month at 02:00
 *   sp_PurgeExpiredPartitions -- monthly, 2nd of month at 03:00
 *   sp_RebuildColumnstoreSegments -- weekly, Sunday 04:00
 *============================================================================*/

USE Sensor_Telemetry;
GO

/*══════════════════════════════════════════════════════════════════════════════
 * PARTITION ROLLOVER -- adds next month's partition and filegroup
 * Run monthly. Idempotent: skips if the partition already exists.
 *══════════════════════════════════════════════════════════════════════════════*/

IF OBJECT_ID('dbo.sp_MaintainPartitions', 'P') IS NOT NULL
    DROP PROCEDURE dbo.sp_MaintainPartitions;
GO

CREATE PROCEDURE dbo.sp_MaintainPartitions
    @months_ahead INT = 3
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @i INT = 1;
    WHILE @i <= @months_ahead
    BEGIN
        DECLARE @target_date DATE = DATEADD(MONTH, @i,
            DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1));
        DECLARE @fg_name NVARCHAR(20) = N'FG_' + FORMAT(@target_date, 'yyyy_MM');
        DECLARE @boundary DATETIME2(3) = CAST(@target_date AS DATETIME2(3));

        -- Create filegroup if not exists
        IF NOT EXISTS (SELECT 1 FROM sys.filegroups WHERE name = @fg_name)
        BEGIN
            DECLARE @fg_sql NVARCHAR(MAX) = N'
                ALTER DATABASE Sensor_Telemetry ADD FILEGROUP [' + @fg_name + N'];
                ALTER DATABASE Sensor_Telemetry ADD FILE (
                    NAME = N''SensorTelemetry_' + FORMAT(@target_date, 'yyyy_MM') + N''',
                    FILENAME = N''D:\SQLData\SensorTelemetry_' + FORMAT(@target_date, 'yyyy_MM') + N'.ndf'',
                    SIZE = 128MB, FILEGROWTH = 128MB
                ) TO FILEGROUP [' + @fg_name + N'];';
            EXEC sp_executesql @fg_sql;
            PRINT 'Created filegroup ' + @fg_name;
        END

        -- Check if boundary already exists
        IF NOT EXISTS (
            SELECT 1 FROM sys.partition_range_values prv
            JOIN sys.partition_functions pf ON pf.function_id = prv.function_id
            WHERE pf.name = 'pf_MonthlyTelemetry'
              AND CAST(prv.value AS DATETIME2(3)) = @boundary
        )
        BEGIN
            -- Map the new filegroup into the scheme
            ALTER PARTITION SCHEME ps_MonthlyTelemetry
                NEXT USED [PRIMARY]; -- fallback, then set properly

            DECLARE @next_sql NVARCHAR(MAX) = N'
                ALTER PARTITION SCHEME ps_MonthlyTelemetry
                    NEXT USED [' + @fg_name + N'];
                ALTER PARTITION FUNCTION pf_MonthlyTelemetry()
                    SPLIT RANGE (''' + CONVERT(NVARCHAR(30), @boundary, 126) + N''');';
            EXEC sp_executesql @next_sql;
            PRINT 'Split partition at boundary ' + CONVERT(VARCHAR(30), @boundary, 126);
        END

        SET @i += 1;
    END

    PRINT 'Partition maintenance complete.';
END
GO


/*══════════════════════════════════════════════════════════════════════════════
 * PARTITION PURGE -- drops partitions older than @retention_months
 * Uses TRUNCATE TABLE ... WITH (PARTITIONS(...)) for instant removal.
 *══════════════════════════════════════════════════════════════════════════════*/

IF OBJECT_ID('dbo.sp_PurgeExpiredPartitions', 'P') IS NOT NULL
    DROP PROCEDURE dbo.sp_PurgeExpiredPartitions;
GO

CREATE PROCEDURE dbo.sp_PurgeExpiredPartitions
    @retention_months INT = 12
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @cutoff DATETIME2(3) = DATEADD(MONTH, -@retention_months,
        DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1));

    DECLARE @expired_partitions TABLE (partition_number INT);

    -- Find partitions with boundaries before the cutoff
    INSERT INTO @expired_partitions (partition_number)
    SELECT prv.boundary_id
    FROM sys.partition_range_values prv
    JOIN sys.partition_functions pf ON pf.function_id = prv.function_id
    WHERE pf.name = 'pf_MonthlyTelemetry'
      AND CAST(prv.value AS DATETIME2(3)) < @cutoff;

    IF NOT EXISTS (SELECT 1 FROM @expired_partitions)
    BEGIN
        PRINT 'No expired partitions found.';
        RETURN;
    END

    DECLARE @pnum INT;
    DECLARE pc CURSOR LOCAL FAST_FORWARD FOR
        SELECT partition_number FROM @expired_partitions ORDER BY partition_number;

    OPEN pc;
    FETCH NEXT FROM pc INTO @pnum;

    WHILE @@FETCH_STATUS = 0
    BEGIN
        DECLARE @trunc_sql NVARCHAR(MAX);

        SET @trunc_sql = N'TRUNCATE TABLE dbo.EndpointTelemetry WITH (PARTITIONS(' + CAST(@pnum AS NVARCHAR(10)) + N'));';
        EXEC sp_executesql @trunc_sql;

        SET @trunc_sql = N'TRUNCATE TABLE dbo.CloudTelemetry WITH (PARTITIONS(' + CAST(@pnum AS NVARCHAR(10)) + N'));';
        EXEC sp_executesql @trunc_sql;

        SET @trunc_sql = N'TRUNCATE TABLE dbo.NetworkTelemetry WITH (PARTITIONS(' + CAST(@pnum AS NVARCHAR(10)) + N'));';
        EXEC sp_executesql @trunc_sql;

        PRINT 'Truncated partition ' + CAST(@pnum AS VARCHAR(10));

        FETCH NEXT FROM pc INTO @pnum;
    END

    CLOSE pc;
    DEALLOCATE pc;

    -- Merge emptied partitions to reclaim metadata
    DECLARE @merge_val DATETIME2(3);
    DECLARE mc CURSOR LOCAL FAST_FORWARD FOR
        SELECT CAST(prv.value AS DATETIME2(3))
        FROM sys.partition_range_values prv
        JOIN sys.partition_functions pf ON pf.function_id = prv.function_id
        WHERE pf.name = 'pf_MonthlyTelemetry'
          AND CAST(prv.value AS DATETIME2(3)) < @cutoff
        ORDER BY prv.value;

    OPEN mc;
    FETCH NEXT FROM mc INTO @merge_val;

    WHILE @@FETCH_STATUS = 0
    BEGIN
        DECLARE @merge_sql NVARCHAR(MAX) = N'
            ALTER PARTITION FUNCTION pf_MonthlyTelemetry()
                MERGE RANGE (''' + CONVERT(NVARCHAR(30), @merge_val, 126) + N''');';
        BEGIN TRY
            EXEC sp_executesql @merge_sql;
            PRINT 'Merged boundary ' + CONVERT(VARCHAR(30), @merge_val, 126);
        END TRY
        BEGIN CATCH
            PRINT 'Merge failed for ' + CONVERT(VARCHAR(30), @merge_val, 126) + ': ' + ERROR_MESSAGE();
        END CATCH

        FETCH NEXT FROM mc INTO @merge_val;
    END

    CLOSE mc;
    DEALLOCATE mc;

    -- Clean up staging older than retention
    DELETE FROM dbo.IngestStaging
    WHERE received_utc < DATEADD(DAY, -7, GETUTCDATE());

    -- Clean up ingest log older than retention
    DELETE FROM dbo.IngestLog
    WHERE batch_utc < DATEADD(MONTH, -@retention_months, GETUTCDATE());

    PRINT 'Purge complete. Retention: ' + CAST(@retention_months AS VARCHAR(4)) + ' months.';
END
GO


/*══════════════════════════════════════════════════════════════════════════════
 * COLUMNSTORE MAINTENANCE -- reorganize open/compressed row groups
 * Run weekly. Targets fragmented segments for better compression.
 *══════════════════════════════════════════════════════════════════════════════*/

IF OBJECT_ID('dbo.sp_RebuildColumnstoreSegments', 'P') IS NOT NULL
    DROP PROCEDURE dbo.sp_RebuildColumnstoreSegments;
GO

CREATE PROCEDURE dbo.sp_RebuildColumnstoreSegments
    @fragmentation_threshold INT = 20
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @tbl NVARCHAR(128);
    DECLARE @idx NVARCHAR(128);
    DECLARE @pnum INT;
    DECLARE @frag FLOAT;
    DECLARE @sql NVARCHAR(MAX);

    -- Find fragmented columnstore partitions
    DECLARE frag_cursor CURSOR LOCAL FAST_FORWARD FOR
        SELECT
            QUOTENAME(OBJECT_SCHEMA_NAME(i.object_id)) + '.' + QUOTENAME(OBJECT_NAME(i.object_id)),
            QUOTENAME(i.name),
            p.partition_number,
            100.0 * SUM(CASE WHEN rg.state = 2 THEN rg.total_rows ELSE 0 END)
                  / NULLIF(SUM(rg.total_rows), 0) AS pct_deleted
        FROM sys.indexes i
        JOIN sys.partitions p ON p.object_id = i.object_id AND p.index_id = i.index_id
        JOIN sys.column_store_row_groups rg ON rg.object_id = i.object_id
            AND rg.index_id = i.index_id AND rg.partition_number = p.partition_number
        WHERE i.type IN (5, 6) -- clustered / nonclustered columnstore
          AND p.rows > 0
        GROUP BY i.object_id, i.name, p.partition_number
        HAVING SUM(CASE WHEN rg.state = 1 THEN 1 ELSE 0 END) > 0  -- has open row groups
            OR 100.0 * SUM(CASE WHEN rg.state = 2 THEN rg.total_rows ELSE 0 END)
                     / NULLIF(SUM(rg.total_rows), 0) > @fragmentation_threshold;

    OPEN frag_cursor;
    FETCH NEXT FROM frag_cursor INTO @tbl, @idx, @pnum, @frag;

    WHILE @@FETCH_STATUS = 0
    BEGIN
        -- Reorganize compresses open delta stores; rebuild defragments
        IF @frag > 50
            SET @sql = N'ALTER INDEX ' + @idx + N' ON ' + @tbl
                     + N' REBUILD PARTITION = ' + CAST(@pnum AS NVARCHAR(10))
                     + N' WITH (ONLINE = ON, MAXDOP = 4);';
        ELSE
            SET @sql = N'ALTER INDEX ' + @idx + N' ON ' + @tbl
                     + N' REORGANIZE PARTITION = ' + CAST(@pnum AS NVARCHAR(10))
                     + N' WITH (COMPRESS_ALL_ROW_GROUPS = ON);';

        BEGIN TRY
            EXEC sp_executesql @sql;
            PRINT 'Maintained ' + @tbl + ' partition ' + CAST(@pnum AS VARCHAR(10))
                + ' (frag ' + CAST(CAST(@frag AS INT) AS VARCHAR(4)) + '%)';
        END TRY
        BEGIN CATCH
            PRINT 'Failed: ' + @tbl + ' p' + CAST(@pnum AS VARCHAR(10))
                + ': ' + ERROR_MESSAGE();
        END CATCH

        FETCH NEXT FROM frag_cursor INTO @tbl, @idx, @pnum, @frag;
    END

    CLOSE frag_cursor;
    DEALLOCATE frag_cursor;

    -- Update statistics on all tables
    EXEC sp_updatestats;

    PRINT 'Columnstore maintenance complete.';
END
GO


/*══════════════════════════════════════════════════════════════════════════════
 * ANALYTICAL VIEWS -- commonly queried aggregations
 *══════════════════════════════════════════════════════════════════════════════*/

CREATE OR ALTER VIEW dbo.vw_HighRiskEndpoint AS
SELECT
    event_timestamp, sensor_type, hostname, process_name,
    dst_ip, dst_port, score, mitre_tactic, mitre_technique,
    ml_result, reasons
FROM dbo.EndpointTelemetry
WHERE score >= 70
  AND suppressed = 0;
GO

CREATE OR ALTER VIEW dbo.vw_CloudAlerts AS
SELECT
    event_timestamp, sensor_type, event_type,
    action_name, caller_identity, target_resource,
    dst_ip, score, mitre_tactic, description
FROM dbo.CloudTelemetry
WHERE score >= 50;
GO

CREATE OR ALTER VIEW dbo.vw_SuspiciousNetworkSessions AS
SELECT
    event_timestamp, src_ip, dst_ip, dst_port,
    protocol_name, session_duration_ms,
    bytes_src + bytes_dst AS total_bytes,
    payload_entropy, tls_ja3, cert_self_signed,
    cert_cn, dst_geo_country, dst_asn_org
FROM dbo.NetworkTelemetry
WHERE (payload_entropy > 7.5 OR cert_self_signed = 1)
  AND session_duration_ms > 1000;
GO

CREATE OR ALTER VIEW dbo.vw_IngestHealth AS
SELECT
    CAST(batch_utc AS DATE)     AS ingest_date,
    sensor_type,
    COUNT(*)                    AS batches,
    SUM(events_received)        AS total_received,
    SUM(events_inserted)        AS total_inserted,
    SUM(events_rejected)        AS total_rejected,
    AVG(duration_ms)            AS avg_sproc_ms,
    MAX(duration_ms)            AS max_sproc_ms
FROM dbo.IngestLog
GROUP BY CAST(batch_utc AS DATE), sensor_type;
GO


PRINT 'Maintenance procedures and analytical views created.';
GO
