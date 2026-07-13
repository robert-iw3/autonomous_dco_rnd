/*============================================================================
 * SENTINEL NEXUS -- Middleware SQL Server Telemetry Store
 * Script 1/4: Database, Filegroups, Partition Function & Scheme
 *
 * Run as sysadmin. Adjust paths to match your disk layout.
 * Creates 25 monthly filegroups (current month ± 12 months).
 *============================================================================*/

USE master;
GO

IF DB_ID('Sensor_Telemetry') IS NOT NULL
BEGIN
    ALTER DATABASE Sensor_Telemetry SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE Sensor_Telemetry;
END
GO

CREATE DATABASE Sensor_Telemetry
ON PRIMARY (
    NAME = N'SensorTelemetry_Primary',
    FILENAME = N'D:\SQLData\SensorTelemetry_Primary.mdf',
    SIZE = 512MB, FILEGROWTH = 256MB
)
LOG ON (
    NAME = N'SensorTelemetry_Log',
    FILENAME = N'L:\SQLLog\SensorTelemetry_Log.ldf',
    SIZE = 256MB, FILEGROWTH = 128MB
);
GO

ALTER DATABASE Sensor_Telemetry SET RECOVERY SIMPLE;
ALTER DATABASE Sensor_Telemetry SET AUTO_CREATE_STATISTICS ON;
ALTER DATABASE Sensor_Telemetry SET AUTO_UPDATE_STATISTICS ON;
ALTER DATABASE Sensor_Telemetry SET ALLOW_SNAPSHOT_ISOLATION ON;
GO

USE Sensor_Telemetry;
GO

/*──────────────────────────────────────────────────────────────────────────────
 * FILEGROUPS -- one per month, 24 months of rolling retention + overflow
 * Naming: FG_YYYY_MM
 *──────────────────────────────────────────────────────────────────────────────*/

DECLARE @sql NVARCHAR(MAX) = N'';
DECLARE @dt DATE = DATEADD(MONTH, -12, GETDATE());
DECLARE @end DATE = DATEADD(MONTH, 13, GETDATE());

WHILE @dt < @end
BEGIN
    DECLARE @fg NVARCHAR(20) = N'FG_' + FORMAT(@dt, 'yyyy_MM');
    DECLARE @ndf NVARCHAR(260) = N'D:\SQLData\SensorTelemetry_' + FORMAT(@dt, 'yyyy_MM') + N'.ndf';

    SET @sql += N'
    IF NOT EXISTS (SELECT 1 FROM sys.filegroups WHERE name = ''' + @fg + N''')
    BEGIN
        ALTER DATABASE Sensor_Telemetry ADD FILEGROUP [' + @fg + N'];
        ALTER DATABASE Sensor_Telemetry ADD FILE (
            NAME = N''SensorTelemetry_' + FORMAT(@dt, 'yyyy_MM') + N''',
            FILENAME = N''' + @ndf + N''',
            SIZE = 128MB, FILEGROWTH = 128MB
        ) TO FILEGROUP [' + @fg + N'];
    END
    ';
    SET @dt = DATEADD(MONTH, 1, @dt);
END

EXEC sp_executesql @sql;
GO

/*──────────────────────────────────────────────────────────────────────────────
 * PARTITION FUNCTION & SCHEME -- monthly boundaries on DATETIME2(3)
 *──────────────────────────────────────────────────────────────────────────────*/

DECLARE @boundaries NVARCHAR(MAX) = N'';
DECLARE @filegroups NVARCHAR(MAX) = N'';
DECLARE @dt2 DATE = DATEADD(MONTH, -12, DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1));
DECLARE @end2 DATE = DATEADD(MONTH, 13, DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1));
DECLARE @i INT = 0;

WHILE @dt2 < @end2
BEGIN
    IF @i > 0 SET @boundaries += N', ';
    SET @boundaries += N'''' + CONVERT(NVARCHAR(30), @dt2, 126) + N'''';
    SET @filegroups += N'[FG_' + FORMAT(@dt2, 'yyyy_MM') + N'], ';
    SET @dt2 = DATEADD(MONTH, 1, @dt2);
    SET @i += 1;
END

-- Overflow filegroup for anything beyond the range
SET @filegroups += N'[PRIMARY]';

DECLARE @pfSql NVARCHAR(MAX) = N'
CREATE PARTITION FUNCTION pf_MonthlyTelemetry (DATETIME2(3))
AS RANGE RIGHT FOR VALUES (' + @boundaries + N');';

EXEC sp_executesql @pfSql;

DECLARE @psSql NVARCHAR(MAX) = N'
CREATE PARTITION SCHEME ps_MonthlyTelemetry
AS PARTITION pf_MonthlyTelemetry TO (' + @filegroups + N');';

EXEC sp_executesql @psSql;
GO

PRINT 'Database, filegroups, partition function and scheme created.';
GO
