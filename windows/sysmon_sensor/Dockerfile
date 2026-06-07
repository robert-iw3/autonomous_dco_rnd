# Nexus Sysmon Sensor -- Windows container image
# Requires Windows Server Core base with Sysmon pre-installed on the host.
# The sensor reads the Sysmon event log via Windows Event Log APIs (pywin32)
# and ships Parquet to the middleware ingress.
#
# NOTE: This container must run on a Windows host with:
#   1. Sysmon installed: sysmon64.exe -accepteula -i sysmon_config.xml
#   2. Event log access: container requires SYSTEM or SeSecurityPrivilege
#   3. Middleware reachable at NEXUS_MIDDLEWARE_URL

FROM mcr.microsoft.com/windows/servercore:ltsc2022

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop';"]

ADD https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe C:/python-installer.exe
RUN Start-Process -Wait -FilePath C:/python-installer.exe \
    -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1 Include_test=0'; \
    Remove-Item C:/python-installer.exe

WORKDIR C:/NexusSysmonSensor
COPY requirements.txt .
COPY schema.py .
COPY parquet_shipper.py .
COPY SysmonSensor.py .
COPY DeepXDR_Sysmon.ini .

RUN pip install --no-cache-dir -r requirements.txt

ENV NEXUS_MIDDLEWARE_URL=https://middleware.internal:8443/api/v1/telemetry
ENV NEXUS_AUTH_TOKEN=ChangeMe-Rotate-In-Production
ENV NEXUS_INTEGRITY_SECRET=Nexus-Integrity-SharedKey-Rotate-Me
ENV NEXUS_TLS_VERIFY=true
ENV NEXUS_MAX_BATCH_ROWS=500
ENV NEXUS_FLUSH_INTERVAL_S=30
ENV NEXUS_POLL_MS=500
ENV NEXUS_LOG_DIR=C:\ProgramData\NexusSysmonSensor\logs
ENV NEXUS_BOOKMARK_PATH=C:\ProgramData\NexusSysmonSensor\bookmark.xml

VOLUME ["C:/ProgramData/NexusSysmonSensor"]
ENTRYPOINT ["python", "SysmonSensor.py", "--config", "DeepXDR_Sysmon.ini"]