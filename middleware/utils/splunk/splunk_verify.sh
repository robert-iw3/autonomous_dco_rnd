#!/bin/bash
#============================================================================
# Sentinel Nexus -- Splunk Deployment & Verification
#
# 1. Deploy the nexus_telemetry app
# 2. Generate the HEC token
# 3. Send a test event
# 4. Verify index + sourcetype recognition
#
# Usage:
#   export SPLUNK_HOST=https://splunk:8089
#   export SPLUNK_USER=admin
#   export SPLUNK_PASS=changeme
#   export HEC_HOST=https://splunk:8088
#   bash splunk_verify.sh
#============================================================================

SPLUNK_HOST="${SPLUNK_HOST:-https://localhost:8089}"
HEC_HOST="${HEC_HOST:-https://localhost:8088}"
SPLUNK_USER="${SPLUNK_USER:-admin}"
SPLUNK_PASS="${SPLUNK_PASS:-changeme}"

echo "═══════════════════════════════════════════════════════════════"
echo " Sentinel Nexus -- Splunk Verification"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── Deploy the app ──────────────────────────────────
echo "── Step 1: App Deployment ──────────────────────────────"
echo "  Copy the nexus_telemetry/ directory to:"
echo "    Search Head:  \$SPLUNK_HOME/etc/apps/nexus_telemetry/"
echo "    Indexers:     (via cluster master / deployer)"
echo ""
echo "  Then restart Splunk or run:"
echo "    splunk restart"
echo ""

# ─── Enable HEC ─────────────────────────────────────
echo "── Step 2: Enable HEC & Create Token ───────────────────"
echo "  Enabling HTTP Event Collector..."

curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    "${SPLUNK_HOST}/servicesNS/admin/nexus_telemetry/data/inputs/http/http" \
    -d "disabled=0&enableSSL=1&port=8088" 2>/dev/null

echo "  Creating HEC token 'Nexus_Middleware'..."

HEC_TOKEN=$(curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    "${SPLUNK_HOST}/servicesNS/admin/nexus_telemetry/data/inputs/http" \
    -d "name=Nexus_Middleware&index=nexus_endpoint&indexes=nexus_endpoint,nexus_cloud,nexus_network,nexus_alerts&useACK=0" \
    2>/dev/null | grep -oP '(?<=<s:key name="token">)[^<]+')

if [ -n "$HEC_TOKEN" ]; then
    echo "  ✓ HEC Token: ${HEC_TOKEN}"
    echo ""
    echo "  Configure middleware.toml:"
    echo "    [splunk]"
    echo "    hec_url   = \"${HEC_HOST}/services/collector/event\""
    echo "    hec_token = \"${HEC_TOKEN}\""
else
    echo "  Token may already exist. Check Splunk UI → Settings → Data Inputs → HTTP Event Collector"
    HEC_TOKEN="PASTE-YOUR-TOKEN-HERE"
fi

echo ""

# ─── Test Events ────────────────────────────────────
echo "── Step 3: Sending Test Events ─────────────────────────"

# Endpoint test event
curl -sk "${HEC_HOST}/services/collector/event" \
    -H "Authorization: Splunk ${HEC_TOKEN}" \
    -d '{"time":'"$(date +%s)"',"index":"nexus_endpoint","sourcetype":"nexus:c2:linux","event":{"app":"curl","dest":"192.168.1.100","dest_port":443,"severity":"85","action":"Command and Control","vendor_product":"Nexus_C2_Sensor_Linux","dns_query":"evil.example.com"}}' \
    2>/dev/null
echo "  Sent: nexus:c2:linux → nexus_endpoint"

# Cloud test event
curl -sk "${HEC_HOST}/services/collector/event" \
    -H "Authorization: Splunk ${HEC_TOKEN}" \
    -d '{"time":'"$(date +%s)"',"index":"nexus_cloud","sourcetype":"nexus:aws:cloudtrail","event":{"user":"arn:aws:iam::123:user/admin","action":"DeleteTrail","src":"198.51.100.5","severity":"90","vendor_product":"AWS_CloudTrail"}}' \
    2>/dev/null
echo "  Sent: nexus:aws:cloudtrail → nexus_cloud"

# Network test event
curl -sk "${HEC_HOST}/services/collector/event" \
    -H "Authorization: Splunk ${HEC_TOKEN}" \
    -d '{"time":'"$(date +%s)"',"index":"nexus_network","sourcetype":"nexus:nettap:session","event":{"src":"10.0.0.5","dest":"203.0.113.50","dest_port":8443,"transport":"TCP","bytes_out":1048576,"duration":3600000,"ssl_ja3":"e7d705a3286e19ea42f587b344ee6865","cert_self_signed":1,"vendor_product":"Nexus_Network_Tap"}}' \
    2>/dev/null
echo "  Sent: nexus:nettap:session → nexus_network"

echo ""

# ─── Verify ─────────────────────────────────────────
echo "── Step 4: Verification Searches ───────────────────────"
echo ""
echo "  Run in Splunk Search:"
echo ""
echo "    \`nexus_all\` | stats count by sourcetype, index"
echo ""
echo "    \`nexus_high_risk\` | table _time, sourcetype, app, dest, severity"
echo ""
echo "    | datamodel Endpoint search | head 5"
echo ""
echo "    | datamodel Network_Traffic search | head 5"
echo ""
echo "    | datamodel Authentication search | head 5"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Splunk setup complete."
echo "═══════════════════════════════════════════════════════════════"
