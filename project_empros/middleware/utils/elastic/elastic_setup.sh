#!/bin/bash
#============================================================================
# Sentinel Nexus -- Elastic Stack Setup
#
# Creates ILM policies, component templates, index templates, and
# data streams for all sensor telemetry routed by the middleware.
#
# Usage:
#   export ES_HOST=https://elastic:9200
#   export ES_AUTH="elastic:changeme"    # or API key
#   bash elastic_setup.sh
#
# Requires: curl, jq (for verification only)
#============================================================================

ES_HOST="${ES_HOST:-https://localhost:9200}"
ES_AUTH="${ES_AUTH:-}"
CURL_OPTS="-sk"

if [ -n "$ES_AUTH" ]; then
    if [[ "$ES_AUTH" == *":"* ]]; then
        CURL_OPTS="$CURL_OPTS -u $ES_AUTH"
    else
        CURL_OPTS="$CURL_OPTS -H 'Authorization: ApiKey $ES_AUTH'"
    fi
fi

put() {
    local path="$1"
    local body="$2"
    echo "PUT $path"
    eval curl $CURL_OPTS -X PUT "${ES_HOST}${path}" \
        -H 'Content-Type: application/json' \
        -d "'${body}'" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('  ✓' if d.get('acknowledged') else '  ' + json.dumps(d))" 2>/dev/null || echo "  (sent)"
}


echo "═══════════════════════════════════════════════════════════════"
echo " Sentinel Nexus -- Elastic Stack Setup"
echo " Target: $ES_HOST"
echo "═══════════════════════════════════════════════════════════════"
echo ""


# ─────────────────────────────────────────────────────────────
# ILM POLICIES -- tiered retention per data category
# ─────────────────────────────────────────────────────────────

echo "── ILM Policies ──────────────────────────────────────────"

put "/_ilm/policy/nexus-endpoint-policy" '{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": { "max_primary_shard_size": "50gb", "max_age": "7d" },
          "set_priority": { "priority": 100 }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": { "number_of_shards": 1 },
          "forcemerge": { "max_num_segments": 1 },
          "set_priority": { "priority": 50 }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "set_priority": { "priority": 0 },
          "readonly": {}
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": { "delete": {} }
      }
    }
  }
}'

put "/_ilm/policy/nexus-cloud-policy" '{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": { "max_primary_shard_size": "50gb", "max_age": "7d" },
          "set_priority": { "priority": 100 }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": { "number_of_shards": 1 },
          "forcemerge": { "max_num_segments": 1 },
          "set_priority": { "priority": 50 }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": { "readonly": {} }
      },
      "delete": {
        "min_age": "90d",
        "actions": { "delete": {} }
      }
    }
  }
}'

put "/_ilm/policy/nexus-network-policy" '{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": { "max_primary_shard_size": "50gb", "max_age": "3d" },
          "set_priority": { "priority": 100 }
        }
      },
      "warm": {
        "min_age": "3d",
        "actions": {
          "shrink": { "number_of_shards": 1 },
          "forcemerge": { "max_num_segments": 1 },
          "set_priority": { "priority": 50 }
        }
      },
      "cold": {
        "min_age": "14d",
        "actions": { "readonly": {} }
      },
      "delete": {
        "min_age": "60d",
        "actions": { "delete": {} }
      }
    }
  }
}'


# ─────────────────────────────────────────────────────────────
# COMPONENT TEMPLATES -- reusable field groups
# ─────────────────────────────────────────────────────────────

echo ""
echo "── Component Templates ─────────────────────────────────"

# Base ECS fields shared across all sensor types
put "/_component_template/nexus-ecs-base" '{
  "template": {
    "settings": {
      "number_of_shards": 2,
      "number_of_replicas": 1,
      "codec": "best_compression"
    },
    "mappings": {
      "dynamic": "runtime",
      "properties": {
        "@timestamp":         { "type": "date" },
        "ecs":                { "properties": { "version": { "type": "keyword" } } },
        "event": {
          "properties": {
            "category":       { "type": "keyword" },
            "dataset":        { "type": "keyword" },
            "action":         { "type": "keyword" },
            "severity":       { "type": "keyword" },
            "risk_score":     { "type": "float" },
            "duration":       { "type": "long" },
            "reason":         { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 512 } } }
          }
        },
        "sensor_type":        { "type": "keyword" },
        "message":            { "type": "text" }
      }
    }
  }
}'

# Endpoint process fields
put "/_component_template/nexus-endpoint-fields" '{
  "template": {
    "mappings": {
      "properties": {
        "process": {
          "properties": {
            "name":           { "type": "keyword" },
            "executable":     { "type": "keyword" },
            "command_line":   { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 2048 } } },
            "pid":            { "type": "integer" },
            "parent": {
              "properties": {
                "executable": { "type": "keyword" },
                "pid":        { "type": "integer" }
              }
            },
            "hash": {
              "properties": {
                "sha256":     { "type": "keyword" }
              }
            }
          }
        },
        "user":               { "properties": { "name": { "type": "keyword" }, "id": { "type": "keyword" } } },
        "destination":        { "properties": { "ip": { "type": "ip" }, "port": { "type": "integer" }, "address": { "type": "keyword" } } },
        "source":             { "properties": { "ip": { "type": "ip" } } },
        "host":               { "properties": { "ip": { "type": "ip" }, "name": { "type": "keyword" } } },
        "dns":                { "properties": { "question": { "properties": { "name": { "type": "keyword" } } } } },
        "threat": {
          "properties": {
            "tactic":         { "properties": { "name": { "type": "keyword" } } },
            "technique":      { "properties": { "id": { "type": "keyword" } } }
          }
        },
        "rule":               { "properties": { "name": { "type": "keyword" } } }
      }
    }
  }
}'

# Network session fields (Arkime)
put "/_component_template/nexus-network-fields" '{
  "template": {
    "mappings": {
      "properties": {
        "source": {
          "properties": {
            "ip":             { "type": "ip" },
            "port":           { "type": "integer" },
            "bytes":          { "type": "long" },
            "packets":        { "type": "integer" },
            "geo":            { "properties": { "country_name": { "type": "keyword" } } }
          }
        },
        "destination": {
          "properties": {
            "ip":             { "type": "ip" },
            "port":           { "type": "integer" },
            "bytes":          { "type": "long" },
            "packets":        { "type": "integer" },
            "geo":            { "properties": { "country_name": { "type": "keyword" } } },
            "as":             { "properties": { "organization": { "properties": { "name": { "type": "keyword" } } } } }
          }
        },
        "network": {
          "properties": {
            "protocol":       { "type": "keyword" },
            "bytes":          { "type": "long" },
            "packets":        { "type": "long" }
          }
        },
        "tls": {
          "properties": {
            "client":         { "properties": { "ja3": { "type": "keyword" } } },
            "server":         { "properties": {
              "ja3s":         { "type": "keyword" },
              "x509":         { "properties": {
                "subject":    { "properties": { "common_name": { "type": "keyword" } } },
                "issuer":     { "properties": { "common_name": { "type": "keyword" } } }
              }}
            }},
            "version":        { "type": "keyword" },
            "cipher":         { "type": "keyword" }
          }
        },
        "http": {
          "properties": {
            "request":        { "properties": { "method": { "type": "keyword" } } },
            "response":       { "properties": { "status_code": { "type": "integer" } } }
          }
        },
        "url":                { "properties": { "original": { "type": "keyword" } } },
        "user_agent":         { "properties": { "original": { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 512 } } } } }
      }
    }
  }
}'


# ─────────────────────────────────────────────────────────────
# INDEX TEMPLATES -- compose component templates + ILM
# ─────────────────────────────────────────────────────────────

echo ""
echo "── Index Templates ─────────────────────────────────────"

put "/_index_template/nexus-endpoint" '{
  "index_patterns": ["nexus-endpoint*"],
  "data_stream": {},
  "composed_of": ["nexus-ecs-base", "nexus-endpoint-fields"],
  "priority": 200,
  "template": {
    "settings": {
      "index.lifecycle.name": "nexus-endpoint-policy"
    }
  },
  "_meta": { "description": "Linux C2, Windows DeepSensor, Windows C2 sensor telemetry" }
}'

put "/_index_template/nexus-cloud" '{
  "index_patterns": ["nexus-cloud*"],
  "data_stream": {},
  "composed_of": ["nexus-ecs-base", "nexus-endpoint-fields"],
  "priority": 200,
  "template": {
    "settings": {
      "index.lifecycle.name": "nexus-cloud-policy"
    }
  },
  "_meta": { "description": "AWS + Azure cloud connector telemetry" }
}'

put "/_index_template/nexus-network" '{
  "index_patterns": ["nexus-network*"],
  "data_stream": {},
  "composed_of": ["nexus-ecs-base", "nexus-network-fields"],
  "priority": 200,
  "template": {
    "settings": {
      "index.lifecycle.name": "nexus-network-policy"
    }
  },
  "_meta": { "description": "Arkime network tap session telemetry" }
}'

# Catch-all for the default nexus-telemetry index
put "/_index_template/nexus-telemetry" '{
  "index_patterns": ["nexus-telemetry*"],
  "data_stream": {},
  "composed_of": ["nexus-ecs-base", "nexus-endpoint-fields", "nexus-network-fields"],
  "priority": 100,
  "template": {
    "settings": {
      "index.lifecycle.name": "nexus-endpoint-policy"
    }
  },
  "_meta": { "description": "Default catch-all for all Nexus sensor telemetry" }
}'


# ─────────────────────────────────────────────────────────────
# INGEST PIPELINES -- enrich + normalize on arrival
# ─────────────────────────────────────────────────────────────

echo ""
echo "── Ingest Pipelines ────────────────────────────────────"

put "/_ingest/pipeline/nexus-telemetry-pipeline" '{
  "description": "Normalize and enrich Nexus sensor telemetry on ingest",
  "processors": [
    {
      "date": {
        "field": "@timestamp",
        "target_field": "@timestamp",
        "formats": ["UNIX", "UNIX_MS", "ISO8601", "yyyy-MM-dd HH:mm:ss"],
        "ignore_failure": true
      }
    },
    {
      "set": {
        "field": "ecs.version",
        "value": "8.0.0",
        "override": false
      }
    },
    {
      "geoip": {
        "field": "source.ip",
        "target_field": "source.geo",
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "destination.ip",
        "target_field": "destination.geo",
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "user_agent": {
        "field": "user_agent.original",
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "script": {
        "description": "Route to correct data stream by sensor_type",
        "source": "if (ctx.sensor_type != null) { if (['linux-c2-sensor','windows_deepsensor','c2sensor'].contains(ctx.sensor_type)) { ctx._index = 'nexus-endpoint'; } else if (ctx.sensor_type == 'network_tap') { ctx._index = 'nexus-network'; } else if (ctx.sensor_type.contains('connector')) { ctx._index = 'nexus-cloud'; } }",
        "ignore_failure": true
      }
    }
  ]
}'


# ─────────────────────────────────────────────────────────────
# CREATE DATA STREAMS (bootstrap)
# ─────────────────────────────────────────────────────────────

echo ""
echo "── Data Streams (bootstrap) ────────────────────────────"

for ds in nexus-endpoint nexus-cloud nexus-network nexus-telemetry; do
    echo "PUT /_data_stream/$ds"
    eval curl $CURL_OPTS -X PUT "${ES_HOST}/_data_stream/${ds}" \
        -H 'Content-Type: application/json' 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('  ✓' if d.get('acknowledged') else '  ' + json.dumps(d))" 2>/dev/null || echo "  (sent)"
done


# ─────────────────────────────────────────────────────────────
# VERIFY
# ─────────────────────────────────────────────────────────────

echo ""
echo "── Verification ────────────────────────────────────────"

echo "ILM policies:"
eval curl $CURL_OPTS -s "${ES_HOST}/_ilm/policy/nexus-*" | python3 -c "import sys,json; [print(f'  {k}') for k in json.load(sys.stdin).keys()]" 2>/dev/null

echo "Index templates:"
eval curl $CURL_OPTS -s "${ES_HOST}/_index_template/nexus-*" | python3 -c "import sys,json; [print(f'  {t[\"name\"]}') for t in json.load(sys.stdin).get('index_templates',[])]" 2>/dev/null

echo "Data streams:"
eval curl $CURL_OPTS -s "${ES_HOST}/_data_stream/nexus-*" | python3 -c "import sys,json; [print(f'  {d[\"name\"]}') for d in json.load(sys.stdin).get('data_streams',[])]" 2>/dev/null

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Setup complete. Configure middleware worker_elastic with:"
echo "   elastic.host  = \"$ES_HOST\""
echo "   elastic.index = \"nexus-telemetry\""
echo "   (pipeline routing auto-selects the correct data stream)"
echo "═══════════════════════════════════════════════════════════════"
