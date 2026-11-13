"""
OpenSearch & OpenSearch Dashboards SIEM Setup Script:
1. Configures index templates & mappings in OpenSearch
2. Populates initial realistic SIEM telemetry events & alerts
3. Registers default index patterns in OpenSearch Dashboards
4. Creates a pre-built SIEM Security Overview Dashboard in OpenSearch Dashboards
"""
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
import random

OPENSEARCH_URL = "http://localhost:9200"
DASHBOARDS_URL = "http://localhost:5601"

HEADERS_JSON = {"Content-Type": "application/json"}
HEADERS_OSD = {"Content-Type": "application/json", "osd-xsrf": "true"}

def http_request(url, method="GET", data=None, headers=None):
    req_headers = dict(headers or {})
    payload = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=payload, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"error": body}

def setup_opensearch():
    print("[1/5] Setting up OpenSearch Index Templates...")
    template = {
        "index_patterns": ["securewatch-events-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "event_timestamp": {"type": "date"},
                    "@timestamp": {"type": "date"},
                    "event_id": {"type": "keyword"},
                    "device_id": {"type": "keyword"},
                    "hostname": {"type": "keyword"},
                    "event_source": {"type": "keyword"},
                    "event_category": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "destination_ip": {"type": "ip"},
                    "process_name": {"type": "keyword"},
                    "process_id": {"type": "integer"},
                    "user_id": {"type": "keyword"},
                    "username": {"type": "keyword"},
                    "file_path": {"type": "keyword"},
                    "event_description": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "is_alert_generated": {"type": "boolean"},
                    "raw_data": {"type": "object", "dynamic": True}
                }
            }
        }
    }
    status, res = http_request(f"{OPENSEARCH_URL}/_index_template/securewatch_events_template", method="PUT", data=template, headers=HEADERS_JSON)
    print(f" - Event index template: {status}")

    now = datetime.now(timezone.utc)
    index_name = f"securewatch-events-{now.strftime('%Y.%m')}"

    print(f"[2/5] Ingesting initial SIEM security events into {index_name}...")
    sample_categories = [
        ("authentication", "user_login_success", "informational", "User logged in via interactive console"),
        ("authentication", "user_login_failed", "high", "Failed authentication attempt from external IP"),
        ("process", "process_creation", "low", "Spawned system diagnostic executable"),
        ("process", "suspicious_powershell", "critical", "PowerShell executed with -EncodedCommand parameter"),
        ("network", "outbound_connection", "informational", "Outbound HTTPS connection to telemetry cloud"),
        ("network", "port_scan_detected", "critical", "SYN flood / TCP port sweep detected from internal host"),
        ("fim", "file_modification", "high", "Critical security file modified: C:\\Windows\\System32\\drivers\\etc\\hosts"),
        ("system", "antivirus_status", "informational", "Endpoint defender definitions up to date"),
        ("system", "firewall_disabled", "high", "Host-based firewall disabled by local administrator")
    ]

    hostnames = ["WIN-SOC-ANALYST", "DHANUZZ-LAPTOP", "UBUNTU-PROD-01", "KALI-PENTEST", "SRV-DC-01"]
    users = ["admin", "jsmith", "rwilson", "SYSTEM", "sec_analyst"]
    ips = ["192.168.1.10", "192.168.1.45", "10.0.0.15", "172.16.0.4", "203.0.113.195"]

    bulk_lines = []
    for i in range(120):
        past_minutes = random.randint(1, 1440 * 7) # Over last 7 days
        ts = (now - timedelta(minutes=past_minutes)).isoformat()
        cat, ev_type, sev, desc = random.choice(sample_categories)
        host = random.choice(hostnames)
        user = random.choice(users)
        src_ip = random.choice(ips)
        dst_ip = "192.168.1.1" if src_ip.startswith("192") else "10.0.0.1"

        doc = {
            "event_id": f"evt-{i+1:05d}",
            "event_timestamp": ts,
            "@timestamp": ts,
            "device_id": f"dev-{host.lower()}",
            "hostname": host,
            "event_source": "endpoint_agent",
            "event_category": cat,
            "event_type": ev_type,
            "severity": sev,
            "source_ip": src_ip if "192" in src_ip or "10." in src_ip else "192.168.1.50",
            "destination_ip": dst_ip,
            "process_name": "powershell.exe" if cat == "process" else ("sshd" if "UBUNTU" in host else "lsass.exe"),
            "process_id": random.randint(1000, 60000),
            "username": user,
            "event_description": f"{desc} on host {host}",
            "is_alert_generated": sev in ("high", "critical"),
            "raw_data": {
                "command_line": f"C:\\Windows\\System32\\{cat}.exe -audit",
                "integrity_level": "High",
                "parent_process": "explorer.exe"
            }
        }
        bulk_lines.append(json.dumps({"index": {"_index": index_name, "_id": doc["event_id"]}}))
        bulk_lines.append(json.dumps(doc))

    bulk_payload = "\n".join(bulk_lines) + "\n"
    req = urllib.request.Request(f"{OPENSEARCH_URL}/_bulk", data=bulk_payload.encode("utf-8"), headers={"Content-Type": "application/x-ndjson"}, method="POST")
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode())
        print(f" - Indexed {len(res.get('items', []))} SIEM events into OpenSearch!")

    # Flush & refresh index
    http_request(f"{OPENSEARCH_URL}/{index_name}/_refresh", method="POST")

    print("[3/5] Configuring OpenSearch Dashboards Index Pattern...")
    # Create Index Pattern object in OpenSearch Dashboards
    index_pattern_payload = {
        "attributes": {
            "title": "securewatch-events-*",
            "timeFieldName": "event_timestamp"
        }
    }
    status, res = http_request(
        f"{DASHBOARDS_URL}/api/saved_objects/index-pattern/securewatch-events",
        method="POST",
        data=index_pattern_payload,
        headers=HEADERS_OSD
    )
    print(f" - Index pattern 'securewatch-events-*': status {status}")

    # Set as Default Index Pattern
    default_payload = {
        "value": "securewatch-events"
    }
    status, res = http_request(
        f"{DASHBOARDS_URL}/api/opensearch-dashboards/settings/defaultIndex",
        method="POST",
        data=default_payload,
        headers=HEADERS_OSD
    )
    print(f" - Set default index pattern: status {status}")

    print("[4/5] Creating Pre-built Visualizations in OpenSearch Dashboards...")
    # Visualization 1: Events by Severity Pie
    vis_sev = {
        "attributes": {
            "title": "Events by Severity",
            "visState": json.dumps({
                "title": "Events by Severity",
                "type": "pie",
                "params": {"type": "pie", "addTooltip": True, "addLegend": True, "isDonut": True},
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": "severity", "size": 5}}
                ]
            }),
            "uiStateJSON": "{}",
            "description": "Breakdown of security events by severity tier",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"index": "securewatch-events", "query": {"match_all": {}}, "filter": []})
            }
        }
    }
    status, res = http_request(
        f"{DASHBOARDS_URL}/api/saved_objects/visualization/events-by-severity",
        method="POST",
        data=vis_sev,
        headers=HEADERS_OSD
    )
    print(f" - Visualization 'Events by Severity': status {status}")

    # Visualization 2: Events over time Histogram
    vis_hist = {
        "attributes": {
            "title": "Security Events Over Time",
            "visState": json.dumps({
                "title": "Security Events Over Time",
                "type": "histogram",
                "params": {"type": "histogram", "grid": {"categoryLines": False}, "addTooltip": True, "addLegend": True},
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment", "params": {"field": "event_timestamp", "interval": "auto"}}
                ]
            }),
            "uiStateJSON": "{}",
            "description": "Chronological histogram of SIEM telemetry",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"index": "securewatch-events", "query": {"match_all": {}}, "filter": []})
            }
        }
    }
    status, res = http_request(
        f"{DASHBOARDS_URL}/api/saved_objects/visualization/events-over-time",
        method="POST",
        data=vis_hist,
        headers=HEADERS_OSD
    )
    print(f" - Visualization 'Events Over Time': status {status}")

    print("[5/5] Creating Unified SIEM Security Overview Dashboard...")
    dashboard_payload = {
        "attributes": {
            "title": "SecureWatch SIEM Security Overview",
            "hits": 0,
            "description": "Unified Security Operations Center (SOC) analytical dashboard for OpenSearch Dashboards",
            "panelsJSON": json.dumps([
                {
                    "gridData": {"x": 0, "y": 0, "w": 24, "h": 14, "i": "1"},
                    "version": "2.11.0",
                    "panelIndex": "1",
                    "type": "visualization",
                    "id": "events-over-time"
                },
                {
                    "gridData": {"x": 24, "y": 0, "w": 24, "h": 14, "i": "2"},
                    "version": "2.11.0",
                    "panelIndex": "2",
                    "type": "visualization",
                    "id": "events-by-severity"
                }
            ]),
            "optionsJSON": json.dumps({"darkTheme": False, "useMargins": True}),
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"match_all": {}}, "filter": []})
            }
        }
    }
    status, res = http_request(
        f"{DASHBOARDS_URL}/api/saved_objects/dashboard/siem-overview",
        method="POST",
        data=dashboard_payload,
        headers=HEADERS_OSD
    )
    print(f" - Unified SIEM Dashboard created: status {status}")
    print("\nSUCCESS! OpenSearch Dashboards is fully populated, configured, and ready at http://localhost:5601")

if __name__ == "__main__":
    setup_opensearch()
