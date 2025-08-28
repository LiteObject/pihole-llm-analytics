#!/usr/bin/env python3
"""
Test script to verify Pi-hole authentication and basic functionality.
"""

from pihole_analytics.utils.logging import setup_logging
from pihole_analytics.utils.config import PiholeConfig
from pihole_analytics.core.pihole_client import PiholeClient
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def test_pihole_connection():
    """Test Pi-hole connection and authentication."""

    # Setup logging
    setup_logging(verbose=True)

    # Create configuration
    config = PiholeConfig(
        host="192.168.7.99",
        password="xPKcAqgV",
        timeout=10
    )

    print(f"Testing Pi-hole connection to {config.host}")
    print("=" * 50)

    try:
        # Create client and test authentication
        client = PiholeClient(config)

        print("1. Testing Pi-hole version...")
        try:
            version_info = client.get_version()
            print(
                f"   ✓ Pi-hole version: {version_info.get('version', 'unknown')}")
        except (KeyError, ValueError) as e:
            print(f"   ⚠ Could not get version: {e}")

        print("\n2. Testing Pi-hole authentication...")

        # Print curl command for authentication
        auth_url = f"http://{config.host}:{config.port}/api/auth"
        auth_payload = {"password": config.password}
        auth_headers = {"Content-Type": "application/json"}
        print_curl_command(
            "POST", auth_url, headers=auth_headers, data=auth_payload)

        session_id = client.authenticate()
        print(
            f"   ✓ Authentication successful - Session ID: {session_id[:8]}...")

        print("\n3. Testing basic Pi-hole data retrieval...")

        # Test summary data
        try:
            summary = client.get_summary()
            if summary:
                print("   ✓ Summary data retrieved:")
                print(f"     - Data keys: {list(summary.keys())}")
                # Check for common summary fields
                if 'queries_total' in summary:
                    print(f"     - Total queries: {summary['queries_total']}")
                if 'ads_blocked_today' in summary:
                    print(
                        f"     - Blocked today: {summary['ads_blocked_today']}")

                # Display actual data that was retrieved
                for key, value in summary.items():
                    if key in ['status', 'queries_all_types', 'blocked_queries']:
                        print(f"     - {key}: {value}")
                    elif key == 'note':
                        # Truncate long notes
                        print(f"     - {key}: {value[:100]}...")
            else:
                print("   ⚠ Summary data is empty")
        except Exception as e:
            print(f"   ✗ Summary retrieval failed: {e}")

        # Test query data
        try:
            queries = client.fetch_queries(count=5)
            if queries:
                print(f"   ✓ Query data retrieved: {len(queries)} queries")
                if queries:
                    print(f"     - Latest query: {queries[0].domain}")
            else:
                print(
                    "   ⚠ No query data retrieved (this may be expected for Pi-hole v6+)")
        except Exception as e:
            print(f"   ✗ Query retrieval failed: {e}")

        # Test top domains
        try:
            top_domains = client.get_top_domains(count=3)
            if top_domains:
                print(
                    f"   ✓ Top domains retrieved: {len(top_domains)} entries")
            else:
                print("   ⚠ No top domains data")
        except Exception as e:
            print(f"   ✗ Top domains retrieval failed: {e}")

        # Test alternative Pi-hole v6+ endpoints
        print("\n4. Testing Pi-hole v6+ alternative endpoints...")
        test_v6_endpoints(client)

        print("\n" + "=" * 50)
        print("✓ Pi-hole connection test completed successfully!")
        return True

    except Exception as e:
        print(f"\n✗ Pi-hole connection test failed: {e}")
        return False


def print_curl_command(method, url, headers=None, data=None):
    """Print the equivalent curl command for the HTTP request."""
    curl_cmd = f"curl -X {method}"

    # Add headers
    if headers:
        for key, value in headers.items():
            if value:  # Only add non-empty headers
                curl_cmd += f" -H '{key}: {value}'"

    # Add data for POST requests
    if data:
        if isinstance(data, dict):
            import json
            curl_cmd += f" -d '{json.dumps(data)}'"
        else:
            curl_cmd += f" -d '{data}'"

    # Add URL
    curl_cmd += f" '{url}'"

    print(f"   🌐 Curl command: {curl_cmd}")
    return curl_cmd


def test_v6_endpoints(client):
    """Test alternative endpoints that might work with Pi-hole v6+."""
    import requests

    session_id = client._session_id
    base_url = f"http://{client.config.host}:{client.config.port if hasattr(client.config, 'port') else 8080}"

    # Complete Pi-hole v6 API endpoints from official FTL specification
    test_endpoints = [
        # Authentication & Core Info
        "/auth",
        "/auth/sessions",
        "/endpoints",  # Lists all available endpoints

        # Information endpoints
        "/info/client",
        "/info/host",
        "/info/ftl",
        "/info/database",
        "/info/system",
        "/info/version",
        "/info/messages",
        "/info/metrics",

        # Statistics endpoints
        "/stats/summary",
        "/stats/database/summary",
        "/stats/upstreams",
        "/stats/database/upstreams",
        "/stats/top_domains",
        "/stats/database/top_domains",
        "/stats/top_clients",
        "/stats/database/top_clients",
        "/stats/query_types",
        "/stats/database/query_types",
        "/stats/recent_blocked",

        # History & Query endpoints
        "/history",
        "/history/clients",
        "/history/database",
        "/history/database/clients",
        "/queries",
        "/queries/suggestions",

        # DNS Control
        "/dns/blocking",

        # Network information
        "/network/devices",
        "/network/gateway",
        "/network/interfaces",
        "/network/routes",

        # DHCP endpoints
        "/dhcp/leases",

        # Configuration endpoints
        "/config",

        # Logs endpoints
        "/logs/dnsmasq",
        "/logs/ftl",
        "/logs/webserver",

        # Action endpoints
        "/action/gravity",
        "/action/restartdns",
        "/action/flush/logs",
        "/action/flush/arp",

        # Utility endpoints
        "/teleporter",
        "/docs",
        "/padd",

        # Legacy v5 endpoints for comparison
        "/admin/api.php?summary",
        "/admin/api.php?version",
    ]

    # Headers for authenticated requests
    headers = {
        "X-FTL-SID": session_id,
        "X-FTL-CSRF": getattr(client, '_csrf_token', ''),  # If available
    }

    working_endpoints = []

    for endpoint in test_endpoints:
        try:
            # Construct proper API URLs: base_url/api + endpoint
            if endpoint.startswith('/admin/'):
                # Legacy v5 endpoints use the old format
                url = f"{base_url}{endpoint}"
                test_url = f"{url}&auth={client.config.password}"
                print_curl_command("GET", test_url)
                response = client._session.get(test_url, timeout=5)
            else:
                # v6 endpoints use /api prefix
                url = f"{base_url}/api{endpoint}"
                print_curl_command("GET", url, headers=headers)
                response = client._session.get(url, headers=headers, timeout=5)

            if response.status_code == 200:
                try:
                    data = response.json() if response.headers.get(
                        'content-type', '').startswith('application/json') else response.text
                    working_endpoints.append(endpoint)

                    if isinstance(data, dict):
                        print(
                            f"   ✓ {endpoint}: Success - Keys: {list(data.keys())[:5]}{'...' if len(data.keys()) > 5 else ''}")

                        # Show interesting data for key endpoints
                        if endpoint == "/endpoints" and "endpoints" in data:
                            endpoints_list = data["endpoints"]
                            print(
                                f"      - Available endpoints: {len(endpoints_list)} total")
                            print(
                                f"      - Sample endpoints: {endpoints_list[:3] if endpoints_list else 'none'}")
                        elif endpoint == "/stats/summary" and isinstance(data, dict):
                            # Check for v6 structure
                            if 'queries' in data:
                                queries = data['queries']
                                print(
                                    f"      - Total queries: {queries.get('total', 'N/A')}")
                                print(
                                    f"      - Blocked queries: {queries.get('blocked', 'N/A')}")
                            # Check for older structure
                            summary_keys = [
                                'queries_all_types', 'ads_blocked_today', 'dns_queries_today', 'clients_ever_seen']
                            for key in summary_keys:
                                if key in data:
                                    print(f"      - {key}: {data[key]}")
                        elif endpoint == "/info/host" and isinstance(data, dict):
                            host_data = data.get('host', data)
                            host_keys = ['version',
                                         'hostname', 'uptime', 'kernel']
                            for key in host_keys:
                                if key in host_data:
                                    print(f"      - {key}: {host_data[key]}")
                        elif endpoint == "/info/version" and isinstance(data, dict):
                            version_keys = ['version', 'hash', 'branch', 'tag']
                            for key in version_keys:
                                if key in data:
                                    print(f"      - {key}: {data[key]}")
                        elif endpoint == "/network/devices" and "devices" in data:
                            devices = data["devices"]
                            print(
                                f"      - Network devices found: {len(devices)}")
                            if devices:
                                print(
                                    f"      - Sample device: {devices[0].get('name', 'Unknown')} ({devices[0].get('ip', 'No IP')})")
                        elif endpoint == "/dhcp/leases" and "leases" in data:
                            leases = data["leases"]
                            print(f"      - DHCP leases: {len(leases)}")
                        elif endpoint in ["/stats/top_domains", "/stats/top_clients"] and isinstance(data, dict):
                            for key in ['domains', 'clients', 'total_queries', 'blocked_queries']:
                                if key in data:
                                    if isinstance(data[key], list):
                                        print(
                                            f"      - {key}: {len(data[key])} entries")
                                    else:
                                        print(f"      - {key}: {data[key]}")
                        elif endpoint == "/queries" and isinstance(data, dict):
                            query_keys = ['queries',
                                          'recordsTotal', 'recordsFiltered']
                            for key in query_keys:
                                if key in data:
                                    if isinstance(data[key], list):
                                        print(
                                            f"      - {key}: {len(data[key])} entries")
                                    else:
                                        print(f"      - {key}: {data[key]}")
                    else:
                        print(
                            f"   ✓ {endpoint}: Success - Data: {str(data)[:80]}{'...' if len(str(data)) > 80 else ''}")
                except Exception as e:
                    print(
                        f"   ✓ {endpoint}: Success (but failed to parse: {str(e)[:40]})")
                    working_endpoints.append(endpoint)
            else:
                print(f"   ✗ {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"   ✗ {endpoint}: Error - {str(e)[:50]}")

    print(
        f"\n   📊 Summary: {len(working_endpoints)} endpoints working out of {len(test_endpoints)} tested")

    if working_endpoints:
        # Categorize working endpoints
        categories = {
            "Authentication": [ep for ep in working_endpoints if ep.startswith("/auth")],
            "Information": [ep for ep in working_endpoints if ep.startswith("/info")],
            "Statistics": [ep for ep in working_endpoints if ep.startswith("/stats")],
            "History/Queries": [ep for ep in working_endpoints if ep.startswith(("/history", "/queries"))],
            "Network": [ep for ep in working_endpoints if ep.startswith("/network")],
            "DNS/DHCP": [ep for ep in working_endpoints if ep.startswith(("/dns", "/dhcp"))],
            "Configuration": [ep for ep in working_endpoints if ep.startswith(("/config", "/endpoints"))],
            "Logs": [ep for ep in working_endpoints if ep.startswith("/logs")],
            "Actions": [ep for ep in working_endpoints if ep.startswith("/action")],
            "Utilities": [ep for ep in working_endpoints if ep.startswith(("/teleporter", "/docs", "/padd"))],
            "Legacy": [ep for ep in working_endpoints if ep.startswith("/admin")]
        }

        print("   ✅ Working endpoints by category:")
        for category, endpoints in categories.items():
            if endpoints:
                print(
                    f"      {category}: {len(endpoints)} endpoints - {', '.join(endpoints[:3])}{'...' if len(endpoints) > 3 else ''}")

    # Show failed endpoints for debugging
    failed_endpoints = [
        ep for ep in test_endpoints if ep not in working_endpoints]
    if failed_endpoints:
        print(f"\n   ❌ Failed endpoints ({len(failed_endpoints)}):")
        failed_categories = {
            "Information": [ep for ep in failed_endpoints if ep.startswith("/info")],
            "Statistics": [ep for ep in failed_endpoints if ep.startswith("/stats")],
            "Configuration": [ep for ep in failed_endpoints if ep.startswith("/config")],
            "Logs": [ep for ep in failed_endpoints if ep.startswith("/logs")],
            "Actions": [ep for ep in failed_endpoints if ep.startswith("/action")],
            "Legacy": [ep for ep in failed_endpoints if ep.startswith("/admin")],
            "Other": [ep for ep in failed_endpoints if not any(ep.startswith(prefix) for prefix in ["/info", "/stats", "/config", "/logs", "/action", "/admin"])]
        }

        for category, endpoints in failed_categories.items():
            if endpoints:
                print(
                    f"      {category}: {', '.join(endpoints[:5])}{'...' if len(endpoints) > 5 else ''}")


if __name__ == "__main__":
    success = test_pihole_connection()
    sys.exit(0 if success else 1)
