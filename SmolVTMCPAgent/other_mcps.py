import requests
from typing import Dict, Any

#  1. URL Reputation MCP (PhishTank, URLhaus) 
def check_url_phishtank(url: str) -> Dict[str, Any]:
    """Check URL reputation using PhishTank (free, no API key required for public feed)."""
    # Download latest verified phishing URLs
    phishtank_feed = "https://data.phishtank.com/data/online-valid.csv"
    try:
        resp = requests.get(phishtank_feed, timeout=10)
        resp.raise_for_status()
        # Check if URL is in the CSV
        return {"phishing": url in resp.text}
    except Exception as e:
        return {"error": f"PhishTank lookup failed: {e}"}

def check_url_urlhaus(url: str) -> Dict[str, Any]:
    """Check URL reputation using URLhaus (free, no API key required for public API)."""
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        resp = requests.post(api_url, data={"url": url}, timeout=10)
        data = resp.json()
        return {"urlhaus": data.get("query_status", "fail") == "ok", "details": data}
    except Exception as e:
        return {"error": f"URLhaus lookup failed: {e}"}

#  2. IP Reputation MCP (AbuseIPDB, free tier) 
def check_ip_abuseipdb(ip: str, api_key=None) -> Dict[str, Any]:
    """Check IP reputation using AbuseIPDB (free API key required)."""
    if not api_key:
        return {"error": "AbuseIPDB API key required"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        data = resp.json()
        return {"abuseConfidenceScore": data.get("data", {}).get("abuseConfidenceScore", 0), "details": data}
    except Exception as e:
        return {"error": f"AbuseIPDB lookup failed: {e}"}

#  3. Passive DNS MCP (SecurityTrails, free tier) 
def passive_dns_securitytrails(domain: str, api_key=None) -> Dict[str, Any]:
    """Query passive DNS records using SecurityTrails (free API key required)."""
    if not api_key:
        return {"error": "SecurityTrails API key required"}
    url = f"https://api.securitytrails.com/v1/domain/{domain}/dns"
    headers = {"APIKEY": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        return {"dns_records": data}
    except Exception as e:
        return {"error": f"SecurityTrails lookup failed: {e}"}

#  4. WHOIS Lookup MCP (whoisxmlapi, free tier) 
def whois_lookup(domain: str, api_key=None) -> Dict[str, Any]:
    """Get WHOIS info using whoisxmlapi (free API key required)."""
    if not api_key:
        return {"error": "whoisxmlapi API key required"}
    url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    params = {"apiKey": api_key, "domainName": domain, "outputFormat": "JSON"}
    try:
        resp = requests.get(url, params=params, timeout=10)
        data = resp.json()
        return {"whois": data}
    except Exception as e:
        return {"error": f"WhoisXML lookup failed: {e}"}

#  5. Geolocation MCP (ip-api.com, free, no key needed) 
def ip_geolocation(ip: str) -> Dict[str, Any]:
    """Get geolocation info for an IP using ip-api.com (no API key required)."""
    url = f"http://ip-api.com/json/{ip}"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        return {"geolocation": data}
    except Exception as e:
        return {"error": f"ip-api.com lookup failed: {e}"}

#  6. YARA Scan MCP (local, requires yara-python) 
def yara_scan(data: bytes, yara_rule: str) -> dict:
    """
    Validate YARA rule syntax and scan data with it.
    Returns {'syntax_error': ...} if invalid, or {'matches': [...]} if valid.
    """
    try:
        import yara
    except ImportError:
        return {"error": "yara-python is not installed. Please install with 'pip install yara-python'"}
    # Validate syntax
    try:
        rules = yara.compile(source=yara_rule)
    except yara.SyntaxError as e:
        return {"syntax_error": str(e)}
    except Exception as e:
        return {"error": f"Failed to compile YARA rule: {e}"}
    # Scan
    try:
        matches = rules.match(data=data)
        return {"matches": [m.rule for m in matches]}
    except Exception as e:
        return {"error": f"YARA scan failed: {e}"}

#  7. Threat Intelligence Aggregation (MISP, OpenCTI) 
# Skipped: free but require local instance setup, not public API.

#  8. File Sandbox/Detonation (Hybrid Analysis public API) 
def hybrid_analysis_file_report(sha256: str, api_key=None) -> Dict[str, Any]:
    """Query Hybrid Analysis for a file hash (free API key with registration)."""
    if not api_key:
        return {"error": "Hybrid Analysis API key required"}
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {"api-key": api_key, "User-Agent": "Falcon Sandbox"}
    params = {"hash": sha256}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        data = resp.json()
        return {"hybrid_analysis": data}
    except Exception as e:
        return {"error": f"Hybrid Analysis lookup failed: {e}"}
