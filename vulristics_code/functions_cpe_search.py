import requests
import time

# =====================
#  Validation helpers
# =====================

def validate_cpe(cpe_string: str) -> str | None:
    """Validate and normalize CPE string"""
    cpe_string = cpe_string.strip()
    
    if not cpe_string.startswith('cpe:'):
        print(f"Warning: CPE '{cpe_string}' doesn't start with 'cpe:' prefix. Adding automatically.")
        if cpe_string.startswith('/'):
            cpe_string = 'cpe:' + cpe_string
        else:
            cpe_string = 'cpe:/' + cpe_string
    
    parts = cpe_string.split(':')
    if len(parts) < 4:
        print(f"Warning: CPE '{cpe_string}' seems malformed. Expected format: cpe:/part:vendor:product[:version]")
        return None
    
    return cpe_string


# =====================
#  Source: NVD
# =====================

def search_cves_nvd(cpe_string: str, max_results: int = 1000) -> set[str]:
    """Search CVEs by CPE using NVD API v2"""
    print(f"[NVD] Searching CVEs for CPE: {cpe_string}")
    
    cves = set()
    start_index = 0
    results_per_page = 100  # API max
    
    while start_index < max_results:
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "cpeName": cpe_string,
                "startIndex": start_index,
                "resultsPerPage": min(results_per_page, max_results - start_index)
            }
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break
                for vuln in vulnerabilities:
                    cve_id = vuln.get("cve", {}).get("id")
                    if cve_id:
                        cves.add(cve_id)
                total_results = data.get("totalResults", 0)
                if start_index + len(vulnerabilities) >= total_results:
                    break
                start_index += results_per_page
                time.sleep(6)  # rate limit
            elif response.status_code == 404:
                break
            else:
                print(f"[NVD] Error {response.status_code}: {response.text}")
                break
        except Exception as e:
            print(f"[NVD] Request error: {e}")
            break
    return cves


# =====================
#  Source: Vulners
# =====================

def search_cves_vulners(cpe_string: str, api_key: str | None = None) -> set[str]:
    """Search CVEs by CPE using Vulners API"""
    print(f"[Vulners] Searching CVEs for CPE: {cpe_string}")
    cves = set()
    try:
        url = "https://vulners.com/api/v3/search/lucene/"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"APIKEY {api_key}"
        payload = {
            "query": f"cpe:{cpe_string}",
            "size": 100
        }
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            for doc in data.get("data", {}).get("search", []):
                cve_id = doc.get("id")
                if cve_id and cve_id.startswith("CVE-"):
                    cves.add(cve_id)
        else:
            print(f"[Vulners] Error {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[Vulners] Request error: {e}")
    return cves


# =====================
#  Source: OSV (Google)
# =====================

def search_cves_osv(cpe_string: str) -> set[str]:
    """Search CVEs by CPE using OSV API"""
    print(f"[OSV] Searching CVEs for CPE: {cpe_string}")
    cves = set()
    try:
        url = "https://api.osv.dev/v1/query"
        payload = {"query": cpe_string}
        resp = requests.post(url, json=payload, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulns", [])
            for vuln in vulns:
                for alias in vuln.get("aliases", []):
                    if alias.startswith("CVE-"):
                        cves.add(alias)
        else:
            print(f"[OSV] Error {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[OSV] Request error: {e}")
    return cves


# =====================
#  Aggregator
# =====================

def search_cves_by_cpe(cpe_string: str, max_results: int = 1000, vulners_api_key: str | None = None) -> list[str]:
    """Aggregate CVE search across multiple sources"""
    all_cves = set()
    all_cves.update(search_cves_nvd(cpe_string, max_results=max_results))
    all_cves.update(search_cves_vulners(cpe_string, api_key=vulners_api_key))
    all_cves.update(search_cves_osv(cpe_string))
    return sorted(all_cves)
