'''
 # @ Create Time: 2025-06-26 10:06:57
 # @ Modified time: 2025-06-26 10:06:59
 # @ Description: the cve api for querying CVE information
 '''
import requests
from mitrecve import crawler
from pprint import pprint
import json, os, time, threading
from typing import Optional, Dict, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pathlib import Path

def nvd_cve_api(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve CVE info. Status code: {response.status_code}")
        return None

def nvd_cwe_api(cwe_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cweId={cwe_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve CVE info. Status code: {response.status_code}")
        return None

def mitre_cve_api(package):
    cve_simple = crawler.get_main_page(package) 
    pprint(crawler.get_cve_detail(cve_simple))


class OSVClient:
    def __init__(self, ttl_seconds: int = 24*3600):
        self.ttl = ttl_seconds
        # cve_id -> {'ts': float, 'data': Any}
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._neg_cache_ttl = 5 * 60 
        self._lock = threading.Lock()
        self.session = requests.Session()
        retry = Retry(
            total=5,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods= ["GET"],
            raise_on_status=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
    
    def get(self, cve_id: str) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self._lock:
            hit = self._cache.get(cve_id)
            if hit:
                age = now - hit["ts"]
                # if we cached a miss, respect a short negative TTL
                if hit["data"] is None and age < self._neg_cache_ttl:
                    return None
                if hit["data"] is not None and age < self.ttl:
                    return hit["data"]
        
        url = f"https://api.osv.dev/v1/vulns/{cve_id}"
        try:
            resp = self.session.get(url, timeout=10)
        except requests.RequestException:
            data = None
        else:
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except (ValueError, json.JSONDecodeError):
                    data = None
            else:
                data = None 

        with self._lock:
            self._cache[cve_id] = {"ts": now, "data": data}
        return data


class PersistentOSVClient(OSVClient):
    def __init__(self, ttl_seconds = 24 * 3600, cache_path: Optional[str] = None):
        super().__init__(ttl_seconds)
        self.cache_path = Path(cache_path)
        Path(cache_path).parent.mkdir(parents=True, exist_ok=True)

        # load cache if the file already exists
        try:
            if self.cache_path.exists():
                with self.cache_path.open('r', encoding='utf-8') as fr:
                    raw = json.load(fr)
                    if isinstance(raw, dict):
                        self._cache = raw
        except Exception:
            self._cache = {}


    def _flush(self):
        # atomic write: write to a temp file then replace
        tmp = self.cache_path.with_suffix(self.cache_path.suffix + '.tmp')
        with tmp.open("w", encoding='utf-8') as fw:
            json.dump(self._cache, fw)
            fw.flush()
            os.fsync(fw.fileno())
        os.replace(tmp, self.cache_path)
        # best-effort restrictive perms
        try:
            os.chmod(self.cache_path, 0o600)
        except Exception:
            pass
    
    def get(self, cve_id: str):
        data = super().get(cve_id)
        try:
            self._flush()
        except Exception:
            pass
        return data

_persistent_osv = PersistentOSVClient(ttl_seconds=24*3600, cache_path=Path.cwd().joinpath("osv_cache.json"))

def osv_cve_api(cve_id):
    return _persistent_osv.get(cve_id)

if __name__ == "__main__":
    # Example usage
    cve_id = "BIT-jenkins-2023-36478"
    osv_id = "OSV-2020-111"
    package = "org.jenkins-ci.main:cli:1.591"
    cwe_id = "CWE-20"
    cve_data = nvd_cve_api(cve_id)
    # print("---- NVD CVE API ----")
    # print(cve_data)
    # cwe_data = nvd_cwe_api(cwe_id)
    # print("---- NVD CWE API ----")
    # print(cwe_data)
    # packages = ["faker", "cache", "1cggeydu", "FfiHelper"]
    # cve_data = mitre_cve_api(package)
    # print("---- MITRE CVE API ----")
    # print(cve_data)

    cve_ids = ["CVE-2024-55591", "CVE-2024-55591", "CVE-2023-4863", "CVE-2023-4864", "CVE-2023-4865", "CVE-2023-4866", "CVE-2023-4867", "CVE-2023-4868", "CVE-2023-4869", "CVE-2023-4870", "CVE-2023-4871", "CVE-2023-4872", "CVE-2023-4873", "CVE-2023-4874", "CVE-2023-4875"]

    for cve_id in cve_ids:
        cve_data = osv_cve_api(cve_id)
        print("----- OSV CVE API ----")
        # print(cve_data)
