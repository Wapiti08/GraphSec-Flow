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



# def nvd_cwe_api(cwe_id):
#     url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cweId={cwe_id}"
#     response = requests.get(url)
#     if response.status_code == 200:
#         return response.json()
#     else:
#         print(f"Failed to retrieve CVE info. Status code: {response.status_code}")
#         return None

# def mitre_cve_api(package):
#     cve_simple = crawler.get_main_page(package) 
#     pprint(crawler.get_cve_detail(cve_simple))


class VulnClient:
    ''' unified OSV + NVD query client with caching and retries
    
    '''
    def __init__(self, ttl_seconds: int = 24*3600):
        self.ttl = ttl_seconds
        # cve_id -> {'ts': float, 'data': Any}
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._neg_cache_ttl = 5 * 60 
        self._lock = threading.Lock()
        self.session = requests.Session()

    
    def _make_session(self):
        s= requests.Session()
        retry = Retry(
            total=5,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods= ["GET"],
            raise_on_status=False,
        )
        s.mount("https://", HTTPAdapter(max_retries=retry))
        return s
    
    def _get_json(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None
    
    def _get_from_osv(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self._get_json(f"https://api.osv.dev/v1/vulns/{cve_id}")

    def _get_from_nvd(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self._get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        ''' query OSV first, fall back to NVD if not found
        
        '''
        now = time.time()
        with self._lock:
            hit = self._cache.get(cve_id)
            if hit:
                age = now - hit["ts"]
                if hit["data"] is None and age < self._neg_cache_ttl:
                    return None
                if hit["data"] is not None and age < self.ttl:
                    return hit["data"]
        
        # OSV first
        data = self._get_from_osv(cve_id)
        source = "osv"

        # Fallback to NVD
        if not data:
            data = self._get_from_nvd(cve_id)
            source = "nvd"
        
        result = {"source": source, "data": data} if data else None

        with self._lock:
            self._cache[cve_id] = {"ts": now, "data": result}
        return result


class PersistentVulnClient(VulnClient):
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
    
    def get_cve(self, cve_id: str):
        ''' query OSV first, fall back to NVD if not found
        
        '''
        now = time.time()
        with self._lock:
            hit = self._cache.get(cve_id)
            if hit:
                age = now - hit['ts']
                if hit['data'] is None and age < self._neg_cache_ttl:
                    return None
                if hit['data'] is not None and age < self.ttl:
                    return hit["data"]
        # OSV first
        data = self._get_from_osv(cve_id)
        source = "osv"

        # Fallback to NVD
        if not data:
            data = self._get_from_nvd(cve_id)
            source = "nvd"
        
        result = {"source": source, "data": data} if data else None

        with self._lock:
            self._cache[cve_id] = {"ts": now, "data": result}
        
        return result


_persistent_osv = PersistentVulnClient(ttl_seconds=24*3600, cache_path=Path.cwd().joinpath("osv_cache.json"))

def osv_cve_api(cve_id):
    return _persistent_osv.get_cve(cve_id)


# def nvd_cve_api(cve_id):
#     url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
#     response = requests.get(url)
#     if response.status_code == 200:
#         return response.json()
#     else:
#         print(f"Failed to retrieve CVE info. Status code: {response.status_code}")
#         return None

if __name__ == "__main__":
    # read aggregated_data.json
    data_path = Path.cwd().parent.joinpath("data").joinpath("aggregated_data.json")
    

    # Example usage
    cve_id = "BIT-jenkins-2023-36478"
    osv_id = "OSV-2020-111"
    package = "org.jenkins-ci.main:cli:1.591"
    cwe_id = "CWE-20"
    # cve_data = nvd_cve_api(cve_id)
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
        # cve_data = nvd_cve_api(cve_id)
        print("----- OSV CVE API ----")
        print(cve_data)
