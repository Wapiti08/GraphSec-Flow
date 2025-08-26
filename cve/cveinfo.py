'''
 # @ Create Time: 2025-06-26 10:06:57
 # @ Modified time: 2025-06-26 10:06:59
 # @ Description: the cve api for querying CVE information
 '''
import requests
from mitrecve import crawler
from pprint import pprint

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

def osv_cve_api(cve_id):
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve CVE info from OSV. Status code: {response.status_code}")
        return None

if __name__ == "__main__":
    # Example usage
    cve_id = "CVE-2016-9910"
    osv_id = "OSV-2020-111"
    package = "org.jenkins-ci.main:cli:1.591"
    cwe_id = "CWE-20"
    # cve_data = nvd_cve_api(cve_id)
    # print("---- NVD CVE API ----")
    # print(cve_data)
    cwe_data = nvd_cwe_api(cwe_id)
    print("---- NVD CWE API ----")
    print(cwe_data)
    # packages = ["faker", "cache", "1cggeydu", "FfiHelper"]
    cve_data = mitre_cve_api(package)
    print("---- MITRE CVE API ----")
    print(cve_data)
    # cve_data = osv_cve_api(cve_id)
    # print("----- OSV CVE API ----")
    # print(cve_data)
