import requests
from galvatron_lib.core.module import BaseModule
from urllib.parse import quote_plus
import json

class VulnIq():
    def __init__(self, token, base_url="https://free.vulniq.com/api"):
        self.token = token
        self.base_url = base_url

    def make_request(self, path, **kwargs):
        url = f"{self.base_url}{path}?resultsPerPage=50"
        headers = {"Authorization": f"Bearer {self.token}"}
        for arg, value in kwargs.items():
            url += f"&{arg}={quote_plus(str(value))}"

        return requests.get(url, headers=headers).json()

    def search_by_cpe(self, cpe):
        return self.make_request("/vulnerability/list-by-cpe", cpe=cpe)

    def search(self, vendor, product, version, pageNumber=1):
        return self.make_request("/vulnerability/list-by-vpv", vendorName=vendor, productName=product, versionName=version, pageNumber=pageNumber)

class Module(BaseModule):
    meta = {
            "name": "VulnIQ",
            "author": "Mike West",
            "descrription": "Searches VulnIQ for cves based on the target",
            "query": "SELECT DISTINCT product_name, vendor, version FROM targets WHERE location IS NOT NULL"
    }


    def module_run(self, params):
        key = self.get_key("vulniq_api")
        if key == "":
            self.error("No api key defined for vulniq_api")
            return

        api = VulnIq(key)
        for p in params:
            product_name, vendor, version = p
            pageNumber = 1
            results = api.search(vendor, product_name, version, pageNumber=pageNumber) 
            while True:
                for result in results["results"]:
                    cve_number = result["name"]
                    published = result["createDateAtSource"]
                    description = result["description"]
                    cvss = result["dataScore"]

                    self.add_cve(product_name, version, cve_number, description, published, cvss)

                if results["hasMore"]:
                    pageNumber += 1
                    results = api.search(vendor, product_name, version, pageNumber=pageNumber)
                else:
                    break

