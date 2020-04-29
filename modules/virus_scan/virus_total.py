from galvatron_lib.core.module import BaseModule
from virus_total_apis import PublicApi as Api
import hashlib
import json
import time
import os

class Module(BaseModule):
    meta = {
            "name": "Virus Total Scanner",
            "author": "Mike West",
            "descrription": "Uses the virus total api to scan for viruses",
            "query": "SELECT DISTINCT location, product_name, version FROM targets WHERE location IS NOT NULL",
            "options": [
                ["sleep_time", 10, True, 'time to sleep between making requests to retrieve the report'],
                ["extra_sleep_time", 30, True, 'time to sleep when we hit the max requests in 1 minute threshold'],
                ["retries", 12, True, 'number of times to retry getting the report from virus total']
            ]
    }

    def module_run(self, params):
        key = self.get_key("virus_total_api")

        if key == "":
            self.error("No key defined for virus_total_api")
            return

        self.output("Got key: %s" % key)

        api = Api(key)

        for i in params:
            location, product_name, version = i

            self.output("Scanning: %s" % location)
            if not os.path.exists(location):
                self.error("%s does not exist")
                continue

            size = os.path.getsize(location)
            if (size / (1024 * 1024.0)) > 32:
                self.error("%s is larger than 32Mb..cannot submit to virus total" % location)
                continue

            is_local = not "://" in location

            response = api.scan_file(location, from_disk=is_local)
            result_code = response["response_code"]
            scan_id = response["results"]["scan_id"]

            self.output("Got response code: %s, scan_id: %s" % (result_code, scan_id))

            if result_code == 200:
                tries = self.options['retries']

                while tries > 1:
                    self.output("Sleeping %ss to wait for response" % self.options['sleep_time'])
                    time.sleep(self.options['sleep_time'])

                    response = api.get_file_report(scan_id)

                    if response["response_code"] == 204:
                        self.output("Exeeded api request limit sleeping an extra %ss" % self.options['extra_sleep_time'])
                        time.sleep(self.options['extra_sleep_time'])
                        continue

                    if not "scans" in response["results"]:
                        tries -= 1
                        continue

                    detected = [s for s in response["results"]["scans"] if response["results"]["scans"][s]["detected"] == True]
                    total_scans = response["results"]["total"]
                    found = response["results"]["positives"]
                    scans = response["results"]["scans"]

                    for d in detected:
                        self.add_virus(product_name, version, d,
                                    scans[d]["version"], scans[d]["update"],
                                    scans[d]["result"])

                    self.output("%s/%s scanners detected viruses" % (found, total_scans))
                    break
