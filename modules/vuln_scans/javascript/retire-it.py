from galvatron_lib.core.module import BaseModule
from galvatron_lib.core.framework import FrameworkException, Colors
import subprocess
import json
import os
import distutils.spawn

class Module(BaseModule):
    meta = {
        "name": "Retire.js Scanner",
        "author": "James Hall",
        "descrription": "This plugin uses Retire.js to scan for CVEs and known vulnerabilities in JavaScript libraries; UPDATED 2019 by Lukasz Malendowicz",
        "query": "SELECT DISTINCT extracted_location, product_name, version FROM targets WHERE location IS NOT NULL"
    }

    def module_pre(self):
        self.retire_path = distutils.spawn.find_executable('retire')
        if not self.retire_path:
            raise FrameworkException('Retire.js is not installed.')

    def module_run(self, params):
        for i in params:
            try:
                extracted_location, product_name, version = i
                self.output("Scanning: %s" % extracted_location)
                retirejs_check = subprocess.Popen([self.retire_path, '--path', extracted_location, '--outputformat', 'json'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                retirejs_output, retirejs_error = retirejs_check.communicate()
                parsed_json = json.loads(retirejs_error)

                for item in parsed_json['data']:
                    issue_links = []

                    for result in item['results']:
                        issue_links = map(lambda x: x['info'][0], result['vulnerabilities'])

                        report = {
                            "file": item['file'],
                            "links": issue_links
                        }

                        file_name = report['file']
                        relative_path = os.path.dirname(file_name.replace(extracted_location, ''))
                        file_name = os.path.basename(file_name)
                        issue_urls = ""

                        for link in report['links']:
                            issue_urls = issue_urls + link + "\n"
                            #add_qa_issue(self, product=None, version=None, file_name=None, location=None, line_number=None, description=None, note='', mute=False):
                            self.add_qa_issue(product_name, version, file_name, relative_path, 0, "Issues found by Retire.js", issue_urls)

            except Exception as ex:
                self.output("Error processing: %s: %s" % (product_name, ex))

