from galvatron_lib.core.module import BaseModule
import os
import re

class RegexModule(BaseModule):

    def file_name_regex(self):
        return ".*"

    def module_run(self, params):
        try:
            self.compiled_regex = [(re.compile(r[0], re.I), r[1]) for r in self.line_regex()]

            for target in params:
                location, product, version = target
                self.output("Scanning folder: %s" % location)
                for f in os.walk(location):
                    dirpath, dirnames, filenames = f
                    for x in filenames:
                        if re.match(self.file_name_regex(), x):
                            full_location = os.path.join(dirpath, x)
                            relative_location = full_location.replace(location + "/", "")
                            _, ext = os.path.splitext(full_location)
                            extra_regex = self.get_ext_specific_regex(ext)
                            self.scan_file(relative_location, full_location, product, version, extra_regex)

        except Exception as ex:
            print(ex)

    def line_regex(self):
        return []

    def get_ext_specific_regex(self, ext):
        return []

    def scan_file(self, relative_location, full_location, product_name, version, extra_regex):
        with open(full_location) as f:
            for line_no, line in enumerate(f):
                line = line.rstrip()
                for r in self.compiled_regex:
                    if r[0].search(line):
                        self.add_qa_issue(product_name, version,
                                os.path.basename(relative_location),
                                os.path.dirname(relative_location), line_no + 1,
                                line, r[1])
                        continue

                for r in extra_regex:
                    if r[0].search(line):
                        self.add_qa_issue(product_name, version,
                                os.path.basename(relative_location),
                                os.path.dirname(relative_location), line_no + 1,
                                line, r[1])
                        continue


