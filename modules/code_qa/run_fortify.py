import re
import os
import subprocess
import shutil
import fnmatch
import xmlrpc.client as xmlrpclib
import time
from galvatron_lib.core.module import BaseModule

class Module(BaseModule):
    meta = {
            "name": "Runs Fortify",
            "author": "Mike West, James Hall",
            "descrription": "Runs fortify on a virtual machine",
            "query": "SELECT DISTINCT location, product_name, version FROM targets WHERE location IS NOT NULL",
            "options": [
                ["vm_name", "HP_Fortify", True, 'Name of the virtual machine to use'],
                ["snapshot", "Clean", True, 'Name of snapshot to restore'],
                ["vm_mode", "gui", True, 'startup mode of vm (gui or headless)']
            ]
    }

    def module_run(self, params):
        vm = self.options['vm_name']
        snapshot = self.options['snapshot']
        mode = self.options["vm_mode"]

        dest_path = ""
        for location, product, version in params:
            try:
                self.output("Restoring snapshot %s on %s" % (snapshot, vm))
                cmd = subprocess.call("VBoxManage snapshot \"%s\" restore \"%s\"" % (vm, snapshot), shell=True)

                self.output("Starting VM: %s" % vm)
                cmd = subprocess.call("VBoxManage startvm \"%s\" --type %s" % (vm, mode), shell=True)

                proc = subprocess.Popen(["VBoxManage guestproperty get \"%s\" /VirtualBox/GuestInfo/Net/0/V4/IP" % vm], stdout = subprocess.PIPE, shell=True)
                ip = proc.communicate()[0].split(" ")[1].rstrip()

                proxy_url = "http://%s:8000" % ip
                self.output("Service endpoint: %s" % proxy_url)
                rpc = xmlrpclib.ServerProxy(proxy_url)

                self.output("Giving VM time to wake up...")
                time.sleep(5)

                self.output("Running fortify script...")
                with open(location, "rb") as h:
                    b = xmlrpclib.Binary(h.read())

                report = rpc.run_fortify(os.path.basename(location), b)
                with open("/tmp/report.fpr", "wb") as h:
                    h.write(report.data)

                self.output("Written report to /tmp/report.fpr")

            finally:
                self.output("Shutting down VM: %s..." %vm)
                subprocess.call("VBoxManage controlvm \"%s\" poweroff" % vm, shell=True)

