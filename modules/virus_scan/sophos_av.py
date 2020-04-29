from galvatron_lib.core.module import BaseModule
from galvatron_lib.core.framework import FrameworkException, Colors
from datetime import datetime, timedelta
import hashlib
import json
import time
import os
import subprocess
import re 

class Module(BaseModule):
  meta = {
      "name": "Sophos Anti-Virus Scanner",
      "author": "James Hall",
      "description": "This plugin uses Sophos anti-virus to scan for viruses",
      "query": "SELECT DISTINCT location, product_name, version FROM targets WHERE location IS NOT NULL"
  }

  def module_pre(self):
    if os.path.isfile("/opt/sophos-av/bin/savdstatus") == False:
      raise FrameworkException('Sophos is not installed.')


  def module_run(self, params):
    engine_name="Sophos"
    version_check = subprocess.Popen(['/opt/sophos-av/bin/savdstatus','--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    version_output, version_error = version_check.communicate()
    version_match = re.search(r'Sophos\sAnti-Virus\s+\=\s(?P<version>[.0-9]+).*Build Revision.*?=\s(?P<revision>\d+).*data\srelease.*?=\s(?P<release>.*)\s', version_output, re.M|re.S)
    sophos_version = version_match.group('version') + " " + version_match.group('revision')
    signature_date = version_match.group('release') 
    sig_date = datetime.strptime(signature_date.strip(), '%a %d %b %Y %H:%M:%S')
    diff = timedelta(days=10)
    check_diff = datetime.today() - diff
    if sig_date < check_diff:
      self.alert("%sSophos is out of date. It is recommended to update Sophos before rerunning this script.%s" % (Colors.O, Colors.N))

    for i in params:
      location, product_name, version = i
      self.output("Scanning: %s" % location)

      os.system("savscan -f " + location + " -p=sophos.log -ss -archive > /dev/null")
      file_descriptor = open("sophos.log", "r")
      log_output = file_descriptor.readlines()

      for log_line in log_output:
        virus_match = re.search(r">>>\sVirus\s+'(?P<virus_description>\S+)'.*in\sfile\s(?P<file>\S+)", log_line)
        description = virus_match.group('virus_description') + " found in " + virus_match.group('file')
        self.add_virus(product_name, version, engine_name, sophos_version, signature_date, description )
        self.output("%s has detected %s" % (engine_name, description))
        break

  def module_post(self):
    os.remove("sophos.log")		
