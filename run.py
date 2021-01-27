#!/usr/bin/env python3

from netrecon import recon
import json
import os

host = os.getenv('NETRECON_HOST')
username = os.getenv('NETRECON_USERNAME')
password = os.environ.get('NETRECON_PASSWORD')

recon_output = recon.host_discovery(host, username, password)

print(json.dumps(recon_output))
