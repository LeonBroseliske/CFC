#!/usr/bin/python

import sys
from netaddr import IPNetwork, IPAddress

ip = (sys.argv[1])
subnet = (sys.argv[2])

if IPNetwork(ip) in IPNetwork(subnet):
	print (subnet)
