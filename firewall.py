#!/usr/bin/python

import os
import pybles
import pybles.builders.iptables as iptables

def custom_chains(table = 'filter'):
    chains = []
    for line in os.popen("iptables -t %s -L -n -v | grep Chain | grep -v policy | awk '{print $2}'" % table):
        chains.append(line.rstrip())
    return chains

def builtin_chains(table = 'filter'):
    chains = []
    for line in os.popen("iptables -t %s -L -n -v | grep Chain | grep policy | awk '{print $2}'" % table):
        chains.append(line.rstrip())
    return chains

def reset_tables():
    # delete custom targets
    for table in ('filter', 'nat', 'mangle'):
        for chain in custom_chains(table):
            print "iptables -t %s -X %s" % (table, chain)
        for chain in builtin_chains(table):
            print "iptables -t %s -F %s" % (table, chain)

interfaces = []
interface_ips = []
for line in os.popen("ip link show | grep -P \"^\d\" | awk -F: '{print $2}'"):
    interface = line.strip()
    interfaces.append(interface)
    for line in os.popen("ip addr show %s| grep inet | awk '{print $1\" \"$2}'" % interface):
        family, ip = line.rstrip().split()
        ip, prefix = ip.split("/")
        interface_ips.append(ip)

parser = pybles.PybleParser(iptables.Builder(interfaces = interfaces, ips = interface_ips))
commands = parser.parse_file("tests/test.conf")
for command in commands:
    print command
#reset_tables()


