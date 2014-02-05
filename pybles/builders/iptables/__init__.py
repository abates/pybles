#
# Copyright 2014 Andrew Bates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import re
import pybles

class IPTablesIP():
    def __init__(self, ip):
        self.ip = ip
        self.ipv4 = (ip.find(".") > -1)
        self.ipv6 = (ip.find(":") > -1)

    def __str__(self):
        return self.ip

class Options():
    def __init__(self, options = None):
        self.option_names = []
        self.options = {}
        if (options):
            for (key, value) in options.items():
                self.option_names.append(key)
                self.options[key] = value

    def __setitem__(self, option_name, option_value):
        if (self.options.get(option_name) is not None):
            raise KeyError("Option '%s' already exists in the option set" % option_name)

        self.options[option_name] = option_value
        self.option_names.append(option_name)

    def __getitem__(self, option_name):
        return self.options.get(option_name)

    def __iter__(self):
        for option_name in self.option_names:
            yield self.options[option_name]

class Directive():
    def __init__(self, command="", options = {}):
        self.command = command
        self.options = Options(options)

    def strings(self):
        return [ "%s %s" % (self.command, " ".join(self.options)) ]

class FilterDirective(Directive):
    def __init__(self):
        self.v4Options = Options()
        self.v6Options = Options()

    def v4String(self):
        return "iptables %s" % " ".join(self.v4Options)

    def v6String(self):
        return "ip6tables %s" % " ".join(self.v6Options)

    def __str__(self):
        return "%s\n%s" % (self.v4String(), self.v6String())

    def strings(self):
        return [ self.v4String(), self.v6String() ]

class FilterBuilder(pybles.DefaultBuilder):
    def __init__(self, interfaces = [], ips = []):
        self.interfaces = interfaces 
        self.ips = map(lambda ip: IPTablesIP(ip), ips)
        self.chains = []
        self.directives = []

        if (len(ips) > 0):
            d = Directive("ipset")
            d.options["action"] = "create"
            d.options["name"] = "iptables-self"
            d.options["type"] = "hash:ip"
            d.options["type_arg"] = "family"
            d.options["type_value"] = "inet"
            self.directives.append(d)

            d = Directive("ipset")
            d.options["action"] = "create"
            d.options["name"] = "iptables-self-v6"
            d.options["type"] = "hash:ip"
            d.options["type_arg"] = "family"
            d.options["type_value"] = "inet6"
            self.directives.append(d)

            for ip in self.ips:
                if (ip.ipv4):
                    d = Directive("ipset")
                    d.options["action"] = "add"
                    d.options["name"] = "iptables-self"
                    d.options["value"] = str(ip)
                    self.directives.append(d)
                else:
                    d = Directive("ipset")
                    d.options["action"] = "add"
                    d.options["name"] = "iptables-self-v6"
                    d.options["value"] = str(ip)
                    self.directives.append(d)


    def new_directive(self):
        self.currentDirective = FilterDirective()
        self.directives.append(self.currentDirective)
        self.append_option("table", "-t filter")

    def append_option(self, option_name, option):
        self.append_v4_option(option_name, option)
        self.append_v6_option(option_name, option)

    def append_v4_option(self, option_name, option):
        self.currentDirective.v4Options[option_name] = option

    def append_v6_option(self, option_name, option):
        self.currentDirective.v6Options[option_name] = option

    def prefix_option(self, value):
        if (self.current_target == "log"):
            self.append_option("log_prefix", "--prefix %s" % value)
        else:
            raise pybles.InvalidOption("The prefix option can only be used with the log target")

    def rate_limit_option(self, value):
        rate = None
        value = value.split("/")
        try:
            rate = int(value[0])
        except ValueError, ex:
            raise pybles.InvalidOption("The rate-limit rate must be an integer")

        if (len(value) > 1):
            if (value[1] in ["sec", "min", "hour", "day"]):
                self.append_option("rate_limit", "-m limit --limit %d/%s" % (rate, value[1]))
            else:
                raise InvalidDOption("Invalid rate limit interval %s" % value[1])
        else:
            self.append_option("rate_limit", "-m limit --limit %d" % rate)

    def tofrom_ip(self, ip_arg, ip):
        direction = "to" if ip_arg == "-d" else "from"
        if (ip.ipv4):
            self.append_v4_option("%s_match_ip" % direction, "%s %s" % (ip_arg, ip))
        elif (ip.ipv6):
            self.append_v6_option("%s_match_ip" % direction, "%s %s" % (ip_arg, ip))

    def tofrom_interface(self, required_direction, int_arg, value):
        (inttype, interface) = value.split(":")
        if (self.direction == required_direction):
            if (interface in self.interfaces):
                self.append_option("%s_match" % inttype, "%s %s" % (int_arg, interface))
            else:
                raise pybles.InvalidOption("Interface %s is not listed as an available system interface" % interface)
        else:
            raise pybles.InvalidOption("%s only applies to %s traffic" % (inttype, required_direction))

    def tofrom_self(self, direction, required_direction, dst_arg):
        if (len(self.ips) == 0):
            raise pybles.InvalidOption("Cannot specify to/from self when no system addresses have been specified")
        if (self.direction == required_direction):
            self.append_v4_option("%s_ip_set" % dst_arg, "-m set --match-set iptables-self %s" % dst_arg)
            self.append_v6_option("%s_ip_set" % dst_arg, "-m set --match-set iptables-self-v6 %s" % dst_arg)
        else:
            raise pybles.InvalidOption("\"%s self\" only applies to %s traffic" % (direction, required_direction))

    def from_option(self, value):
        if (value == "self"):
            self.tofrom_self("from", "output", "src")
        elif (value.find("int:") > -1):
            self.tofrom_interface("output", "-o", value)
        else:
            self.tofrom_ip("-s", IPTablesIP(value))

    def to_option(self, value):
        if (value == "self"):
            self.tofrom_self("to", "input", "dst")
        elif (value.find("int:") > -1):
            self.tofrom_interface("input", "-i", value)
        else:
            self.tofrom_ip("-d", IPTablesIP(value))

    def srcdst_ports(self, ports):
        (direction, ports) = ports.split(":")
        if (re.match(r"""^(?:\d+)|(?:\d+:)|(?:\d+:\d+)|(?::\d+)$""", ports)):
            if (direction == "dst-port"):
                self.append_option("dst_port", "--dport %s" % ports)
            elif (direction == "src-port"):
                self.append_option("src_port", "--sport %s" % ports)
            else:
                raise pybles.InvalidOption("Port option must be either src-port or dst-port")
        else:
            raise pybles.InvalidOption("The supplied port argument, %s, is not recognized." % ports)

    def udp_option(self, value):
        self.append_option("protocol_module", "-m udp")
        self.append_option("protocol", "-p udp")
        self.srcdst_ports(value)

    def tcp_option(self, value):
        self.append_option("protocol_module", "-m tcp")
        self.append_option("protocol", "-p tcp")
        self.srcdst_ports(value)

    def process_options(self, directive):
        for option in directive.options:
            option_name = option.name.replace("-", "_")
            if (hasattr(self, "%s_option" % option_name)):
                getattr(self, "%s_option" % option_name)(option.value)
            else:
                raise pybles.InvalidOption("%s is an invalid option" % option_name)

    def default_build_directive(self, path, directive):
        if (directive.name in [ "log", "accept", "drop", "reject" ]):
            self.current_target = directive.name
            self.new_directive()
            self.append_option("chain", "-A %s" % self.chains[-1])
            self.append_option("target", "-j %s" % directive.name.upper())
            self.process_options(directive)
            directives = []
            for directive in self.directives:
                for string in directive.strings():
                    directives.append(string)
            self.current_directive = None
            self.directives = []
            return directives
        else:
            raise InvalidDirective("Valid directives are \"log\", \"accept\", \"drop\" and \"reject\"")

    def default_build_block(self, path):
        if (len(self.chains) == 0):
            if (path[-1] in [ 'input', 'output', 'forward' ]):
                self.direction = path[-1]
                self.chains.append(path[-1].upper())
            else:
                raise pybles.InvalidBlock("Unknown default filter chain %s" % path[-1])
        else:
            if (path[-1] not in [ 'input', 'output', 'forward' ]):
                self.new_directive()
                self.append_option("new_chain", "-N %s" % path[-1])
                self.new_directive()
                self.append_option("policy", "-P %s RETURN" % path[-1])
                self.new_directive()
                self.append_option("chain", "-A %s" % self.chains[-1])
                self.append_option("target", "-j %s" % path[-1])
                self.chains.append(path[-1])
            else:
                raise pybles.InvalidBlock("The system chain \"%s\" cannot be nested inside chain \"%s\"" % (path[-1], self.chains[-1]))
        return self

    def default_build_block_end(self, block_name):
        self.chains.pop()

class Builder(pybles.DefaultBuilder):
    def __init__(self, ips=[], interfaces=[]):
        self.filter_builder = FilterBuilder(ips=ips, interfaces=interfaces)

    def filter(self, *args):
        return self.filter_builder

