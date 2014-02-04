
import re
import pybles

class IPTablesIP():
    def __init__(self, ip):
        self.ip = ip
        self.ipv4 = (ip.find(".") > -1)
        self.ipv6 = (ip.find(":") > -1)

    def __str__(self):
        return self.ip

class IPTablesDirective():
    def __init__(self):
        self.v4Options = []
        self.v6Options = []

    def v4String(self):
        return "iptables %s" % " ".join(self.v4Options)

    def v6String(self):
        return "ip6tables %s" % " ".join(self.v6Options)

    def __str__(self):
        return "%s\n%s" % (self.v4String(), self.v6String())

class FilterBuilder(pybles.DefaultBuilder):
    def __init__(self, interfaces = [], ips = []):
        self.interfaces = interfaces 
        self.ips = ips

        self.chains = []
        self.directives = []

    def new_directive(self):
        self.currentDirective = IPTablesDirective()
        self.directives.append(self.currentDirective)
        self.append_option("-t filter")

    def append_option(self, option):
        self.currentDirective.v4Options.append(option)
        self.currentDirective.v6Options.append(option)

    def append_v4_option(self, option):
        self.currentDirective.v4Options.append(option)

    def append_v6_option(self, option):
        self.currentDirective.v6Options.append(option)

    def prefix_option(self, value):
        if (self.current_target == "log"):
            self.append_option("--prefix %s" % value)
        else:
            raise pybles.InvalidOption("The prefix option can only be used with the log target")

    def rate_limit_option(self, value):
        rate = None
        value = value.split("/")
        try:
            rate = int(value[0])
        except ValueError, ex:
            raise InvalidOption("The rate-limit rate must be an integer")

        if (len(value) > 1):
            if (value[1] in ["sec", "min", "hour", "day"]):
                self.append_option("-m limit --limit %d/%s" % (rate, value[1]))
            else:
                raise InvalidDOption("Invalid rate limit interval %s" % value[1])
        else:
            self.append_option("-m limit --limit %d" % rate)

    def tofrom_ip(self, ip_arg, ip):
        if (ip.ipv4):
            self.append_v4_option("%s %s" % (ip_arg, ip))
        elif (ip.ipv6):
            self.append_v6_option("%s %s" % (ip_arg, ip))

    def tofrom_interface(self, required_direction, int_arg, value):
        (inttype, interface) = value.split(":")
        if (self.direction == required_direction):
            if (interface in self.interfaces):
                self.append_option("%s %s" % (int_arg, interface))
            else:
                raise InvalidOption("Interface %s is not listed as an available system interface" % interface)
        else:
            raise InvalidOption("%s only applies to %s traffic" % (inttype, required_direction))

    def tofrom_self(self, direction, required_direction, ip_arg):
        if (self.direction == required_direction):
            for ip in self.ips:
                self.tofrom_ip(ip_arg, ip)
        else:
            raise InvalidOption("\"%s self\" only applies to %s traffic" % (direction, required_direction))

    def from_option(self, value):
        if (value == "self"):
            self.tofrom_self("from", "output", "-s")
        elif (value.find("int:") > -1):
            self.tofrom_interface("output", "-o", value)
        else:
            self.tofrom_ip("-s", IPTablesIP(value))

    def to_option(self, value):
        if (value == "self"):
            self.tofrom_self("to", "input", "-d")
        elif (value.find("int:") > -1):
            self.tofrom_interface("input", "-i", value)
        else:
            self.tofrom_ip("-d", IPTablesIP(value))

    def srcdst_ports(self, ports):
        (direction, ports) = ports.split(":")
        if (re.match(r"""^(?:\d+)|(?:\d+:)|(?:\d+:\d+)|(?::\d+)$""", ports)):
            if (direction == "dst-port"):
                self.append_option("--dport %s" % ports)
            elif (direction == "src-port"):
                self.append_option("--sport %s" % ports)
            else:
                raise InvalidOption("Port option must be either src-port or dst-port")
        else:
            raise InvalidOption("The supplied port argument, %s, is not recognized." % ports)

    def udp_option(self, value):
        self.append_option("-m udp")
        self.append_option("-p udp")
        self.srcdst_ports(value)

    def tcp_option(self, value):
        self.append_option("-m udp")
        self.append_option("-p udp")
        self.srcdst_ports(value)

    def process_options(self, directive):
        for option in directive.options:
            option_name = option.name.replace("-", "_")
            if (hasattr(self, "%s_option" % option_name)):
                getattr(self, "%s_option" % option_name)(option.value)
            else:
                raise InvalidOption("%s is an invalid option" % option_name)

    def default_build_directive(self, path, directive):
        if (directive.name in [ "log", "accept", "drop", "reject" ]):
            self.current_target = directive.name
            self.new_directive()
            self.append_option("-A %s" % self.chains[-1])
            self.append_option("-j %s" % directive.name.upper())
            self.process_options(directive)
            directives = []
            for directive in self.directives:
                directives.append(directive.v4String())
                directives.append(directive.v6String())
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
                self.append_option("-N %s" % path[-1])
                self.new_directive()
                self.append_option("-P %s RETURN" % path[-1])
                self.new_directive()
                self.append_option("-A %s" % self.chains[-1])
                self.append_option("-j %s" % path[-1])
                self.chains.append(path[-1])
            else:
                raise pybles.InvalidBlock("The system chain \"%s\" cannot be nested inside chain \"%s\"" % (path[-1], self.chains[-1]))
        return self

    def default_build_block_end(self, block_name):
        self.chains.pop()

class Builder(pybles.DefaultBuilder):
    def __init__(self):
        self.filter_builder = FilterBuilder()

    def filter(self, *args):
        return self.filter_builder

