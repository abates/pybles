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

import unittest
import pybles
import pybles.builders.iptables as iptables

class IPTableTest(unittest.TestCase):
    def test_chain_names(self):
        b = iptables.Builder()
        pyble = pybles.PybleParser(b)

        config = "filter {} fowler {}"
        self.assertRaises(pybles.InvalidBlock, pyble.parse_string, config)

        config = "filter { fowler {}}"
        self.assertRaises(pybles.InvalidBlock, pyble.parse_string, config)

        config = "filter { input {}}"
        pyble.parse_string(config)

        config = "filter { output {}}"
        pyble.parse_string(config)

        config = "filter { forward {}}"
        pyble.parse_string(config)

        config = "filter { input { footable {}}}"
        pyble.parse_string(config)

    def test_nested_chain(self):
        p = pybles.PybleParser(iptables.Builder())
        config = "filter { input { foochain { accept; }}}"
        output = p.parse_string(config)

        self.assertEqual(8, len(output))
        self.assertEqual(output[0], "iptables -t filter -N foochain")
        self.assertEqual(output[1], "ip6tables -t filter -N foochain")

        self.assertEqual(output[2], "iptables -t filter -P foochain RETURN")
        self.assertEqual(output[3], "ip6tables -t filter -P foochain RETURN")

        self.assertEqual(output[4], "iptables -t filter -A INPUT -j foochain")
        self.assertEqual(output[5], "ip6tables -t filter -A INPUT -j foochain")

        self.assertEqual(output[6], "iptables -t filter -A foochain -j ACCEPT")
        self.assertEqual(output[7], "ip6tables -t filter -A foochain -j ACCEPT")

    def test_two_nested_chains(self):
        p = pybles.PybleParser(iptables.Builder())
        config = "filter { input { foochain1 { foochain2 { accept; }}}}"
        output = p.parse_string(config)

        self.assertEqual(14, len(output))
        self.assertEqual(output[0], "iptables -t filter -N foochain1")
        self.assertEqual(output[1], "ip6tables -t filter -N foochain1")

        self.assertEqual(output[2], "iptables -t filter -P foochain1 RETURN")
        self.assertEqual(output[3], "ip6tables -t filter -P foochain1 RETURN")

        self.assertEqual(output[4], "iptables -t filter -A INPUT -j foochain1")
        self.assertEqual(output[5], "ip6tables -t filter -A INPUT -j foochain1")

        self.assertEqual(output[6], "iptables -t filter -N foochain2")
        self.assertEqual(output[7], "ip6tables -t filter -N foochain2")

        self.assertEqual(output[8], "iptables -t filter -P foochain2 RETURN")
        self.assertEqual(output[9], "ip6tables -t filter -P foochain2 RETURN")

        self.assertEqual(output[10], "iptables -t filter -A foochain1 -j foochain2")
        self.assertEqual(output[11], "ip6tables -t filter -A foochain1 -j foochain2")

        self.assertEqual(output[12], "iptables -t filter -A foochain2 -j ACCEPT")
        self.assertEqual(output[13], "ip6tables -t filter -A foochain2 -j ACCEPT")

    def test_parallel_nested_chains(self):
        p = pybles.PybleParser(iptables.Builder())
        config = "filter { input { foochain1 { foochain2 { accept; }} foochain3 { accept; }}}"
        output = p.parse_string(config)

        self.assertEqual(22, len(output))
        self.assertEqual(output[0], "iptables -t filter -N foochain1")
        self.assertEqual(output[1], "ip6tables -t filter -N foochain1")

        self.assertEqual(output[2], "iptables -t filter -P foochain1 RETURN")
        self.assertEqual(output[3], "ip6tables -t filter -P foochain1 RETURN")

        self.assertEqual(output[4], "iptables -t filter -A INPUT -j foochain1")
        self.assertEqual(output[5], "ip6tables -t filter -A INPUT -j foochain1")

        self.assertEqual(output[6], "iptables -t filter -N foochain2")
        self.assertEqual(output[7], "ip6tables -t filter -N foochain2")

        self.assertEqual(output[8], "iptables -t filter -P foochain2 RETURN")
        self.assertEqual(output[9], "ip6tables -t filter -P foochain2 RETURN")

        self.assertEqual(output[10], "iptables -t filter -A foochain1 -j foochain2")
        self.assertEqual(output[11], "ip6tables -t filter -A foochain1 -j foochain2")

        self.assertEqual(output[12], "iptables -t filter -A foochain2 -j ACCEPT")
        self.assertEqual(output[13], "ip6tables -t filter -A foochain2 -j ACCEPT")

        self.assertEqual(output[14], "iptables -t filter -N foochain3")
        self.assertEqual(output[15], "ip6tables -t filter -N foochain3")

        self.assertEqual(output[16], "iptables -t filter -P foochain3 RETURN")
        self.assertEqual(output[17], "ip6tables -t filter -P foochain3 RETURN")

        self.assertEqual(output[18], "iptables -t filter -A INPUT -j foochain3")
        self.assertEqual(output[19], "ip6tables -t filter -A INPUT -j foochain3")

        self.assertEqual(output[20], "iptables -t filter -A foochain3 -j ACCEPT")
        self.assertEqual(output[21], "ip6tables -t filter -A foochain3 -j ACCEPT")

    def test_simple_directive(self):
        p = pybles.PybleParser(iptables.Builder())

        config = "filter { input { accept; }}"
        output = p.parse_string(config)
        self.assertEqual(2, len(output))
        self.assertEqual(output[0], "iptables -t filter -A INPUT -j ACCEPT")
        self.assertEqual(output[1], "ip6tables -t filter -A INPUT -j ACCEPT")

    def test_only_log_allows_prefix(self):
        p = pybles.PybleParser(iptables.Builder())

        config = "filter { input { accept prefix \"foobar\"; }}"
        self.assertRaises(pybles.InvalidOption, p.parse_string, config)

        p = pybles.PybleParser(iptables.Builder())

        config = "filter { input { log prefix \"foobar\"; }}"
        output = p.parse_string(config)
        self.assertEqual(2, len(output))
        self.assertEqual(output[0], "iptables -t filter -A INPUT -j LOG --prefix \"foobar\"")
        self.assertEqual(output[1], "ip6tables -t filter -A INPUT -j LOG --prefix \"foobar\"")

    def test_src_port(self):
        p = pybles.PybleParser(iptables.Builder())

        config = "filter { input { accept tcp src-port:22; }}"
        output = p.parse_string(config)
        self.assertEqual(2, len(output))
        self.assertEqual(output[0], "iptables -t filter -A INPUT -j ACCEPT -m tcp -p tcp --sport 22")
        self.assertEqual(output[1], "ip6tables -t filter -A INPUT -j ACCEPT -m tcp -p tcp --sport 22")

        config = "filter { input { accept udp src-port:22; }}"
        output = p.parse_string(config)
        self.assertEqual(2, len(output))
        self.assertEqual(output[0], "iptables -t filter -A INPUT -j ACCEPT -m udp -p udp --sport 22")
        self.assertEqual(output[1], "ip6tables -t filter -A INPUT -j ACCEPT -m udp -p udp --sport 22")

    def test_dst_port(self):
        p = pybles.PybleParser(iptables.Builder())

        config = "filter { input { accept tcp dst-port:22; }}"
        output = p.parse_string(config)
        self.assertEqual(2, len(output))
        self.assertEqual(output[0], "iptables -t filter -A INPUT -j ACCEPT -m tcp -p tcp --dport 22")
        self.assertEqual(output[1], "ip6tables -t filter -A INPUT -j ACCEPT -m tcp -p tcp --dport 22")

        config = "filter { input { accept udp dst-port:22; }}"
        output = p.parse_string(config)
        self.assertEqual(2, len(output))
        self.assertEqual(output[0], "iptables -t filter -A INPUT -j ACCEPT -m udp -p udp --dport 22")
        self.assertEqual(output[1], "ip6tables -t filter -A INPUT -j ACCEPT -m udp -p udp --dport 22")

    def test_to_self(self):
        p = pybles.PybleParser(iptables.Builder(ips = [ "192.168.1.1" ]))

        config = "filter { input { accept to self; }}"
        output = p.parse_string(config)

        self.assertEqual(5, len(output))
        self.assertEqual(output[0], "ipset create iptables-self hash:ip family inet")
        self.assertEqual(output[1], "ipset create iptables-self-v6 hash:ip family inet6")
        self.assertEqual(output[2], "ipset add iptables-self 192.168.1.1")
        self.assertEqual(output[3], "iptables -t filter -A INPUT -j ACCEPT -m set --match-set iptables-self dst")
        self.assertEqual(output[4], "ip6tables -t filter -A INPUT -j ACCEPT -m set --match-set iptables-self-v6 dst")

        config = "filter { input { accept from self; }}"
        self.assertRaises(pybles.InvalidOption, p.parse_string, config)

    def test_from_self(self):
        p = pybles.PybleParser(iptables.Builder(ips = [ "192.168.1.1" ]))

        config = "filter { output { accept from self; }}"
        output = p.parse_string(config)

        self.assertEqual(5, len(output))
        self.assertEqual(output[0], "ipset create iptables-self hash:ip family inet")
        self.assertEqual(output[1], "ipset create iptables-self-v6 hash:ip family inet6")
        self.assertEqual(output[2], "ipset add iptables-self 192.168.1.1")
        self.assertEqual(output[3], "iptables -t filter -A OUTPUT -j ACCEPT -m set --match-set iptables-self src")
        self.assertEqual(output[4], "ip6tables -t filter -A OUTPUT -j ACCEPT -m set --match-set iptables-self-v6 src")

        config = "filter { output { accept to self; }}"
        self.assertRaises(pybles.InvalidOption, p.parse_string, config)

    def test_to_interface(self):
        p = pybles.PybleParser(iptables.Builder(interfaces = [ "eth0" ]))

        config = "filter { input { accept to dst-int:eth0; }}"
        output = p.parse_string(config)

        self.assertEqual(2, len(output))
        self.assertEqual(output[0], "iptables -t filter -A INPUT -j ACCEPT -i eth0")
        self.assertEqual(output[1], "ip6tables -t filter -A INPUT -j ACCEPT -i eth0")

        config = "filter { output { accept to dst-int:eth0; }}"
        self.assertRaises(pybles.InvalidOption, p.parse_string, config)

    def test_from_interface(self):
        p = pybles.PybleParser(iptables.Builder(interfaces = [ "eth0" ]))

        config = "filter { output { accept from src-int:eth0; }}"
        output = p.parse_string(config)

        self.assertEqual(2, len(output))
        self.assertEqual(output[0], "iptables -t filter -A OUTPUT -j ACCEPT -o eth0")
        self.assertEqual(output[1], "ip6tables -t filter -A OUTPUT -j ACCEPT -o eth0")

        config = "filter { input { accept from src-int:eth0; }}"
        self.assertRaises(pybles.InvalidOption, p.parse_string, config)

