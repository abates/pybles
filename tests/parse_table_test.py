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
import os

class ParseTableTest(unittest.TestCase):
    def test_parse_table(self):
        pyble = pybles.PybleParser()

        self.assertRaises(pybles.ParseError, pyble.parse_string, "")
        config = "filter {}"
        pyble.parse_string(config) 
        
        config = "filter {}nat {}mangle {}raw {}security {}"
        pyble.parse_string(config)

    def test_parse_table_chain(self):
        pyble = pybles.PybleParser()

        config = "filter {input {}}"
        pyble.parse_string(config)

    def test_parse_chain_in_chain(self):
        pyble = pybles.PybleParser()
        config = "filter { input { baz {}}}"
        pyble.parse_string(config)

        pyble = pybles.PybleParser()
        config = "filter {input { foo { bar {} } }}"
        pyble.parse_string(config)


    def test_parse_directive(self):
        pyble = pybles.PybleParser()
        config = "filter { input { target; }}"

        pyble.parse_string(config)
        
        pyble = pybles.PybleParser()
        config = "filter { input { target option_name option_value;}}"
        pyble.parse_string(config)
        
        pyble = pybles.PybleParser()
        config = "filter { input { foo { target option_name option_value;}}}"
        pyble.parse_string(config)
        
        pyble = pybles.PybleParser()
        config = "filter { input { foo { target option_name option_value; bar {}}}}"
        pyble.parse_string(config)
        
        pyble = pybles.PybleParser()
        config = "filter { input { foo { target option_name option_value; bar { target option_name option_value; }}}}"
        pyble.parse_string(config)
        
    def test_parse_from_file(self):
        p = pybles.PybleParser()
        p.parse_file("%s/test.conf" % os.path.dirname(__file__))
