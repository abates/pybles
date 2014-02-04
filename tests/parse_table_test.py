

import unittest
import pybles


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
        return
        pyble = pybles.PybleParser()
        config = "filter { input { target;}}"

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
        
