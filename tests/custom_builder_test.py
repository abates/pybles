

import unittest
import pybles


class CustomFilterBuilder(pybles.DefaultBuilder):
    def __init__(self):
        self.close = []

    def input(self, path):
        return self

    def input_end(self, path):
        self.close.append(path[-1])
        return self

    def output(self, path):
        return self

    def accept(self, path, directive):
        assert(directive.path[0] == "filter")
        assert(directive.path[1] == "input")
        assert(directive.name == "accept")
        if (len(directive.options) > 0):
            assert(directive.options["option1"].name == "option1")
            assert(directive.options["option1"].value == "value1")
            assert(directive.options["option2"].name == "option2")
            assert(directive.options["option2"].value == "value2")

        for option in directive.options:
            assert(directive.options[option.name].value == option.value)

        return self;

    def default_build_block(self, path, directive=None):
        if (path[-1] == "forward"):
            return self
        else:
            if (directive is not None):
                raise pybles.InvalidDirective("Unknown directive %s" % directive.name)
            else:
                raise pybles.InvalidBlock("Unknown block %s" % path[-1])

    def default_build_block_end(self, path):
        self.close.append(path[-1])

class CustomTableBuilder(pybles.DefaultBuilder):
    def __init__(self):
        self.filter_builder = CustomFilterBuilder()

    def filter(self, *args):
        return self.filter_builder

class CustomBuilderTest(unittest.TestCase):
    def test_parsing_invalid_block(self):
        p = pybles.PybleParser(CustomTableBuilder())
        config = "foo {}"
        self.assertRaises(pybles.InvalidBlock, p.parse_string, config)

    def test_parsing_valid_block(self):
        p = pybles.PybleParser(CustomTableBuilder())
        config = "filter {}"
        p.parse_string(config)

    def test_parsing_nested_invalid_block(self):
        p = pybles.PybleParser(CustomTableBuilder())
        config = "filter { foo {} }"
        self.assertRaises(pybles.InvalidBlock, p.parse_string, config)

    def test_parsing_nested_valid_block(self):
        p = pybles.PybleParser(CustomTableBuilder())
        config = "filter { input {} }"
        p.parse_string(config)

    def test_parsing_invalid_directive(self):
        p = pybles.PybleParser(CustomTableBuilder())
        config = "filter { input { drop; } }"
        self.assertRaises(pybles.InvalidDirective, p.parse_string, config)

    def test_parsing_valid_directive(self):
        p = pybles.PybleParser(CustomTableBuilder())
        config = "filter { input { accept; } }"
        p.parse_string(config)

    def test_parsing_valid_directive_with_options(self):
        p = pybles.PybleParser(CustomTableBuilder())
        config = "filter { input { accept option1 value1 option2 value2; } }"
        p.parse_string(config)

    def test_default(self):
        p = pybles.PybleParser(CustomTableBuilder())
        config = "filter { forward {} }"
        p.parse_string(config)

    def test_block_close(self):
        b = CustomTableBuilder()
        p = pybles.PybleParser(b)
        config = "filter { input {} }"
        p.parse_string(config)
        self.assertEqual(b.filter_builder.close, ["input"])

    def test_default_close(self):
        b = CustomTableBuilder()
        p = pybles.PybleParser(b)
        config = "filter { forward {} }"
        p.parse_string(config)
        self.assertEqual(b.filter_builder.close, ["forward"])

