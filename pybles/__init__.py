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

import sys
import pyparsing
from pyparsing import OneOrMore, Word, Literal, alphas, alphanums, ParseException, ZeroOrMore, Optional, MatchFirst, Forward, Suppress, Group, Combine, dblQuotedString

# redefine this function since it makes debugging
# exceptions impossible
def pyble_trim_arity(func, maxargs=2):
    def wrapper(*args):
        return func(*args)
    return wrapper
pyparsing._trim_arity = pyble_trim_arity

class BuildException(BaseException):
    pass

class InvalidBlock(BaseException):
    pass

class InvalidDirective(BaseException):
    pass

class InvalidOption(BaseException):
    pass

class ParseError(BaseException):
    pass

class Options():
    def __init__(self, options):
        self.option_names = []
        self.options = {}
        for option in options:
            self.option_names.append(option.name)
            self.options[option.name] = Option(name=option.name, value=option.value)

    def __getitem__(self, name):
        return self.options[name]

    def __len__(self):
        return len(self.option_names)

    def __iter__(self):
        for name in self.option_names:
            yield self.options[name]

class Option():
    def __init__(self, name, value):
        self.name = name
        self.value = value

class Directive():
    def __init__(self, name, path=[], options=[]):
        self.name = name
        self.path = path
        self.options = options

class DefaultBuilder():
    def get_builder(self, name):
        if (hasattr(self, name)):
            return getattr(self, name)
        else:
            return None

    def execute_directive(self, directive):
        raise BuildException("execute_directive was not implemented for %s" % self.__class__.__name__)

    def __getitem__(self, name):
        return self.get_builder(name)

class PybleParser:
    def __init__(self, builder=None):
        pyble_name  = Word(alphanums + "-")

        option_value   = (Word(alphanums + ":-/,_") | dblQuotedString)
        option         = Group(pyble_name.setResultsName("name") + option_value.setResultsName("value"))
        options        = ZeroOrMore(option).setResultsName("options")
        directive_name = pyble_name.setResultsName("directive_name")
        directive      = directive_name + options + Literal(";")

        block_start    = pyble_name.setResultsName("block_start") + Suppress("{")
        block_end      = Suppress("}").setResultsName("block_end")
        block          = Forward()
        block          << block_start + ZeroOrMore(block | directive) + block_end

        directive.setParseAction(self.parse_directive)
        block_start.setParseAction(self.block_start)
        block_end.setParseAction(self.block_end)

        self.parser = OneOrMore(block)
        self.builder = builder
        self.reset()

    def reset(self):
        self.path = []
        self.stack = [self.builder]

    def parse_file(self, infile):
        self.reset()
        try:
            return self.parser.parseFile(infile, parseAll=True)
        except ParseException, pe:
            raise ParseError("%s" % pe)

    def parse_string(self, config):
        self.reset()
        try:
            return self.parser.parseString(config, parseAll=True)
        except ParseException, pe:
            raise ParseError("%s" % pe)

    def block_start(self, string, location, tokens):
        if (self.stack[-1] is not None):
            callback = self.stack[-1][tokens.block_start]
            if (callback is None):
                callback = self.stack[-1]["default_build_block"]

            if (callback):
                self.path.append(tokens.block_start)
                self.stack.append(callback(self.path))
            else:
                raise InvalidBlock("Cannot parse block %s with builder %s" % (string, self.stack[-1].__class__.__name__))
        return []

    def block_end(self, string, location, tokens):
        # never never never pop off the base builder, if you do
        # then the builder loses its anchor and if the parse tree
        # ends up at the root of the object then needs to
        # traverse back down it will have no builder object to
        # attempt and handle
        # Best described pictorially :)
        #
        # config {
        #   firewall {
        #     rule1;
        #     rule2;
        #     rule3;
        #   }
        # }
        #
        # config {
        #   network {
        #     interface {
        #       directive1;
        #     }
        #   }
        # }
        #
        # If we were to pop off the builder when the first
        # config block closes, then we no longer have access
        # to it when the second config block opens
        # 
        if (len(self.stack) > 1):
            block_name = self.path[-1]
            self.stack.pop()
            callback = self.stack[-1]["%s_end" % block_name]
            if (callback is None):
                callback = self.stack[-1]["default_build_block_end"]

            if (callback):
                callback(self.path)

            self.path.pop()
        return []

    def parse_directive(self, string, location, tokens):
        if (self.stack[-1]):
            callback = self.stack[-1][tokens.directive_name]
            if (callback is None):
                callback = self.stack[-1]["default_build_directive"]

            if (callback):
                options = Options(tokens.options)
                directive = Directive(name = tokens.directive_name, path = self.path, options = options)
                return callback(self.path, directive)
            else:
                raise InvalidDirective("Cannot parse directive %s:" % string)
