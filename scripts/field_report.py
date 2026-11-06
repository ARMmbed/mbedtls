#!/usr/bin/env python3
"""Report on structure types defined in C source files.

This script uses the clang python bindings (``pip3 install --user clang``).

This script only works on code that compiles. If there are any errors,
this script will just return garbage data (typically missing fields, or
having 0 values everywhere). The most common cause of failure is missing
include directories, either for the code you're analyzing or for the
standard library when cross-compiling.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import collections
import re
import sys
from typing import Dict, List, Optional

import clang.cindex #type: ignore
from clang.cindex import Cursor, SourceLocation, TranslationUnit
from clang.cindex import CursorKind, TypeKind

from mbedtls_dev import typing_util


class SanityCheck(Exception):
    def __init__(self, msg: str) -> None:
        super().__init__('Sanity check failed: ' + msg +
                         '\nThis likely indicates a compilation error.' +
                         '\nMaybe a missing include directory (-I)?')



class FieldInfo:
    """Information about a field of a structure."""

    def __init__(self, node: Cursor) -> None:
        self.node = node
        self.lexical_uses = 0
        self.size = node.type.get_size()
        self.align = node.type.get_align()
        # Empirically, offsetof is in bits, not bytes. To make the output
        # easier to read, convert to bytes (the same unit as size and
        # alignment), which means that bitfields will be located at their
        # first byte.
        self.offset = node.get_field_offsetof() // 8

    def name(self) -> str:
        return self.node.spelling

    def record_use(self, _node: Cursor) -> None:
        self.lexical_uses += 1

    def uses(self) -> int:
        return self.lexical_uses

    def is_indirect(self) -> bool:
        """Whether access to this field is indirect on ARM Cortex-M0+."""
        word_offset = self.offset // self.align
        return word_offset >= 128

    def score(self) -> int:
        """A field's score is an estimate of its access cost.

        The cost is calculated as the number of instructions needed to
        access the field on ARM Cortex-M0+, multiplied by the number of uses
        of the field inside the library.
        """
        cost_per_use = 1 + 2 * self.is_indirect()
        return self.uses() * cost_per_use


class Ast:
    """Abstract representation of the source code."""

    def __init__(self, options) -> None:
        """Prepare for analysis of C source files."""
        if options.clang_library_file:
            clang.cindex.Config.set_library_file(options.clang_library_file)
        self.parse_options = []
        if options.target:
            self.parse_options += ['-target', options.target]
        for d in options.include:
            self.parse_options.append('-I' + d)
        for d in options.define:
            self.parse_options.append('-D' + d)
        self.index = clang.cindex.Index.create()
        self.files = {} #type: Dict[str, TranslationUnit]
        # fields[TYPE_OR_STRUCT_NAME][FIELD_NAME]
        self.fields = {} #type: Dict[str, Dict[str, FieldInfo]]

    def load(self, *filenames: str) -> None:
        """Load the AST of the given source files."""
        for filename in filenames:
            self.files[filename] = self.index.parse(filename,
                                                    self.parse_options)

    def in_interesting_file(self, location: SourceLocation) -> bool:
        """Whether the given location is in a file that should be analyzed."""
        if not hasattr(location.file, 'name'):
            # Some artificial nodes have associated no file name.
            # Let's hope they're not important.
            return False
        return location.file.name in self.files

    def read_field_definitions(self, filenames: List[str]) -> None:
        """Parse structure field definitions in the given C source files (usually headers)."""
        self.load(*filenames)
        for filename in filenames:
            for node in self.files[filename].cursor.walk_preorder():
                if not self.in_interesting_file(node.location):
                    continue
                if node.kind == CursorKind.FIELD_DECL:
                    type_name = node.lexical_parent.spelling
                    # Skip unions
                    if node.lexical_parent.kind != CursorKind.STRUCT_DECL:
                        continue
                    # type_name is the struct name. If there's no struct
                    # name, see if there's a typedef name, to cope with
                    # "typedef struct { ... } foo;"
                    if not type_name:
                        type_name = node.lexical_parent.type.spelling
                    # Skip anonymous structs for now.
                    if '(anonymous ' in type_name:
                        continue
                    self.fields.setdefault(type_name, collections.OrderedDict())
                    self.fields[type_name][node.spelling] = FieldInfo(node)

    @staticmethod
    def get_underlying_type(typ: clang.cindex.Type) -> Optional[clang.cindex.Type]:
        """Strip off one level of type indirection.

        Return None if the type is as primitive as can be.
        """
        if hasattr(typ, 'get_canonical'):
            lower = typ.get_canonical()
            if lower != typ:
                return lower
        if typ.kind == TypeKind.POINTER:
            return typ.get_pointee()
        if hasattr(typ, 'underlying_typedef_type'):
            return typ.underlying_typedef_type
        return None

    QUALIFIERS_RE = re.compile(r'.* ')
    def get_type_core(self, type: clang.cindex.Type) -> str:
        # pylint: disable=redefined-builtin
        """Get the base name of a type, without typedefs, qualifiers or pointers."""
        core = type
        lower = type # type: Optional[clang.cindex.Type]
        while lower:
            core, lower = lower, self.get_underlying_type(core)
        # There's no API function to remove qualifiers from a type,
        # so do it textually. Remove 'const', 'restrict', etc.
        # Also remove 'struct', so we'll get the struct name from struct
        # definitions.
        return re.sub(self.QUALIFIERS_RE, r'', core.spelling)

    def record_field_access(self, node: Cursor) -> None:
        """Record one location where a field is accessed."""
        field_name = node.spelling
        lhs = next(node.get_children())
        structure_type = self.get_type_core(lhs.type)
        if structure_type not in self.fields:
            # This is not a structure defined by the library
            return
        self.fields[structure_type][field_name].record_use(node)

    def sanity_check_failed(self, log: Optional[typing_util.Writable],
                            fmt: str, *args, **kwargs) -> None:
        #pylint: disable=no-self-use,no-else-raise
        msg = fmt.format(*args, **kwargs)
        if log is None:
            raise SanityCheck(msg)
        else:
            log.write('Warning: ' + msg + '\n')

    def sanity_checks(self, log: Optional[typing_util.Writable]) -> None:
        """If the data looks wrong, signal it.

        If `log` is `None`, signaling means to raise an exception explaining
        the first failure encountered. Otherwise signaling means calling
        `log.write` with a message for each failure.
        """
        for type_name in sorted(self.fields):
            for field in self.fields[type_name].values():
                if field.offset == -1:
                    self.sanity_check_failed(
                        log,
                        'Could not determine offset of {}.{}.',
                        type_name, field.name())

    def run_analysis(self, files: List[str],
                     log: Optional[typing_util.Writable] = None) -> None:
        """Run analyses on the specified files.

        Pass `log` to `sanity_checks`.
        """
        self.read_field_definitions(files)
        self.read_field_usage(files)
        self.sanity_checks(log)

    def read_field_usage(self, filenames: List[str]) -> None:
        """Parse field usage in the given C source files."""
        self.load(*filenames)
        for filename in filenames:
            for node in self.files[filename].cursor.walk_preorder():
                if not self.in_interesting_file(node.location):
                    continue
                if node.kind == CursorKind.MEMBER_REF_EXPR:
                    self.record_field_access(node)

    @staticmethod
    def report_field(out: typing_util.Writable,
                     prefix: str, field: FieldInfo) -> None:
        """Print information about a structure field.

        Format: <type>.<name>,<size>,<alignment>,<offset>,<use_count>,<score>
        """
        out.write('{},{},{},{},{},{}\n'.format(
            prefix + field.node.spelling,
            field.size, field.align, field.offset,
            field.uses(), field.score()
        ))

    def report_fields(self, out: typing_util.Writable,
                      header=False) -> None:
        """Print information about fields of structures defined by the library."""
        if header:
            out.write('field,size,align,offset,uses,score\n')
        for type_name in sorted(self.fields):
            for field in self.fields[type_name].values():
                self.report_field(out, type_name + '.', field)

    def report(self, options, out: typing_util.Writable) -> None:
        """Report what this script has to report."""
        self.report_fields(out,
                           header=options.csv_header)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang-library-file',
                        help="Alternative location of libclang.so")
    parser.add_argument('--define', '-D',
                        action='append',
                        default=[],
                        help="Additional C preprocessor definition")
    parser.add_argument('--include', '-I',
                        action='append',
                        default=[],
                        help="Directory to add to the header include path")
    parser.add_argument('--no-csv-header',
                        dest='csv_header', default=True, action='store_false',
                        help="Omit the CSV header from the output")
    parser.add_argument('--no-sanity-checks',
                        dest='sanity_checks', default=True, action='store_false',
                        help="Bypass sanity checks, print output even if it's suspicious")
    parser.add_argument('--target', '-t',
                        help="Target triple to build for (default: native build)")
    parser.add_argument('files', metavar='FILE', nargs='*',
                        help="Source files to analyze")
    options = parser.parse_args()
    ast = Ast(options)
    if options.sanity_checks:
        sanity_log = None
    else:
        sanity_log = sys.stderr
    ast.run_analysis(options.files, log=sanity_log)
    ast.report(options, sys.stdout)

if __name__ == '__main__':
    main()
