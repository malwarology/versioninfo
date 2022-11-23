# Copyright 2022 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Unit test versioninfo parser module."""
import hashlib
import json
import pathlib
import unittest

import versioninfo.parser

THIS_DIR = pathlib.Path(__file__).parent


class TestHelpers(unittest.TestCase):
    """Check if the helper functions are working."""

    def test_convert_no_bytes(self):
        """Test that the JSON serialization converter works with no bytes present."""
        testdict = {
            'A': '1',
            'B': '2'
        }
        expected = '{"A": "1", "B": "2"}'

        output = json.dumps(testdict, default=versioninfo.parser.convert)

        self.assertEqual(expected, output, 'Output from JSON conversion not as expected.')

    def test_convert_bytes(self):
        """Test that the JSON serialization converter works with bytes present."""
        testdict = {
            'A': b'1',
            'B': b'2'
        }
        expected = '{"A": "MQ==", "B": "Mg=="}'

        output = json.dumps(testdict, default=versioninfo.parser.convert)

        self.assertEqual(expected, output, 'Output from JSON conversion not as expected.')

    def test_convert_fail(self):
        """Test that the JSON serialization converter fails on unknown types."""
        class Foo:
            pass

        testdict = {
            'A': Foo()
        }

        with self.assertRaises(TypeError, msg='Expected TypeError was not raised.'):
            _ = json.dumps(testdict, default=versioninfo.parser.convert)


class TestParseAPI(unittest.TestCase):
    """Check if the public parser function works against test data."""

    def setUp(self):
        """Instantiate the class for testing."""
        # This VS_VERSIONINFO structure is from
        # fc04e80d343f5929aea4aac77fb12485c7b07b3a3d2fc383d68912c9ad0666da
        self.input_fc04e8 = THIS_DIR.joinpath('data').joinpath('fc04e8.0x37e18-0x38004.dat').read_bytes()
        self.input_31fb24 = THIS_DIR.joinpath('data').joinpath('31fb24.0x5158c-0x51708.dat').read_bytes()
        self.input_98629c = THIS_DIR.joinpath('data').joinpath('98629c.0x4858c-0x48d94.dat').read_bytes()

    def test_fc04e8_content(self):
        """Test that the data used for subsequent tests is as expected."""
        expected = '0ce97c2ad9aa2f320b1a7edb9d590bf388b3ae69980ebbad3dcd8a720bb82209'

        sha256 = hashlib.sha256(self.input_fc04e8).hexdigest()

        self.assertEqual(expected, sha256, 'Hash of test data does not match.')

    def test_fc04e8(self):
        """Test that the parser works against the RT_VERSION resource from fc04e8."""
        expected = THIS_DIR.joinpath('data').joinpath('fc04e8.0x37e18-0x38004.json').read_text()

        output = versioninfo.parser.to_json(self.input_fc04e8)

        self.assertEqual(expected, output, 'Output from public parser function not as expected: fc04e8')

    def test_31fb24(self):
        """Test that the parser works against the RT_VERSION resource from 31fb24."""
        expected = THIS_DIR.joinpath('data').joinpath('31fb24.0x5158c-0x51708.json').read_text()

        output = versioninfo.parser.to_json(self.input_31fb24)

        self.assertEqual(expected, output, 'Output from public parser function not as expected: 31fb24')

    def test_98629c(self):
        """Test that the parser works against the RT_VERSION resource from 98629c."""
        expected = THIS_DIR.joinpath('data').joinpath('98629c.0x4858c-0x48d94.json').read_text()

        output = versioninfo.parser.to_json(self.input_98629c)

        self.assertEqual(expected, output, 'Output from public parser function not as expected: 98629c')


class TestParsingFunctions(unittest.TestCase):
    """Check if each of the parsing functions works against test data."""

    def setUp(self):
        """Instantiate the class for testing."""
        # This VS_VERSIONINFO structure is from
        # fc04e80d343f5929aea4aac77fb12485c7b07b3a3d2fc383d68912c9ad0666da
        self.input_fc04e8 = THIS_DIR.joinpath('data').joinpath('fc04e8.0x37e18-0x38004.dat').read_bytes()
        self.input_31fb24 = THIS_DIR.joinpath('data').joinpath('31fb24.0x5158c-0x51708.dat').read_bytes()

    def test_get_wchar(self):
        """Test that the function is able to parse one WCHAR and return the expected output."""
        expected = (
            b'S\x00t\x00r\x00i\x00n\x00g\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00r\x00m\x00',
            'StringFileInform',
            [],
            132
        )

        output = versioninfo.parser.get_wchar(self.input_fc04e8, 98)

        self.assertTupleEqual(expected, output, msg='Output from get_wchar not as expected.')

    def test_get_wchar_pads(self):
        """Test that the function is able to parse one WCHAR and return the expected output includes padding."""
        expected = (
            b'F\x00i\x00l\x00e\x00D\x00e\x00s\x00c\x00r\x00i\x00p\x00t\x00i\x00o\x00n\x00',
            'FileDescription',
            [0],
            192
        )

        output = versioninfo.parser.get_wchar(self.input_31fb24, 158)

        self.assertTupleEqual(expected, output, msg='Output from get_wchar not as expected.')


if __name__ == '__main__':
    unittest.main(verbosity=2)
