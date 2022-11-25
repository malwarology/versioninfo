# Copyright 2022 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Unit test versioninfo parser module."""
# import hashlib
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


class TestParserFunctionsBenign(unittest.TestCase):
    """Check each individual parsing function works against a known good Windows EXE."""

    def setUp(self):
        """Load testing resources from files."""
        self.csrss_win7 = THIS_DIR.joinpath('data').joinpath('cb1c60_csrss_win7.0x1798-0x1b30.dat').read_bytes()

    def test_benign_get_padding_one(self):
        """Test that the padding reader counts one padding WORD correctly."""
        expected = (1, 40, )

        output = versioninfo.parser.get_padding(self.csrss_win7, 38)

        self.assertTupleEqual(expected, output, 'Padding result tuple is not correct.')

    def test_benign_get_padding_zero(self):
        """Test that the padding reader counts zero padding WORD correctly."""
        expected = (0, 128, )

        output = versioninfo.parser.get_padding(self.csrss_win7, 128)

        self.assertTupleEqual(expected, output, 'Padding result tuple is not correct.')

    def test_benign_get_padding_at_end(self):
        """Test that the padding reader counts zero padding WORD correctly at the end of the data."""
        expected = (0, 920, )

        output = versioninfo.parser.get_padding(self.csrss_win7, 920)

        self.assertTupleEqual(expected, output, 'Padding result tuple is not correct.')

    def test_benign_get_wchar_one(self):
        """Test that the wchar reader returns correctly when there is one padding WORD."""
        expected = (
            b'V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00',
            'VS_VERSION_INFO',
            1,
            40,
        )

        output = versioninfo.parser.get_wchar(self.csrss_win7, 6)

        self.assertTupleEqual(expected, output, 'Output of wchar reader is not as expected.')

    def test_benign_get_wchar_zero(self):
        """Test that the wchar reader returns correctly when there is zero padding WORD."""
        expected = (
            b'S\x00t\x00r\x00i\x00n\x00g\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00',
            'StringFileInfo',
            0,
            128,
        )

        output = versioninfo.parser.get_wchar(self.csrss_win7, 98)

        self.assertTupleEqual(expected, output, 'Output of wchar reader is not as expected.')

    def test_benign_get_wchar_at_end(self):
        """Test that the wchar reader returns correctly at the end of the data."""
        expected = (b'', '', 0, 922, )

        output = versioninfo.parser.get_wchar(self.csrss_win7, 920)

        self.assertTupleEqual(expected, output, 'Output of wchar reader is not as expected.')

    def test_benign_header_vs_versioninfo(self):
        """Test the header parser on the VS_VERSION_INFO struct."""
        expected = {
            'wLength': 920,
            'wValueLength': 52,
            'wType': 0,
            'szKey': {
                'Value': {
                    'Bytes': b'V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00',
                    'Decoded': 'VS_VERSION_INFO'
                },
                'Standard': True
            },
            'Padding': 1
        }

        header, _ = versioninfo.parser.get_next_header(self.csrss_win7, 0, expected='VS_VERSION_INFO')

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_benign_header_vs_versioninfo_cursor(self):
        """Test the cursor after parsing the VS_VERSION_INFO struct."""
        _, cursor = versioninfo.parser.get_next_header(self.csrss_win7, 0, expected='VS_VERSION_INFO')

        self.assertEqual(40, cursor, 'Resulting cursor not as expected.')

    def test_benign_header_stringfileinfo(self):
        """Test the header parser on a StringFileInfo struct."""
        expected = {
            'wLength': 758,
            'wValueLength': 0,
            'wType': 1,
            'szKey': {
                'Value': {
                    'Bytes': b'S\x00t\x00r\x00i\x00n\x00g\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00',
                    'Decoded': 'StringFileInfo'
                },
                'Standard': True
            },
            'Padding': 0
        }

        header, _ = versioninfo.parser.get_next_header(self.csrss_win7, 92, expected='StringFileInfo')

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_benign_header_stringfileinfo_cursor(self):
        """Test the cursor after parsing the StringFileInfo struct."""
        _, cursor = versioninfo.parser.get_next_header(self.csrss_win7, 92, expected='StringFileInfo')

        self.assertEqual(128, cursor, 'Resulting cursor not as expected.')

    def test_benign_header_stringtable(self):
        """Test the header parser on a StringTable struct."""
        expected = {
            'wLength': 722,
            'wValueLength': 0,
            'wType': 1,
            'szKey': {
                'Value': {
                    'Bytes': b'0\x004\x000\x009\x000\x004\x00B\x000\x00',
                    'Decoded': '040904B0'
                }
            },
            'Padding': 0
        }

        header, _ = versioninfo.parser.get_next_header(self.csrss_win7, 128)

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_benign_header_stringtable_cursor(self):
        """Test the cursor after parsing the StringTable struct."""
        _, cursor = versioninfo.parser.get_next_header(self.csrss_win7, 128)

        self.assertEqual(152, cursor, 'Resulting cursor not as expected.')

    def test_benign_header_string_padding(self):
        """Test the header parser on a String struct with padding."""
        expected = {
            'wLength': 76,
            'wValueLength': 22,
            'wType': 1,
            'szKey': {
                'Value': {
                    'Bytes': b'C\x00o\x00m\x00p\x00a\x00n\x00y\x00N\x00a\x00m\x00e\x00',
                    'Decoded': 'CompanyName'
                }
            },
            'Padding': 1
        }

        header, _ = versioninfo.parser.get_next_header(self.csrss_win7, 152)

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_benign_header_string_padding_cursor(self):
        """Test the cursor after parsing the String struct with padding."""
        _, cursor = versioninfo.parser.get_next_header(self.csrss_win7, 152)

        self.assertEqual(184, cursor, 'Resulting cursor not as expected.')

    def test_benign_header_string_no_padding(self):
        """Test the header parser on a String struct with no padding."""
        expected = {
            'wLength': 52,
            'wValueLength': 10,
            'wType': 1,
            'szKey': {
                'Value': {
                    'Bytes': b'I\x00n\x00t\x00e\x00r\x00n\x00a\x00l\x00N\x00a\x00m\x00e\x00',
                    'Decoded': 'InternalName'
                }
            },
            'Padding': 0
        }

        header, _ = versioninfo.parser.get_next_header(self.csrss_win7, 436)

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_benign_header_string_no_padding_cursor(self):
        """Test the cursor after parsing the String struct with no padding."""
        _, cursor = versioninfo.parser.get_next_header(self.csrss_win7, 436)

        self.assertEqual(468, cursor, 'Resulting cursor not as expected.')

    def test_benign_header_varfileinfo(self):
        """Test the header parser on a VarFileInfo struct."""
        expected = {
            'wLength': 68,
            'wValueLength': 0,
            'wType': 1,
            'szKey': {
                'Value': {
                    'Bytes': b'V\x00a\x00r\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00',
                    'Decoded': 'VarFileInfo'
                },
                'Standard': True
            },
            'Padding': 1
        }

        header, _ = versioninfo.parser.get_next_header(self.csrss_win7, 852, expected='VarFileInfo')

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_benign_header_varfileinfo_cursor(self):
        """Test the cursor after parsing the VarFileInfo struct."""
        _, cursor = versioninfo.parser.get_next_header(self.csrss_win7, 852, expected='VarFileInfo')

        self.assertEqual(884, cursor, 'Resulting cursor not as expected.')

    def test_benign_header_var(self):
        """Test the header parser on a Var struct."""
        expected = {
            'wLength': 36,
            'wValueLength': 4,
            'wType': 0,
            'szKey': {
                'Value': {
                    'Bytes': b'T\x00r\x00a\x00n\x00s\x00l\x00a\x00t\x00i\x00o\x00n\x00',
                    'Decoded': 'Translation'
                },
                'Standard': True
            },
            'Padding': 1
        }

        header, _ = versioninfo.parser.get_next_header(self.csrss_win7, 884, expected='Translation')

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_benign_header_var_cursor(self):
        """Test the cursor after parsing the Var struct."""
        _, cursor = versioninfo.parser.get_next_header(self.csrss_win7, 884, expected='Translation')

        self.assertEqual(916, cursor, 'Resulting cursor not as expected.')

    def test_benign_get_ffi(self):
        """Test parsing of VS_FIXEDFILEINFO struct."""
        expected = {
            'Type': 'VS_FIXEDFILEINFO',
            'Struct': {
                'dwSignature': '0xfeef04bd',
                'dwStrucVersion': {
                    'major': 1,
                    'minor': 0
                },
                'dwFileVersionMS': 393217,
                'dwFileVersionLS': 498089985,
                'dwProductVersionMS': 393217,
                'dwProductVersionLS': 498089985,
                'dwFileFlagsMask': {
                    'Decimal': 63,
                    'Hexadecimal': '0x0000003f'
                },
                'dwFileFlags': {
                    'Decimal': 0,
                    'Hexadecimal': '0x00000000'
                },
                'dwFileOS': {
                    'Decimal': 262148,
                    'Hexadecimal': '0x00040004'
                },
                'dwFileType': {
                    'Decimal': 1,
                    'Hexadecimal': '0x00000001'
                },
                'dwFileSubtype': {
                    'Decimal': 0,
                    'Hexadecimal': '0x00000000'
                },
                'dwFileDateMS': 0,
                'dwFileDateLS': 0
            }
        }

        output, _ = versioninfo.parser.get_ffi(self.csrss_win7, 40)

        self.assertDictEqual(expected, output, 'Parsed VS_FIXEDFILEINFO structure not as expected.')

    def test_benign_get_ffi_cursor(self):
        """Test the cursor after parsing the VS_FIXEDFILEINFO struct."""
        _, cursor = versioninfo.parser.get_ffi(self.csrss_win7, 40)

        self.assertEqual(92, cursor, 'Resulting cursor not as expected.')

    def test_benign_get_fileinfo_type_stringfileinfo(self):
        """Test the FileInfo structure type determiner on StringFileInfo."""
        output = versioninfo.parser.get_fileinfo_type(self.csrss_win7, 92)

        self.assertEqual('StringFileInfo', output, 'Expected type for StringFileInfo not correct.')

    def test_benign_get_fileinfo_type_varfileinfo(self):
        """Test the FileInfo structure type determiner on VarFileInfo."""
        output = versioninfo.parser.get_fileinfo_type(self.csrss_win7, 852)

        self.assertEqual('VarFileInfo', output, 'Expected type for VarFileInfo not correct.')

    def test_benign_process_language_code(self):
        """Test the language code processor function."""
        expected = {
            'LangID': {
                'Hexadecimal': '0x0409',
                'Parsed': {
                    'MajorLanguage': '0b0000001001',
                    'SubLanguage': '0b000001'
                }
            },
            'CodePage': {
                'Decimal': 1200,
                'Hexadecimal': '0x04b0'
            }
        }

        output = versioninfo.parser.process_language_code((0x0409, 1200, ))

        self.assertDictEqual(expected, output, 'Language code processor output not as expected.')

    def test_benign_var_value_single_len(self):
        """Test the length of the output from the Var value parser on one Value."""
        output, _ = versioninfo.parser.get_var_value(self.csrss_win7, 916, 920)

        self.assertEqual(1, len(output), 'Length of the Var Value parser not as expected.')

    def test_benign_var_value_single(self):
        """Test the output from the Var value parser on one Value."""
        expected = {
            'Type': 'VarValue',
            'Struct': {
                'LangID': {
                    'Hexadecimal': '0x0409',
                    'Parsed': {
                        'MajorLanguage': '0b0000001001',
                        'SubLanguage': '0b000001'
                    }
                },
                'CodePage': {
                    'Decimal': 1200,
                    'Hexadecimal': '0x04b0'
                }
            }
        }

        output, _ = versioninfo.parser.get_var_value(self.csrss_win7, 916, 920)

        self.assertDictEqual(expected, next(iter(output)), 'The Var Value parser output not as expected.')

    def test_benign_var_value_single_cursor(self):
        """Test the cursor after parsing one Var Value."""
        end = 920
        _, cursor = versioninfo.parser.get_var_value(self.csrss_win7, 916, end)

        self.assertEqual(end, cursor, 'Resulting cursor not as expected.')


if __name__ == '__main__':
    unittest.main(verbosity=2)
