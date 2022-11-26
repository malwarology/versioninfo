# Copyright 2022 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Unit test versioninfo parser module."""
import json
import pathlib
import pickle
import struct
import unittest

import versioninfo.parser

THIS_DIR = pathlib.Path(__file__).parent


class TestHelpers(unittest.TestCase):
    """Check if the helper functions are working."""

    def tesT_convert_no_bytes(self):
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


class TestParserBenign(unittest.TestCase):
    """Check each individual parsing function works against a known good Windows EXEs."""

    def setUp(self):
        """Load testing resources from files."""
        # SHA256: cb1c6018fc5c15483ac5bb96e5c2e2e115bb0c0e1314837d77201bab37e8c03a
        self.csrss_win7 = THIS_DIR.joinpath('data').joinpath('cb1c60_csrss_win7.0x1798-0x1b30.dat').read_bytes()
        # SHA256: 2527978321a4f9c098f5c27aaf58f36edd3a62ffea85642831d47c2b2ccdd5cf
        self.wscwiz_intel = THIS_DIR.joinpath('data').joinpath('252797_wscwiz_intel.0x18840-0x18e30.dat').read_bytes()
        # SHA256: fc1d535307725e8d9020ed4d709ee92533bc5a2331ecdabf397e8ff18f5fd366
        filename = 'fc1d53_txkbci_alienware.0x3453a4-0x3458e4.dat'
        self.txkbci_alienware = THIS_DIR.joinpath('data').joinpath(filename).read_bytes()

    def test_get_padding_one(self):
        """Test that the padding reader counts one padding WORD correctly."""
        expected = (1, 40, )

        output = versioninfo.parser.get_padding(self.csrss_win7, 38)

        self.assertTupleEqual(expected, output, 'Padding result tuple is not correct.')

    def test_get_padding_zero(self):
        """Test that the padding reader counts zero padding WORD correctly."""
        expected = (0, 128, )

        output = versioninfo.parser.get_padding(self.csrss_win7, 128)

        self.assertTupleEqual(expected, output, 'Padding result tuple is not correct.')

    def test_get_padding_at_end(self):
        """Test that the padding reader counts zero padding WORD correctly at the end of the data."""
        expected = (0, 920, )

        output = versioninfo.parser.get_padding(self.csrss_win7, 920)

        self.assertTupleEqual(expected, output, 'Padding result tuple is not correct.')

    def test_get_padding_with_boundary(self):
        """Test that the padding reader counts zero padding WORD correctly with a boundary."""
        expected = (1, 1512, )

        output = versioninfo.parser.get_padding(self.wscwiz_intel, 1510, 1512)

        self.assertTupleEqual(expected, output, 'Padding result tuple is not correct.')

    def test_get_wchar_one(self):
        """Test that the wchar reader returns correctly when there is one padding WORD."""
        expected = {
            'Bytes': b'V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00',
            'Decoded': 'VS_VERSION_INFO'
        }

        parsed, _ = versioninfo.parser.get_wchar(self.csrss_win7, 6)

        self.assertDictEqual(expected, parsed, 'Parsed output of wchar reader is not as expected.')

    def test_get_wchar_one_cursor(self):
        """Test the cursor after running the wchar reader when there is one padding WORD."""
        _, cursor = versioninfo.parser.get_wchar(self.csrss_win7, 6)

        self.assertEqual(38, cursor, 'Resulting cursor not as expected.')

    def test_get_wchar_zero(self):
        """Test that the wchar reader returns correctly when there are zero padding WORDs."""
        expected = {
            'Bytes': b'S\x00t\x00r\x00i\x00n\x00g\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00',
            'Decoded': 'StringFileInfo'
        }

        parsed, _ = versioninfo.parser.get_wchar(self.csrss_win7, 98)

        self.assertDictEqual(expected, parsed, 'Parsed output of wchar reader is not as expected.')

    def test_get_wchar_zero_cursor(self):
        """Test the cursor after running the wchar reader when there are zero padding WORDs."""
        _, cursor = versioninfo.parser.get_wchar(self.csrss_win7, 98)

        self.assertEqual(128, cursor, 'Resulting cursor not as expected.')

    def test_get_wchar_at_end(self):
        """Test that the wchar reader returns correctly at the end of the data."""
        expected = ({'Bytes': b'', 'Decoded': ''}, 920)

        output = versioninfo.parser.get_wchar(self.csrss_win7, 920)

        self.assertTupleEqual(expected, output, 'Output of wchar reader is not as expected.')

    def test_get_header_vs_versioninfo(self):
        """Test the header parser on the VS_VERSION_INFO struct."""
        expected = {
            'wLength': 920,
            'wValueLength': 52,
            'wType': 0,
            'szKey': {
                'Bytes': b'V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00',
                'Decoded': 'VS_VERSION_INFO',
                'Standard': True
            },
            'Padding': 1
        }

        header, _ = versioninfo.parser.get_header(self.csrss_win7, 0, expected='VS_VERSION_INFO')

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_get_header_vs_versioninfo_cursor(self):
        """Test the cursor after parsing the VS_VERSION_INFO struct."""
        _, cursor = versioninfo.parser.get_header(self.csrss_win7, 0, expected='VS_VERSION_INFO')

        self.assertEqual(40, cursor, 'Resulting cursor not as expected.')

    def test_get_header_stringfileinfo(self):
        """Test the header parser on a StringFileInfo struct."""
        expected = {
            'wLength': 758,
            'wValueLength': 0,
            'wType': 1,
            'szKey': {
                'Bytes': b'S\x00t\x00r\x00i\x00n\x00g\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00',
                'Decoded': 'StringFileInfo',
                'Standard': True
            },
            'Padding': 0
        }

        header, _ = versioninfo.parser.get_header(self.csrss_win7, 92, expected='StringFileInfo')

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_get_header_stringfileinfo_cursor(self):
        """Test the cursor after parsing the StringFileInfo struct."""
        _, cursor = versioninfo.parser.get_header(self.csrss_win7, 92, expected='StringFileInfo')

        self.assertEqual(128, cursor, 'Resulting cursor not as expected.')

    def test_get_header_stringtable(self):
        """Test the header parser on a StringTable struct."""
        expected = {
            'wLength': 722,
            'wValueLength': 0,
            'wType': 1,
            'szKey': {
                'Bytes': b'0\x004\x000\x009\x000\x004\x00B\x000\x00',
                'Decoded': '040904B0'
            },
            'Padding': 0
        }

        header, _ = versioninfo.parser.get_header(self.csrss_win7, 128)

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_get_header_stringtable_cursor(self):
        """Test the cursor after parsing the StringTable struct."""
        _, cursor = versioninfo.parser.get_header(self.csrss_win7, 128)

        self.assertEqual(152, cursor, 'Resulting cursor not as expected.')

    def test_get_header_string_padding(self):
        """Test the header parser on a String struct with padding."""
        expected = {
            'wLength': 76,
            'wValueLength': 22,
            'wType': 1,
            'szKey': {
                'Bytes': b'C\x00o\x00m\x00p\x00a\x00n\x00y\x00N\x00a\x00m\x00e\x00',
                'Decoded': 'CompanyName'
            },
            'Padding': 1
        }

        header, _ = versioninfo.parser.get_header(self.csrss_win7, 152)

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_get_header_string_padding_cursor(self):
        """Test the cursor after parsing the String struct with padding."""
        _, cursor = versioninfo.parser.get_header(self.csrss_win7, 152)

        self.assertEqual(184, cursor, 'Resulting cursor not as expected.')

    def test_get_header_string_no_padding(self):
        """Test the header parser on a String struct with no padding."""
        expected = {
            'wLength': 52,
            'wValueLength': 10,
            'wType': 1,
            'szKey': {
                'Bytes': b'I\x00n\x00t\x00e\x00r\x00n\x00a\x00l\x00N\x00a\x00m\x00e\x00',
                'Decoded': 'InternalName'
            },
            'Padding': 0
        }

        header, _ = versioninfo.parser.get_header(self.csrss_win7, 436)

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_get_header_string_no_padding_cursor(self):
        """Test the cursor after parsing the String struct with no padding."""
        _, cursor = versioninfo.parser.get_header(self.csrss_win7, 436)

        self.assertEqual(468, cursor, 'Resulting cursor not as expected.')

    def test_get_header_varfileinfo(self):
        """Test the header parser on a VarFileInfo struct."""
        expected = {
            'wLength': 68,
            'wValueLength': 0,
            'wType': 1,
            'szKey': {
                'Bytes': b'V\x00a\x00r\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00',
                'Decoded': 'VarFileInfo',
                'Standard': True
            },
            'Padding': 1
        }

        header, _ = versioninfo.parser.get_header(self.csrss_win7, 852, expected='VarFileInfo')

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_get_header_varfileinfo_cursor(self):
        """Test the cursor after parsing the VarFileInfo struct."""
        _, cursor = versioninfo.parser.get_header(self.csrss_win7, 852, expected='VarFileInfo')

        self.assertEqual(884, cursor, 'Resulting cursor not as expected.')

    def test_get_header_var(self):
        """Test the header parser on a Var struct."""
        expected = {
            'wLength': 36,
            'wValueLength': 4,
            'wType': 0,
            'szKey': {
                'Bytes': b'T\x00r\x00a\x00n\x00s\x00l\x00a\x00t\x00i\x00o\x00n\x00',
                'Decoded': 'Translation',
                'Standard': True
            },
            'Padding': 1
        }

        header, _ = versioninfo.parser.get_header(self.csrss_win7, 884, expected='Translation')

        self.assertDictEqual(expected, header, 'Parsed header output not as expected.')

    def test_get_header_var_cursor(self):
        """Test the cursor after parsing the Var struct."""
        _, cursor = versioninfo.parser.get_header(self.csrss_win7, 884, expected='Translation')

        self.assertEqual(916, cursor, 'Resulting cursor not as expected.')

    def test_get_ffi(self):
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

    def test_get_ffi_cursor(self):
        """Test the cursor after parsing the VS_FIXEDFILEINFO struct."""
        _, cursor = versioninfo.parser.get_ffi(self.csrss_win7, 40)

        self.assertEqual(92, cursor, 'Resulting cursor not as expected.')

    def test_get_fileinfo_type_stringfileinfo(self):
        """Test the FileInfo structure type determiner on StringFileInfo."""
        output = versioninfo.parser.get_fileinfo_type(self.csrss_win7, 92)

        self.assertEqual('StringFileInfo', output, 'Expected type for StringFileInfo not correct.')

    def test_get_fileinfo_type_varfileinfo(self):
        """Test the FileInfo structure type determiner on VarFileInfo."""
        output = versioninfo.parser.get_fileinfo_type(self.csrss_win7, 852)

        self.assertEqual('VarFileInfo', output, 'Expected type for VarFileInfo not correct.')

    def test_process_language_code(self):
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

    def test_get_var_values_single_len(self):
        """Test the length of the output from the Var value parser on one Value."""
        output, _ = versioninfo.parser.get_var_values(self.csrss_win7, 916, 920)

        self.assertEqual(1, len(output), 'Length of the Var Value parser not as expected.')

    def test_get_var_values_two_len(self):
        """Test the length of the output from the Var value parser on two Values."""
        output, _ = versioninfo.parser.get_var_values(self.wscwiz_intel, 1512, 1520)

        self.assertEqual(2, len(output), 'Length of the Var Value parser not as expected.')

    def test_get_var_values_single(self):
        """Test the output from the Var value parser on one Value."""
        expected = {
            'Type': 'Value',
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

        output, _ = versioninfo.parser.get_var_values(self.csrss_win7, 916, 920)

        self.assertDictEqual(expected, next(iter(output)), 'The Var Value parser output not as expected.')

    def test_get_var_values_two(self):
        """Test the output from the Var value parser on two Values."""
        expected = [
            {
                'Type': 'Value',
                'Struct': {
                    'LangID': {
                        'Hexadecimal': '0x0000',
                        'Parsed': {
                            'MajorLanguage': '0b0000000000',
                            'SubLanguage': '0b000000'
                        }
                    },
                    'CodePage': {
                        'Decimal': 1200,
                        'Hexadecimal': '0x04b0'
                    }
                }
            },
            {
                'Type': 'Value',
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
        ]

        output, _ = versioninfo.parser.get_var_values(self.wscwiz_intel, 1512, 1520)
        for index, entry in enumerate(zip(expected, output)):
            with self.subTest(var_val=index):
                expected, output, = entry

                self.assertDictEqual(expected, output, 'The Var Value parser output not as expected.')

    def test_get_var_values_single_cursor(self):
        """Test the cursor after parsing one Var Value."""
        end = 920
        _, cursor = versioninfo.parser.get_var_values(self.csrss_win7, 916, end)

        self.assertEqual(end, cursor, 'Resulting cursor not as expected.')

    def test_get_var_values_two_cursor(self):
        """Test the cursor after parsing two Var Values."""
        end = 1520
        _, cursor = versioninfo.parser.get_var_values(self.wscwiz_intel, 1512, end)

        self.assertEqual(end, cursor, 'Resulting cursor not as expected.')

    def test_get_vars_single_len(self):
        """Test the length of the output from the Var parser on one Var."""
        output, _ = versioninfo.parser.get_vars(self.csrss_win7, 884, 920)

        self.assertEqual(1, len(output), 'Length of the Var parser output not as expected.')

    def test_get_vars_two_len(self):
        """Test the length of the output from the Var parser on two Vars."""
        output, _ = versioninfo.parser.get_vars(self.txkbci_alienware, 124, 196)

        self.assertEqual(2, len(output), 'Length of the Var parser output not as expected.')

    def test_get_vars_single(self):
        """Test the output from the Var value parser on one Var."""
        expected = {
            'Type': 'Var',
            'Struct': {
                'wLength': 36,
                'wValueLength': 4,
                'wType': 0,
                'szKey': {
                    'Bytes': b'T\x00r\x00a\x00n\x00s\x00l\x00a\x00t\x00i\x00o\x00n\x00',
                    'Decoded': 'Translation',
                    'Standard': True
                },
                'Padding': 1,
                'Value': [
                    {
                        'Type': 'Value',
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
                ]
            }
        }

        output, _ = versioninfo.parser.get_vars(self.csrss_win7, 884, 920)

        self.assertDictEqual(expected, next(iter(output)), 'The Var parser output not as expected.')

    def test_get_vars_two(self):
        """Test the output from the Var parser on two Vars."""
        expected = [
            {
                'Type': 'Var',
                'Struct': {
                    'wLength': 36,
                    'wValueLength': 4,
                    'wType': 0,
                    'szKey': {
                        'Bytes': b'T\x00r\x00a\x00n\x00s\x00l\x00a\x00t\x00i\x00o\x00n\x00',
                        'Decoded': 'Translation',
                        'Standard': True,
                    },
                    'Padding': 1,
                    'Value': [
                        {
                            'Type': 'Value',
                            'Struct': {
                                'LangID': {
                                    'Hexadecimal': '0x0409',
                                    'Parsed': {
                                        'MajorLanguage': '0b0000001001',
                                        'SubLanguage': '0b000001',
                                    },
                                },
                                'CodePage': {
                                    'Decimal': 1252,
                                    'Hexadecimal': '0x04e4'
                                },
                            },
                        }
                    ],
                },
            },
            {
                'Type': 'Var',
                'Struct': {
                    'wLength': 36,
                    'wValueLength': 4,
                    'wType': 0,
                    'szKey': {
                        'Bytes': b'T\x00r\x00a\x00n\x00s\x00l\x00a\x00t\x00i\x00o\x00n\x00',
                        'Decoded': 'Translation',
                        'Standard': True,
                    },
                    'Padding': 1,
                    'Value': [
                        {
                            'Type': 'Value',
                            'Struct': {
                                'LangID': {
                                    'Hexadecimal': '0x0411',
                                    'Parsed': {
                                        'MajorLanguage': '0b0000010001',
                                        'SubLanguage': '0b000001',
                                    },
                                },
                                'CodePage': {
                                    'Decimal': 1252,
                                    'Hexadecimal': '0x04e4'
                                },
                            },
                        }
                    ],
                },
            },
        ]

        output, _ = versioninfo.parser.get_vars(self.txkbci_alienware, 124, 196)
        for index, entry in enumerate(zip(expected, output)):
            with self.subTest(var_val=index):
                expected, output, = entry

                self.assertDictEqual(expected, output, 'The Var parser output not as expected.')

    def test_get_vars_single_cursor(self):
        """Test the cursor after parsing one Var."""
        end = 920
        _, cursor = versioninfo.parser.get_vars(self.csrss_win7, 884, end)

        self.assertEqual(end, cursor, 'Resulting cursor not as expected.')

    def test_get_vars_two_cursor(self):
        """Test the cursor after parsing two Vars."""
        end = 196
        _, cursor = versioninfo.parser.get_vars(self.txkbci_alienware, 124, end)

        self.assertEqual(end, cursor, 'Resulting cursor not as expected.')

    def test_get_varfileinfo(self):
        """Test the output from the VarFileInfo parser."""
        expected = {
            'Type': 'VarFileInfo',
            'Struct': {
                'wLength': 68,
                'wValueLength': 0,
                'wType': 1,
                'szKey': {
                    'Bytes': b'V\x00a\x00r\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00',
                    'Decoded': 'VarFileInfo',
                    'Standard': True,
                },
                'Padding': 1,
                'Children': [
                    {
                        'Type': 'Var',
                        'Struct': {
                            'wLength': 36,
                            'wValueLength': 4,
                            'wType': 0,
                            'szKey': {
                                'Bytes': b'T\x00r\x00a\x00n\x00s\x00l\x00a\x00t\x00i\x00o\x00n\x00',
                                'Decoded': 'Translation',
                                'Standard': True,
                            },
                            'Padding': 1,
                            'Value': [
                                {
                                    'Type': 'Value',
                                    'Struct': {
                                        'LangID': {
                                            'Hexadecimal': '0x0409',
                                            'Parsed': {
                                                'MajorLanguage': '0b0000001001',
                                                'SubLanguage': '0b000001',
                                            },
                                        },
                                        'CodePage': {
                                            'Decimal': 1200,
                                            'Hexadecimal': '0x04b0'
                                        },
                                    },
                                }
                            ],
                        },
                    }
                ],
            },
        }

        output, _ = versioninfo.parser.get_varfileinfo(self.csrss_win7, 852)

        self.assertDictEqual(expected, output, 'The VarFileInfo parser output not as expected.')

    def test_get_varfileinfo_cursor(self):
        """Test the cursor after parsing one VarFileInfo."""
        _, cursor = versioninfo.parser.get_varfileinfo(self.csrss_win7, 852)

        self.assertEqual(920, cursor, 'Resulting cursor not as expected.')

    def test_get_strings(self):
        """Test the output from the String parser."""
        # Pickle text content: test_get_strings_csrss_win7.txt
        expected_pickle = THIS_DIR.joinpath('data').joinpath('test_get_strings_csrss_win7.pickle')
        with open(expected_pickle, 'rb') as fh:
            expected = pickle.load(fh)

        output, _ = versioninfo.parser.get_strings(self.csrss_win7, 152, 852)

        self.assertListEqual(expected, output, 'The String parser output not as expected.')

    def test_get_strings_cursor(self):
        """Test the cursor after parsing array of String structures."""
        end = 852
        _, cursor = versioninfo.parser.get_strings(self.csrss_win7, 152, end)

        self.assertEqual(end, cursor, 'Resulting cursor not as expected.')

    def test_get_stringtables(self):
        """Test the output from the StringTable parser."""
        # Pickle text content: test_get_stringtables_csrss_win7.txt
        expected_pickle = THIS_DIR.joinpath('data').joinpath('test_get_stringtables_csrss_win7.pickle')
        with open(expected_pickle, 'rb') as fh:
            expected = pickle.load(fh)

        output, _ = versioninfo.parser.get_stringtables(self.csrss_win7, 128, 852)

        self.assertListEqual(expected, output, 'The StringTable parser output not as expected.')

    def test_get_stringtables_cursor(self):
        """Test the cursor after parsing array of StringTable structures."""
        end = 852
        _, cursor = versioninfo.parser.get_stringtables(self.csrss_win7, 128, end)

        self.assertEqual(end, cursor, 'Resulting cursor not as expected.')

    def test_get_stringtables_empty(self):
        """Test the output from the StringTable parser with an empty value."""
        # Pickle text content: test_get_stringtables_txkbci_alienware.txt
        expected_pickle = THIS_DIR.joinpath('data').joinpath('test_get_stringtables_txkbci_alienware.pickle')
        with open(expected_pickle, 'rb') as fh:
            expected = pickle.load(fh)

        output, _ = versioninfo.parser.get_stringtables(self.txkbci_alienware, 232, 1344)

        self.assertListEqual(expected, output, 'The StringTable parser output not as expected.')

    def test_get_stringtables_empty_cursor(self):
        """Test the cursor after parsing array of StringTable structures with an empty value."""
        end = 1344
        _, cursor = versioninfo.parser.get_stringtables(self.txkbci_alienware, 232, end)

        self.assertEqual(end, cursor, 'Resulting cursor not as expected.')

    def test_get_stringfileinfo(self):
        """Test the output from the StringFileInfo parser."""
        # Pickle text content: test_get_stringfileinfo_csrss_win7.txt
        expected_pickle = THIS_DIR.joinpath('data').joinpath('test_get_stringfileinfo_csrss_win7.pickle')
        with open(expected_pickle, 'rb') as fh:
            expected = pickle.load(fh)

        output, _ = versioninfo.parser.get_stringfileinfo(self.csrss_win7, 92)

        self.assertDictEqual(expected, output, 'The StringFileInfo parser output not as expected.')

    def test_get_stringfileinfo_cursor(self):
        """Test the cursor after parsing StringFileInfo structure."""
        _, cursor = versioninfo.parser.get_stringfileinfo(self.csrss_win7, 92)

        self.assertEqual(852, cursor, 'Resulting cursor not as expected.')

    def test_get_fileinfo_len(self):
        """Test the length of list after parsing FileInfo structures."""
        output = versioninfo.parser.get_fileinfo(self.csrss_win7, 92, 920)

        self.assertEqual(2, len(output), 'Length of the FileInfo parser output not as expected.')

    def test_get_fileinfo(self):
        """Test the output from the FileInfo parser."""
        # Pickle text content: test_get_fileinfo_csrss_win7.txt
        expected_pickle = THIS_DIR.joinpath('data').joinpath('test_get_fileinfo_csrss_win7.pickle')
        with open(expected_pickle, 'rb') as fh:
            expected = pickle.load(fh)

        output = versioninfo.parser.get_fileinfo(self.csrss_win7, 92, 920)

        self.assertListEqual(expected, output, 'The FileInfo parser output not as expected.')


class TestIssues(unittest.TestCase):
    """Check for closed issues on data that caused the issue."""

    def test_issue1(self):
        """Test handling of 0x0000 Language IDs."""
        wscwiz_intel = THIS_DIR.joinpath('data').joinpath('252797_wscwiz_intel.0x18840-0x18e30.dat').read_bytes()

        raised = False
        try:
            _ = versioninfo.parser.to_json(wscwiz_intel)
        except struct.error:
            raised = True

        self.assertFalse(raised, 'Problem with issue #1: Exception raised.')

    def test_issue2(self):
        """Test handling of StringTable with zero children."""
        filename = 'fc1d53_txkbci_alienware.0x3453a4-0x3458e4.dat'
        txkbci_alienware = THIS_DIR.joinpath('data').joinpath(filename).read_bytes()

        raised = False
        try:
            _ = versioninfo.parser.to_json(txkbci_alienware)
        except struct.error:
            raised = True

        self.assertFalse(raised, 'Problem with issue #1: Exception raised.')


if __name__ == '__main__':
    unittest.main(verbosity=2)
