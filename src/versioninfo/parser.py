# Copyright 2022 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Parsing functions and the JSON emitter."""
import base64
import json
import struct


def convert(entry):
    """Convert objects to JSON serializable formats."""
    if isinstance(entry, bytes):
        # Base64 is used rather than decoding so that the exact bytes are preserved.
        return base64.standard_b64encode(entry).decode()
    else:
        raise TypeError


def get_wchar(data, cursor):
    """Parse one WCHAR struct member string including trailing padding."""
    # Read from the data starting at the cursor by two-byte chunks. Stop at the null terminator.
    size = 2
    terminator = b'\x00\x00'
    wchars = list()
    for i in range(cursor, len(data), size):
        chunk = data[i:i+size]
        if chunk == terminator:
            break
        else:
            wchars.append(chunk)

    wchar_str = b''.join(wchars)
    decoded = wchar_str.decode('utf-16')

    # Advance the cursor to include the two bytes of the null terminator
    cursor += len(wchar_str) + 2

    # Count padding WORDs.
    pad_word = b'\x00\x00'
    padding = 0
    for i in range(cursor, len(data), size):
        chunk = data[i:i+size]
        if chunk != pad_word:
            break
        else:
            padding += 1

    cursor += padding * 2

    return wchar_str, decoded, padding, cursor


def get_next_header(data, cursor, expected=None):
    """Parse the header members that exist in each struct: wLength, wValueLength, wType, szKey, and Padding."""
    h_format = 'HHH'
    wlength, wvaluelength, wtype = struct.unpack_from(h_format, data, offset=cursor)
    h_struct = {
        'wLength': wlength,
        'wValueLength': wvaluelength,
        'wType': wtype
    }
    cursor += struct.calcsize(h_format)

    szkey, decoded, padding, cursor = get_wchar(data, cursor)

    standard = False
    parsed = None

    if expected is None:
        standard = None
    elif expected == 'StringTable':
        # StringTable has a big endian hex string DWORD containing language info in the WCHAR szKey.
        lang_id, code_page, = struct.unpack('!HH', bytes.fromhex(decoded))
        parsed = {
            'LanguageID': lang_id,
            'CodePageNum': code_page
        }
        standard = True
    elif expected == decoded:
        # This checks if the szKey content matches the expected, if it was included as an input parameter.
        standard = True

    h_struct['szKey'] = {
        'Value': {
            'Bytes': szkey,
            'Decoded': decoded
        }
    }

    if standard is not None:
        h_struct['szKey']['Standard'] = standard

    if parsed:
        h_struct['szKey']['Value']['Parsed'] = parsed

    # Number the padding memmber: VS_VERSIONINFO structure has Padding2 added later.
    if expected == 'VS_VERSION_INFO':
        h_struct['Padding1'] = padding
    else:
        h_struct['Padding'] = padding

    return h_struct, cursor


def get_ffi(data, cursor):
    """Parse a VS_FIXEDFILEINFO structure."""
    ffi_format = '4sHHIIII4sIIIIII'
    ffi = struct.unpack_from(ffi_format, data, cursor)

    (
        dwsignature, dwstrucversionls, dwstrucversionms, dwfileversionms, dwfileversionls,
        dwproductversionms, dwproductversionls, dwfileflagsmask, dwfileflags,
        dwfileos, dwfiletype, dwfilesubtype, dwfiledatems, dwfiledatels
    ) = ffi

    fixed_file_info = {
        'dwSignature': dwsignature.hex(),
        'dwStrucVersion': {
            'major': dwstrucversionms,
            'minor': dwstrucversionls
        },
        'dwFileVersionMS': dwfileversionms,
        'dwFileVersionLS': dwfileversionls,
        'dwProductVersionMS': dwproductversionms,
        'dwProductVersionLS': dwproductversionls,
        'dwFileFlagsMask': dwfileflagsmask.hex(),
        'dwFileFlags': dwfileflags,
        'dwFileOS': dwfileos,
        'dwFileType': dwfiletype,
        'dwFileSubtype': dwfilesubtype,
        'dwFileDateMS': dwfiledatems,
        'dwFileDateLS': dwfiledatels
    }

    cursor += struct.calcsize(ffi_format)

    meta = {
        'Type': 'VS_FIXEDFILEINFO',
        'Struct': fixed_file_info
    }

    return meta, cursor


def get_fileinfo_type(data, cursor):
    """Determine the type of the FileInfo struct based on the wValueLength member of the immediate child."""
    file_info, cursor = get_next_header(data, cursor)
    child_header, cursor = get_next_header(data, cursor)

    fileinfo_type = 'StringFileInfo' if not child_header['wValueLength'] else 'VarFileInfo'

    return fileinfo_type


def get_var_value(data, cursor, end):
    """Parse one Var value member with recursion."""
    var_value_format = 'HH'
    lang_id, code_page, = struct.unpack_from(var_value_format, data, offset=cursor)
    value = {
        'LanguageID': lang_id,
        'CodePageNum': code_page
    }

    cursor += struct.calcsize(var_value_format)

    meta = {
        'Type': 'VarValue',
        'Struct': value
    }

    if cursor >= end:
        return [meta], cursor
    else:
        children, cursor = get_var_value(data, cursor, end)
        children.insert(0, meta)
        return children, cursor


def get_var(data, cursor, end):
    """Parse one Var structure with recursion."""
    start = cursor
    var, cursor = get_next_header(data, cursor, expected='Translation')
    var_end = start + var['wLength']

    # The Value of Var is an array of DWORDs. Parse it recursively.
    var_children, cursor = get_var_value(data, cursor, var_end)
    var['Children'] = var_children

    meta = {
        'Type': 'Var',
        'Struct': var
    }

    if cursor >= end:
        return [meta], cursor
    else:
        children, cursor = get_var(data, cursor, end)
        children.insert(0, meta)
        return children, cursor


def get_varfileinfo(data, cursor):
    """Parse the outer VarFileInfo structure and call the recusive function that gets the Var children list."""
    start = cursor
    varfileinfo, cursor = get_next_header(data, cursor, expected='VarFileInfo')
    end = start + varfileinfo['wLength']

    # Children member of VarFileInfo struct is an array of Var structs. Parse it recursively.
    children, cursor = get_var(data, cursor, end)
    varfileinfo['Children'] = children

    meta = {
        'Type': 'VarFileInfo',
        'Struct': varfileinfo
    }

    return meta, cursor


def get_string(data, cursor, end):
    """Parse one String structure with recursion."""
    string_member, cursor = get_next_header(data, cursor)

    # Each String has only one Value member WCHAR.
    bytestring, decoded, padding, cursor = get_wchar(data, cursor)

    string_member['Value'] = {
        'Bytes': bytestring,
        'Decoded': decoded,
        'Padding': padding
    }

    meta = {
        'Type': 'String',
        'Struct': string_member
    }

    if cursor >= end:
        return [meta], cursor
    else:
        children, cursor = get_string(data, cursor, end)
        children.insert(0, meta)
        return children, cursor


def get_stringtable(data, cursor, end):
    """Parse one StringTable and call the recursive function that gets the String children list."""
    start = cursor
    stringtable, cursor = get_next_header(data, cursor, expected='StringTable')
    table_end = start + stringtable['wLength']

    # Children member of StringTable struct is an array of String structs. Parse it recursively.
    str_children, cursor = get_string(data, cursor, table_end)
    stringtable['Children'] = str_children

    meta = {
        'Type': 'StringTable',
        'Struct': stringtable
    }

    if cursor >= end:
        return [meta], cursor
    else:
        children, cursor = get_stringtable(data, cursor, end)
        children.insert(0, meta)
        return children, cursor


def get_stringfileinfo(data, cursor):
    """Parse outer StringFileInfo structure and call the recusive function that gets the StringTable children list."""
    start = cursor
    stringfileinfo, cursor = get_next_header(data, cursor, expected='StringFileInfo')
    end = start + stringfileinfo['wLength']

    # Children member of StringFileInfo struct is an array of StringTable structs. Parse it recursively.
    children, cursor = get_stringtable(data, cursor, end)
    stringfileinfo['Children'] = children

    meta = {
        'Type': 'StringFileInfo',
        'Struct': stringfileinfo
    }

    return meta, cursor


def get_fileinfo(data, cursor, end):
    """Parse one FileInfo structure, determine its type, and run the approproate parsing function with recursion."""
    fileinfo_type = get_fileinfo_type(data, cursor)

    if fileinfo_type == 'StringFileInfo':
        fileinfo, cursor = get_stringfileinfo(data, cursor)
    else:
        fileinfo, cursor = get_varfileinfo(data, cursor)

    if cursor >= end:
        return [fileinfo]
    else:
        children = get_fileinfo(data, cursor, end)
        children.insert(0, fileinfo)
        return children


def get_versioninfo(data, cursor):
    """Parse the outermost VS_VERSIONINFO structure."""
    vs_versioninfo, cursor = get_next_header(data, cursor, expected='VS_VERSION_INFO')
    end = vs_versioninfo['wLength']

    # If the wValueLength is zero, the VS_FIXEDFILEINFO does not exist.
    if vs_versioninfo['wValueLength'] == 52:
        fixed_file_info, cursor = get_ffi(data, cursor)
        vs_versioninfo['Value'] = fixed_file_info

    # Because VS_VERSION_INFO already has padding in the szKey member,
    # and VS_FIXEDFILEINFO is only DWORDs, this padding member cannot exist under any conditions.
    # If a file abuses the format of the structure, this hard-coding may need to be replaced.
    vs_versioninfo['Padding2'] = list()

    children = get_fileinfo(data, cursor, end)

    vs_versioninfo['Children'] = children

    meta = {
        'Type': 'VS_VERSION_INFO',
        'Struct': vs_versioninfo
    }

    return meta


def to_json(data):
    """Set the initial cursor and parse the data provided as input."""
    cursor = 0
    parsed = get_versioninfo(data, cursor)

    output = json.dumps(parsed, default=convert)

    return output
