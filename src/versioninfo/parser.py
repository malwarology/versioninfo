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
        return base64.standard_b64encode(entry).decode()
    else:
        raise TypeError


def get_wchar(data, cursor):
    """Parse one WCHAR struct member string including trailing padding."""
    str_bytes = list()

    for i in range(cursor, len(data), 2):
        chunk = data[i:i+2]
        if chunk == b'\x00\x00':
            break
        else:
            str_bytes.append(data[i:i+2])

    bytestring = b''.join(str_bytes)
    decoded = bytestring.decode('utf-16')

    cursor += len(bytestring) + 2

    padding = list()
    pad, = struct.unpack_from('H', data, offset=cursor)
    if pad == 0:
        padding.append(pad)

    cursor += len(padding) * 2

    return bytestring, decoded, padding, cursor


def get_next_header(data, cursor, expected=None, morepads=False):
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
        lang_id, code_page, = struct.unpack('!HH', bytes.fromhex(decoded))
        parsed = {
            'LanguageID': lang_id,
            'CodePageNum': code_page
        }
        standard = True
    elif expected == decoded:
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

    if morepads:
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
    vs_versioninfo, cursor = get_next_header(data, cursor, expected='VS_VERSION_INFO', morepads=True)
    end = vs_versioninfo['wLength']

    if vs_versioninfo['wValueLength'] == 52:
        fixed_file_info, cursor = get_ffi(data, cursor)
        vs_versioninfo['Value'] = fixed_file_info

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
