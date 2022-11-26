import "console"
import "pe"

private rule WindowsPE
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule NonStandard_StringFileInfo_Key
{
    meta:
        author = "Malwarology LLC"
        date = "2022-11-20"
        description = "Detects non-standard szKey members of StringFileInfo structure PE version info resources."
        reference = "https://malwarology.substack.com/"
        documentation = "https://learn.microsoft.com/en-us/windows/win32/menurc/stringfileinfo"
        sharing = "TLP:CLEAR"
        exemplar = "fc04e80d343f5929aea4aac77fb12485c7b07b3a3d2fc383d68912c9ad0666da"
    strings:
        $a = "StringFileInfo" private wide
    condition:
        for any resource in pe.resources : (
            resource.type == 16 and
            uint8(resource.offset + 126) != 0x0 and
            for 1 i in (1..#a) : (
                @a[i] == resource.offset + 98
            )
        )
}

rule Two_RT_VERSION
{
    meta:
        author = "Malwarology LLC"
        date = "2022-11-24"
        description = "Detects PE files with two RT_VERSION type resource directory entries. These are assumed to be corrupt."
    condition:
        pe.number_of_resources > 0 and
        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address != 0 and
        uint16(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address) + 12) < 20 and
        uint16(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address) + 14) < 20 and
        for 2 i in (0..uint16(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address) + 14)-1) : (
            16 == (uint32(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address) + 16 + (uint16(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address) + 12) * 8) + i*8))
        )
}

/*

names = uint16(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address) + 12)
ids = uint16(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address) + 14)

start = pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address) + 16 + (names * 8)

start = pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address) + 16 + (uint16(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address) + 12) * 8)

ids > 1 and
for 1 i in (0..ids-1) : (
    uint32(start + i*8)
)

*/

rule NoFixedFileInfo
{
    meta:
        author = "Malwarology LLC"
        date = "2022-11-25"
        description = "Detects PE files with no VS_FIXEDFILEINFO structure."
    strings:
        $a = { 0000 ( 0000 | 0100 ) 56005300 5F005600 45005200 53004900 4F004E00 5F004900 4E004600 4F000000 0000  }
    condition:
        WindowsPE and $a
}

rule TwoVars
{
    meta:
        author = "Malwarology LLC"
        date = "2022-11-25"
        description = "Detects PE files with an array of two Var structures."
    strings:
        $a = { 24000400 00005400 72006100 6E007300 6C006100 74006900 6F006E00 00000000 ????????
               24000400 00005400 72006100 6E007300 6C006100 74006900 6F006E00 00000000 ???????? }
    condition:
        WindowsPE and $a
}
