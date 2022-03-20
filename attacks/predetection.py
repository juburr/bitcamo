import array
import lief
from utils.os import get_code_section, text_section_exists

def bypass_predetection(bytez):
    patched = False
    binary = lief.PE.parse(list(bytez))

    section = get_code_section(binary)
    if section is None:
        print(f'   Unable to determine code section.')
        return bytez, False

    print(f'   Setting code section to: {section.name}')
    exists = text_section_exists(binary)
    print(f'   Does .text section exist: {exists}')

    gap = section.sizeof_raw_data - section.virtual_size
    print(f'   Slack space exists: {gap > 0}')
    if gap <= 0:
        return bytez, False

    # TODO: Make this a random byte to avoid defenders checking explicity
    # for 0x01. Don't use 0x00 or 0xCC though (likely the original byte value)
    section.content = section.content + list(b"\x01")

    # TODO: Remove? Does LIEF update the headers automatically?
    section.virtual_size = section.virtual_size + 1
    patched = True
    builder = lief.PE.Builder(binary)
    builder.build()
    print('   Executable has been patched.')
    return array.array('B', builder.get_build()).tobytes(), patched