import hashlib
import lief
import os
import struct
import sys

def validate_output_directory(path):
    '''
    Verifies that the input path is an existing directory
    and that user has the ability to write to and list the
    contents of that directory (write and execute bits).

    Parameters
    ----------
    path : str
        A user-supplied path to a directory.

    bool
        A boolean signifying that its a valid, writable directory.
    '''
    if os.path.exists(path) == False:
        print(f'Output directory does not exist: {path}')
        return False
    if os.path.isdir(path) == False:
        print(f'Output path is not a directory: {path}')
        return False
    if os.access(path, os.W_OK | os.X_OK) == False:
        print(f'Output directory is not writable: {path}')
        return False
    return True

def is_pe_file(path):
    '''
    Verifies that the file at the given path is a Windows
    PE file.

    path : str
        A path to a file.

    bool
        A boolean signifying that the file is in Windows PE format.
    '''
    return lief.PE.parse(path) is not None

def read_file_bytes(filepath):
    '''
    Opens a file and returns its byte contents.
    
    Parameters
    ----------
    filepath : str
        The path to the file to open.

    Returns
    -------
    data: bytes
        The bytes contained within the file.
    '''
    with open(filepath, 'rb') as f:
        data = f.read()
    return data

def write_file_bytes(out_filepath, data):
    '''
    Writes bytes to an output file.
    
    Parameters
    ----------
    out_filepath : str
        The path to the output file.

    data : bytes
        The bytes that should be place in the file.
    '''
    with open(out_filepath, 'wb') as f:
        for b in data:
            f.write(struct.pack('B', int(b)))

def exit(code):
    '''
    Exits the program early.
    
    Parameters
    ----------
    code : int
        The exit code to return from the program.
    '''
    try:
        sys.exit(code)
    except SystemExit:
        os._exit(code)

def hash_bytes(bytez):
    '''
    Runs a SHA-256 hash on the input bytes. Running this function on
    the all bytes for a file is equivalent to running sha256sum on the
    command line and supplying the file name.
    
    Parameters
    ----------
    bytez : bytes
        The bytes to run the hash function on.

    Returns
    -------
    str
        The SHA-256 hash of the input bytes.
    '''
    h = hashlib.sha256()
    h.update(bytez)
    return h.hexdigest()

def section_bytes(file_bytes, section):
    '''
    Retreives the bytes for a desired section within the PE file.

    Parameters
    ----------
    file_bytes : bytes
        The bytes for the entire PE file.

    section : str
        The section to extract the bytes for.

    Returns
    -------
    bytes
        The bytes for the desired section in the PE file.
    '''
    binary = lief.PE.parse(list(file_bytes))
    section = binary.get_section(section)
    data = bytearray(section.content)
    return data

def section_hash(file_bytes, section):
    '''
    A convenience function for returning the SHA-256 hash for a
    given section of the PE file.

    Parameters
    ----------
    file_bytes : bytes
        The bytes for the entire PE file.

    section : str
        The section to extract the bytes for.

    Returns
    -------
    str
        The SHA-256 hash of the desired section in the PE file.
    '''
    return hash_bytes(section_bytes(file_bytes, section))

def get_code_section(binary):
    '''
    Determines the code section, as not all PE files honor the .text
    section as an entry point.

    Parameters
    ----------
    binary : lief.PE.Binary
        A LIEF representation of a Windows PE file.

    Returns
    -------
    lief.PE.Section
        A LIEF representation of the code section.
    '''
    try:
        # First try to determine section using BaseOfCode
        code_rva = binary.optional_header.baseof_code
        code_section = binary.section_from_rva(code_rva)
        return code_section
    except:
        try:
            # Then try using AddressOfEntryPoint
            code_rva = binary.optional_header.addressof_entrypoint
            code_section = binary.section_from_rva(code_rva)
            return code_section
        except:
            try:
                # Try the standard .text section if those methods don't work
                code_section = binary.get_section('.text')
                return code_section
            except:
                return None

def code_section_hash(file_bytes):
    '''
    A convenience function for returning the SHA-256 hash of the
    code section.

    Parameters
    ----------
    file_bytes : bytes
        The bytes for the entire PE file.

    Returns
    -------
    str
        The SHA-256 hash of the code section.

    section : str
        The name of the code section, determined by following the BaseOfCode field
    '''
    binary = lief.PE.parse(list(file_bytes))
    code_section = get_code_section(binary)

    if code_section is not None:
        data = bytearray(code_section.content)
        return hash_bytes(data), code_section.name
    else:
        hash = '0000000000000000000000000000000000000000000000000000000000000000'
        return hash, 'None'

def text_section_exists(binary):
    '''
    Determines if a .text section exists within the PE file.

    Parameters
    ----------
    binary : lief.PE.Binary
        A LIEF representation of a Windows PE file.

    Returns
    -------
    bool
        A boolean that represents whether a .text section exists.
    '''
    try:
        _ = binary.get_section('.text')
    except:
        return False
    return True