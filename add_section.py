import os
import sys
import struct
import binascii

NULL_BYTE = "\x00"

#Section characteristic constants
IMAGE_SCN_TYPE_NO_PAD = 0x00000008
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_LNK_INFO = 0x00000200
IMAGE_SCN_LNK_REMOVE = 0x00000800
IMAGE_SCN_LNK_COMDAT = 0x00001000
IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000
IMAGE_SCN_GPREL = 0x00008000
IMAGE_SCN_ALIGN_1BYTES = 0x00100000
IMAGE_SCN_ALIGN_2BYTES = 0x00200000
IMAGE_SCN_ALIGN_4BYTES = 0x00300000
IMAGE_SCN_ALIGN_8BYTES = 0x00400000
IMAGE_SCN_ALIGN_16BYTES = 0x00500000
IMAGE_SCN_ALIGN_32BYTES = 0x00600000
IMAGE_SCN_ALIGN_64BYTES = 0x00700000
IMAGE_SCN_ALIGN_128BYTES = 0x00800000
IMAGE_SCN_ALIGN_256BYTES = 0x00900000
IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

#Indexes for IMAGE_DATA_DIRECTORY
IMAGE_DIRECTORY_ENTRY_EXPORT         =  0
IMAGE_DIRECTORY_ENTRY_IMPORT         =  1
IMAGE_DIRECTORY_ENTRY_RESOURCE       =  2
IMAGE_DIRECTORY_ENTRY_EXCEPTION      =  3
IMAGE_DIRECTORY_ENTRY_SECURITY       =  4
IMAGE_DIRECTORY_ENTRY_BASERELOC      =  5
IMAGE_DIRECTORY_ENTRY_DEBUG          =  6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   =  7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR      =  8
IMAGE_DIRECTORY_ENTRY_TLS            =  9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11
IMAGE_DIRECTORY_ENTRY_IAT            = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

#Size constants
SIZE_IMAGE_SECTION_HEADER = 0x28
SIZE_IMAGE_NT_HEADER = 0x18
SIZE_DATA_DIRECTORY = 0x8
SIZE_ISH_NAME = 0x8

#Structure offsets
#IMAGE_NT_HEADER
OFF_INTH_NumberOfSections = 0x6
OFF_INTH_SizeOptionalHdr = 0x14
#IMAGE_OPTIONAL_HEADER
OFF_IOH_SectionAlignment = 0x20
OFF_IOH_FileAlignment = 0x24
OFF_IOH_SizeOfImage = 0x38
OFF_IOH_SizeOfHeaders = 0x3C
OFF_IOH_Checksum = 0x40
OFF_IOH_DataDirectories = 0x70
#IMAGE_DOS_HEADER
OFF_IDH_eLFANew = 0x3C
#IMAGE_SECTION_HEADER
OFF_SH_Miscellaneous = 0x8
OFF_SH_VirtualAddress = 0xC
OFF_SH_SizeOfRawData = 0x10
OFF_SH_PointerToRawData = 0x14
OFF_SH_PointerToRelocations = 0x18
OFF_SH_PointerToLineNumbers = 0x1C
OFF_SH_NumberOfRelocations = 0x20
OFF_SH_NumberOfLineNumbers = 0x22
OFF_SH_Characteristics = 0x24



def get_ledword(buffer, offset):
    """
    A function to retrieve a little endian 32-bit value from a byte buffer as a python long

    :param buffer: the string buffer to pull from
    :param offset: the offset into the string buffer to pull from
    :return: the little endian 32-bit value in a native python format
    """
    dd_val = struct.unpack("<L", buffer[offset:offset+4])[0]
    return dd_val

def get_leword(buffer, offset):
    """
    A function to retrieve a little endian 16-bit value from a byte buffer as a python long

    :param buffer: the string buffer to pull from
    :param offset: the offset into the string buffer to pull from
    :return: the little endian 32-bit value in a native python format
    """
    dw_val = struct.unpack("<H", buffer[offset:offset+2])[0]
    return dw_val

def shift_leword(buffer, offset, value):
    """
    A function to add a delta to a little endian 16-bit value inside a buffer

    :param buffer: the buffer that contains the 16-bit value
    :param offset: the offset into the buffer for the 16-bit value
    :param value: the value to add to the 16-bit value
    :return: the buffer with the 16-bit value changed
    """
    dw_val = struct.unpack("<H", buffer[offset:offset+2])[0]
    dw_val += value
    buffer = buffer[0:offset] + struct.pack("<H", dw_val) + buffer[offset+2:]
    return buffer

def shift_ledword(buffer, offset, value):
    """
    A function to add a delta to a little endian 32-bit value inside a buffer

    :param buffer: the buffer that contains the 32-bit value
    :param offset: the offset into the buffer for the 32-bit value
    :param value: the value (delta) to add to the 32-bit value
    :return: the buffer with the 32-bit value changed
    """
    dd_val = struct.unpack("<L", buffer[offset:offset+4])[0]
    dd_val += value
    buffer = buffer[0:offset] + struct.pack("<L", dd_val) + buffer[offset+4:]
    return buffer

def write_ledword(buffer, offset, value):
    """
    A function to write a little endian 32-bit value into a buffer

    :param buffer: The buffer that contains the old 32-bit value
    :param offset: The offset for the old 32-bit value
    :param value: The new value for the 32-bit value
    :return: the buffer with the 32-bit value changed
    """
    buffer = buffer[0:offset] + struct.pack("<L", value) + buffer[offset+4:]
    return buffer

def get_data_dir(buffer, index):
    """
    A function to retrieve a PE data directory as a dictionary

    :param buffer: The buffer beginning with the nt signature
    :param index: The index for the data directory
    :return: A dictionary with the values unpacked
    """
    offset = SIZE_IMAGE_NT_HEADER + OFF_IOH_DataDirectories + ( index * SIZE_DATA_DIRECTORY )
    virtualaddress = get_ledword(buffer, offset)
    size = get_ledword(buffer, offset+4)
    ret_dict = {
        "virtualaddress": virtualaddress,
        "size": size,
    }
    return ret_dict

def shift_data_dir(buffer, index, value):
    """
    A function to shift the virtual address of a data directory

    :param buffer: The buffer beginning with the nt signature
    :param index: The index of the data directory
    :param value: The value (delta) to add to the virtual address
    :return:
    """
    offset = SIZE_IMAGE_NT_HEADER + OFF_IOH_DataDirectories + ( index * SIZE_DATA_DIRECTORY )
    virtualaddress = get_ledword(buffer, offset)
    virtualaddress += value
    buffer = buffer[0:offset] + struct.pack("<L", virtualaddress) + buffer[offset+4:]
    return bufferi

def get_section_hdr(buffer, offset):
    """
    A function to retrieve a section header from a buffer

    :param buffer: the string containing the section header
    :param offset: the offset for the section header
    :return: a dictionary containing python native values for the section header
    """
    name = buffer[offset:offset+SIZE_ISH_NAME]
    misc = get_ledword(buffer, offset+OFF_SH_Miscellaneous)
    virtualaddress = get_ledword(buffer, offset+OFF_SH_VirtualAddress)
    sizeofrawdata = get_ledword(buffer, offset+OFF_SH_SizeOfRawData)
    pointertorawdata = get_ledword(buffer, offset+OFF_SH_PointerToRawData)
    pointertorelocations = get_ledword(buffer, offset+OFF_SH_PointerToRelocations)
    pointertolinenumbers = get_ledword(buffer, offset+OFF_SH_PointerToLineNumbers)
    numberofrelocations = get_leword(buffer, offset+OFF_SH_NumberOfRelocations)
    numberoflinenumbers = get_leword(buffer, offset+OFF_SH_NumberOfLineNumbers)
    characteristics = get_ledword(buffer, offset+OFF_SH_Characteristics)
    ret_dict = {
        "name": name,
        "misc": misc,
        "virtualaddress": virtualaddress,
        "sizeofrawdata": sizeofrawdata,
        "pointertorawdata": pointertorawdata,
        "pointertorelocations": pointertorelocations,
        "pointertolinenumbers": pointertolinenumbers,
        "numberofrelocations":numberofrelocations,
        "numberoflinenumbers": numberoflinenumbers,
        "characteristics": characteristics,
    }
    return ret_dict

def shift_section_hdrs(hdrs, offset):
    """
    A function to shift the native python section headers file offset by a delta

    :param hdrs: An array of dictionaries that are section headers
    :param offset: The value (delta) to shift the file offset by
    :return: True
    """
    for a_hdr in hdrs:
        a_hdr["pointertorawdata"] += offset
    return True

def serialize_section_hdr(a_section):
    """
    A function to take a python dictionary-based section header representation and serialize it to a byte buffer

    :param a_section: the section header to serialize
    :return: a string containing the byte representation of a section header
    """
    data = a_section["name"]
    data += struct.pack("<LLLLLLHHL",
        a_section["misc"],
        a_section["virtualaddress"],
        a_section["sizeofrawdata"],
        a_section["pointertorawdata"],
        a_section["pointertorelocations"],
        a_section["pointertolinenumbers"],
        a_section["numberofrelocations"],
        a_section["numberoflinenumbers"],
        a_section["characteristics"]
    )
    return data

def get_lowest_section_fo(sections):
    """
    A function that returns the lowest file offset among an array of sections.

    :param sections: a list of section headers represented as a python dicitonary
    :return: the lowest file offset contained in the section headers
    """
    lowest_fo = 0x10000000000000000
    for a_section in sections:
        curr_fo = a_section["pointertorawdata"]
        if curr_fo < lowest_fo:
            lowest_fo = curr_fo
    return lowest_fo

def get_highest_section_fo(sections):
    """
    A function that returns the highest file offset consumed by an array of sections.  This value should be rounded.

    :param sections: a list of sections headers represented as a python dictionary
    :return: the highest byte value occupied by a section (pointer to data + size of data)
    """
    highest_fo = -1
    for a_section in sections:
        curr_fo = a_section["pointertorawdata"] + a_section["sizeofrawdata"]
        if curr_fo > highest_fo:
            highest_fo = curr_fo
    return highest_fo


def get_highest_section_va(sections):
    """
    A function that returns the highest virtual address consumed by an array of sections.  Note that this value must be
    rounded.

    :param sections: a list of section headers represented as a python dictionary
    :return: the highest virtual address occupied by a section (virtual address + size of raw data)
    """
    max_va = -1
    for a_section in sections:
        curr_va = a_section["virtualaddress"] + a_section["sizeofrawdata"]
        if curr_va > max_va:
            max_va = curr_va
    return max_va

class PeFile(object):
    def __init__(self, path):
        #A string containing the full pe file data
        self.pe_data = None
        #A value specifying the offset to the beginning of the NT header
        self.p_nt_hdr = None
        #A value specifying the number of sections in the PE file
        self.num_sections = None
        #A string buffer to hold the IMAGE_DOS_HEADER
        self.dos_hdr = None
        #A string buffer to hold the signature, IMAGE_FILE_HEADER and IMAGE_NT_HEADER
        self.full_nt_hdr = None
        #A string buffer to hold all of the section headers
        self.section_hdrs = None
        #The highest virtual address used in the PE, said another way, the first address that
        #is available for a new section
        self.highest_va = None
        #The highest file offset inside the PE, said another way, the index after the last byte for file data
        self.highest_fo = None
        #A value holding the offset to the padding before the section data
        self.end_of_hdrs = None
        #A string buffer holding all the section data
        self.rest_data = None
        #The PE file's file aligment value
        self.file_alignment = None
        #The PE file's section alignment value
        self.section_alignment = None
        #A value indicating the offset at which the section data goes into the PE file
        self.rest_begin = None
        #A string value holding the bound import directory data
        self.bound_import_dir = None
        #Let's load the file...
        self.load_pe(path)

    def get_file_data(self):
        """
        A function to retrieve the pe file data as a string
        :return: a string representing the pe file data
        """
        total_data = self.dos_hdr
        total_data += self.full_nt_hdr
        for a_section in self.section_hdrs:
            total_data += serialize_section_hdr(a_section)
        total_data += self.bound_import_dir
        #Add padding if necessary
        cur_pos = len(total_data)
        if cur_pos != self.rest_begin:
            needed_padding = self.rest_begin - cur_pos
            total_data += NULL_BYTE * needed_padding
        total_data += self.rest_data
        return total_data

    def get_checksum(self):
        """
        A function to retrieve a valid checksum for the given pe file data

        :return: A 32-bit value for the checksum of the pe file
        """
        checksum_offset = len(self.dos_hdr) + SIZE_IMAGE_NT_HEADER + OFF_IOH_Checksum
        data = self.get_file_data()

        remainder = len(data) % 4
        checksum = 0
        for index in xrange(len(data) / 4):
            data_ptr = index * 4
            if (data_ptr == checksum_offset):
              continue
            value = struct.unpack("<I", data[data_ptr:data_ptr+4])[0]
            checksum += value
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
        if remainder > 0:
            last_val = [a_byte for a_byte in data[len(data-remainder):]]
            for index, a_byte in enumerate(last_val):
                value = value + ( ord(a_byte) << (8 * index) )
            checksum += value
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

        checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum = (checksum) + (checksum >> 16)
        checksum = (checksum & 0xffff) + len(data)
        return checksum


    def get_num_sections(self):
        """
        Getter method to retrieve the current number of sections

        :return: a long specifying the number of sections
        """
        return len(self.section_hdrs)

    def recalc(self):
        """
        A function to adjust the current pe values to the current data set.

        :return: None
        """
        highest_va = get_highest_section_va(self.section_hdrs)
        self.highest_va = self.get_salign(highest_va)
        highest_fo = get_highest_section_fo(self.section_hdrs)
        self.highest_fo = self.get_falign(highest_fo)
        lowest_fo = get_lowest_section_fo(section_hdrs)
        lowest_fo = self.get_falign(lowest_fo)
        self.rest_begin = lowest_fo
        highest_fo = get_highest_section_fo(section_hdrs)
        highest_fo = self.get_falign(highest_fo)
        self.highest_fo = highest_fo
        self.full_nt_hdr = write_ledword(self.full_nt_hdr, SIZE_IMAGE_NT_HEADER + OFF_IOH_Checksum, self.get_checksum())
        return

    def add_section(self, a_section, data):
        """
        A function to add a section as modeled by a python struct, with the given data to the pe file

        :param a_section: python dictionary representing the section header
        :param data: data for the section
        :return: None
        """
        #first we align the data to a good size
        if len(data) != self.get_falign(len(data)):
            aligned_size = self.get_falign(len(data))
            needed_pad = aligned_size - len(data)
            data = data + NULL_BYTE * needed_pad
        #next we make sure that the name is 8 bytes
        if len(a_section["name"]) > SIZE_ISH_NAME:
            a_section["name"] = a_section["name"][0:SIZE_ISH_NAME]
        elif len(a_section["name"]) < SIZE_ISH_NAME:
            a_section["name"] = NULL_BYTE * (SIZE_ISH_NAME - len(a_section["name"]))
        #next we calculate space for the section
        end_of_cur_hdrs = self.end_of_hdrs + len(self.section_hdrs) * SIZE_IMAGE_SECTION_HEADER + len(self.bound_import_dir)
        space_left = self.rest_begin - end_of_cur_hdrs
        if space_left < SIZE_IMAGE_SECTION_HEADER:
            shift_section_hdrs(self.section_hdrs, self.file_alignment)
            self.rest_begin += self.file_alignment
            self.full_nt_hdr = shift_ledword(self.full_nt_hdr, SIZE_IMAGE_NT_HEADER + OFF_IOH_SizeOfHeaders, self.file_alignment)
            self.recalc()
        self.full_nt_hdr = shift_data_dir(self.full_nt_hdr, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, SIZE_IMAGE_SECTION_HEADER)
        #add things to the section
        a_section["virtualaddress"] = self.highest_va
        a_section["sizeofrawdata"] = len(data)
        a_section["pointertorawdata"] = self.highest_fo
        self.section_hdrs.append(dict(a_section))
        self.full_nt_hdr = shift_leword(self.full_nt_hdr, OFF_INTH_NumberOfSections, 0x1)
        self.full_nt_hdr = shift_ledword(self.full_nt_hdr, SIZE_IMAGE_NT_HEADER + OFF_IOH_SizeOfImage, self.get_salign(len(data)))
        self.recalc()
        self.rest_data += data
        return


    def write_pe(self, path):
        """
        A function to write the pe data to a file at the specified path
        :param path: A path to write the file
        :return: None
        """
        out_file = open(path,"wb")
        total_data = self.get_file_data()
        out_file.write(total_data)
        out_file.close()
        return

    def get_falign(self, value):
        """
        A function to align a value to the current PE's file alignment

        :param value: The value to align
        :return: The aligned value
        """
        if (value % self.file_alignment) != 0:
            value = value + (self.file_alignment - (value % self.file_alignment))
        return value

    def get_salign(self, value):
        """
        A function to align a value to the current PE's section alignment

        :param value: the value to align
        :return: The aligned value
        """
        if (value % self.section_alignment) != 0:
            value = value + (self.section_alignment - (value % self.section_alignment))
        return value

    def load_pe(self, path):
        """
        A function to load a PE file at the given path into the class

        :param path: A path to a PE file
        :return: None
        """
        #Load the data
        in_file = open(path,"rb")
        pe_data = in_file.read()
        in_file.close()
        self.pe_data = pe_data

        #Load the IMAGE_DOS_HDR
        dos_hdr = pe_data[0:p_nt_hdr]
        self.dos_hdr = dos_hdr

        #Get the pointer to the IMAGE_NT_HEADER
        p_nt_hdr = get_ledword(dos_hdr, OFF_IDH_eLFANew)
        self.p_nt_hdr = p_nt_hdr

        #First load the signature and IMAGE_FILE_HEADER
        nt_hdr_short = pe_data[p_nt_hdr:p_nt_hdr+SIZE_IMAGE_NT_HEADER]
        #Now we can get the full size of the optional header
        size_optional_hdr = get_leword(nt_hdr_short, OFF_INTH_SizeOptionalHdr)
        #Now we load the full Signature + IMAGE_NT_HEADER + IMAGE_OPTIONAL_HEADER
        size_full_nt_hdr = SIZE_IMAGE_NT_HEADER + size_optional_hdr
        full_nt_hdr = pe_data[p_nt_hdr:p_nt_hdr+size_full_nt_hdr]
        self.full_nt_hdr = full_nt_hdr
        #Now let's save off some data inside the IMAGE_NT_HEADER
        file_alignment = get_ledword(full_nt_hdr, SIZE_IMAGE_NT_HEADER + OFF_IOH_FileAlignment)
        self.file_alignment = file_alignment
        section_alignment = get_ledword(full_nt_hdr, SIZE_IMAGE_NT_HEADER + OFF_IOH_SectionAlignment)
        self.section_alignment = section_alignment
        #Now let's load the section data
        num_sections = get_leword(nt_hdr_short, OFF_INTH_NumberOfSections)
        size_section_hdrs = SIZE_IMAGE_SECTION_HEADER * (num_sections)
        section_hdrs_data = pe_data[p_nt_hdr+size_full_nt_hdr:p_nt_hdr+size_full_nt_hdr+size_section_hdrs]
        section_hdrs = []
        for cnt in xrange(num_sections):
            sh_dict = get_section_hdr(section_hdrs_data, cnt * SIZE_IMAGE_SECTION_HEADER)
            section_hdrs.append(sh_dict)
        self.section_hdrs = section_hdrs
        #Load the bound import data if it exists
        bound_import_dir = get_data_dir(full_nt_hdr, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)
        bid_va = bound_import_dir["virtualaddress"]
        bid_vs = bound_import_dir["size"]
        if bid_va != 0:
            self.bound_import_dir = pe_data[bid_va:bid_va + bid_vs]
        #Save off some pointers
        end_of_hdrs = p_nt_hdr + size_full_nt_hdr
        self.end_of_hdrs = end_of_hdrs
        #Calculate some values
        self.recalc()
        #Save off the actual section's data
        self.rest_data = pe_data[self.rest_begin:]
        return



def main(argc, argv):
    if argc < 3:
        print "Usage: %s <in_file> <out_file> <section_name> <section_size>" % (argv[0])

    in_file_path = argv[1]
    out_file_path = argv[2]
    section_name = argv[3]
    section_size = long(argv[4],0)

    my_file = PeFile(in_file_path)
    print "%8.8X" % my_file.get_checksum()
    sec_dict = {
        "name": section_name,
        "misc": 0,
        "pointertorelocations": 0,
        "pointertolinenumbers": 0,
        "numberofrelocations":0,
        "numberoflinenumbers": 0,
        "characteristics": IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE,
    }
    section_data = "ADDEDSECTIONISHERE"
    my_file.add_section(sec_dict, section_data)
    my_file.write_pe(out_file_path)
    return(0)


if __name__ == "__main__":
    main(len(sys.argv),sys.argv)