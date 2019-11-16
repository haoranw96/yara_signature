import sys
import pefile

def usage():
    sys.stderr.write('usage: python get_code_section.py sample.exe\n')
    sys.exit(2)

def _main():
    if len(sys.argv) != 2:
        usage()

    fn = sys.argv[1]

    # Retrieve code section(s') contents
    code = list()
    pe = pefile.PE(fn)
    for section in pe.sections:
        section_flags = pefile.retrieve_flags(pefile.SECTION_CHARACTERISTICS, 'IMAGE_SCN_')

        isCode = False

        for flag, value in section_flags:
            if section.__dict__[flag] is True:
                if flag == 'IMAGE_SCN_CNT_CODE' or flag == 'IMAGE_SCN_MEM_EXECUTE':
                    isCode = True
                    break

        if isCode:
            offset = section.PointerToRawData
            end = offset + section.SizeOfRawData
            code.extend(pe.__data__[offset:end])

    # Print out code seciton bytes
    #print(code)
    for sec in code: 
        print(str(hex(sec))[1:], end="")

if __name__ == '__main__':
    _main()
