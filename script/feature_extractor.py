import pefile

def extract_features(file_path):

    pe = pefile.PE(file_path)

    features = {}

    # DOS HEADER
    features['e_magic'] = pe.DOS_HEADER.e_magic
    features['e_cblp'] = pe.DOS_HEADER.e_cblp
    features['e_cp'] = pe.DOS_HEADER.e_cp
    features['e_crlc'] = pe.DOS_HEADER.e_crlc
    features['e_cparhdr'] = pe.DOS_HEADER.e_cparhdr
    features['e_minalloc'] = pe.DOS_HEADER.e_minalloc
    features['e_maxalloc'] = pe.DOS_HEADER.e_maxalloc
    features['e_ss'] = pe.DOS_HEADER.e_ss
    features['e_sp'] = pe.DOS_HEADER.e_sp
    features['e_csum'] = pe.DOS_HEADER.e_csum
    features['e_ip'] = pe.DOS_HEADER.e_ip
    features['e_cs'] = pe.DOS_HEADER.e_cs
    features['e_lfarlc'] = pe.DOS_HEADER.e_lfarlc
    features['e_ovno'] = pe.DOS_HEADER.e_ovno
    features['e_oemid'] = pe.DOS_HEADER.e_oemid
    features['e_oeminfo'] = pe.DOS_HEADER.e_oeminfo
    features['e_lfanew'] = pe.DOS_HEADER.e_lfanew

    # FILE HEADER
    features['Machine'] = pe.FILE_HEADER.Machine
    features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
    features['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
    features['PointerToSymbolTable'] = pe.FILE_HEADER.PointerToSymbolTable
    features['NumberOfSymbols'] = pe.FILE_HEADER.NumberOfSymbols
    features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    features['Characteristics'] = pe.FILE_HEADER.Characteristics

    # OPTIONAL HEADER
    features['Magic'] = pe.OPTIONAL_HEADER.Magic
    features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    features['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    features['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    features['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    features['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    features['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    features['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics


        # SECTION FEATURES
    
    features['SectionsLength'] = len(pe.sections)
    
    entropies = [section.get_entropy() for section in pe.sections]
    
    features['SectionMinEntropy'] = min(entropies)
    features['SectionMaxEntropy'] = max(entropies)
    
    raw_sizes = [section.SizeOfRawData for section in pe.sections]
    
    features['SectionMinRawsize'] = min(raw_sizes)
    features['SectionMaxRawsize'] = max(raw_sizes)
    
    virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
    
    features['SectionMinVirtualsize'] = min(virtual_sizes)
    features['SectionMaxVirtualsize'] = max(virtual_sizes)
    
    physical_sizes = [section.Misc_PhysicalAddress for section in pe.sections]
    
    features['SectionMaxPhysical'] = max(physical_sizes)
    features['SectionMinPhysical'] = min(physical_sizes)
    
    virtual_addresses = [section.VirtualAddress for section in pe.sections]
    
    features['SectionMaxVirtual'] = max(virtual_addresses)
    features['SectionMinVirtual'] = min(virtual_addresses)
    
    pointer_data = [section.PointerToRawData for section in pe.sections]
    
    features['SectionMaxPointerData'] = max(pointer_data)
    features['SectionMinPointerData'] = min(pointer_data)
    
    characteristics = [section.Characteristics for section in pe.sections]
    
    features['SectionMaxChar'] = max(characteristics)
    features['SectionMainChar'] = min(characteristics)

    # IMPORT FEATURES

    features['DirectoryEntryImport'] = 0
    features['DirectoryEntryImportSize'] = 0
    
    suspicious_apis = [
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "LoadLibraryA",
        "WinExec",
        "ShellExecuteA"
    ]
    
    suspicious_count = 0
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    
        features['DirectoryEntryImport'] = len(pe.DIRECTORY_ENTRY_IMPORT)
    
        total_imports = 0
    
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
    
            total_imports += len(entry.imports)
    
            for imp in entry.imports:
    
                if imp.name:
    
                    api_name = imp.name.decode(errors='ignore')
    
                    if api_name in suspicious_apis:
                        suspicious_count += 1
    
        features['DirectoryEntryImportSize'] = total_imports
    
    features['SuspiciousImportFunctions'] = suspicious_count

    # DIRECTORY FEATURES

    features['DirectoryEntryExport'] = (
        1 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
    )
    
    features['ImageDirectoryEntryExport'] = (
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
        ].Size
    )
    
    features['ImageDirectoryEntryImport'] = (
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ].Size
    )
    
    features['ImageDirectoryEntryResource'] = (
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
        ].Size
    )
    
    features['ImageDirectoryEntryException'] = (
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']
        ].Size
    )
    
    features['ImageDirectoryEntrySecurity'] = (
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        ].Size
    )

    # STACK / HEAP FEATURES

    features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    features['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    
    features['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # IMPORT FEATURES

    features['DirectoryEntryImport'] = 0
    features['DirectoryEntryImportSize'] = 0
    
    suspicious_apis = [
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "LoadLibraryA",
        "WinExec",
        "ShellExecuteA"
    ]
    
    suspicious_count = 0
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    
        features['DirectoryEntryImport'] = len(pe.DIRECTORY_ENTRY_IMPORT)
    
        total_imports = 0
    
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
    
            total_imports += len(entry.imports)
    
            for imp in entry.imports:
    
                if imp.name:
    
                    api_name = imp.name.decode(errors='ignore')
    
                    if api_name in suspicious_apis:
                        suspicious_count += 1
    
        features['DirectoryEntryImportSize'] = total_imports
    
    features['SuspiciousImportFunctions'] = suspicious_count
    suspicious_sections = ['UPX', '.packed', '.rsrc']

    features['SuspiciousNameSection'] = 0
    
    for section in pe.sections:
    
        name = section.Name.decode(errors='ignore').strip('\x00')
    
        if name in suspicious_sections:
            features['SuspiciousNameSection'] = 1
            break

    # DIRECTORY FEATURES
    
    features['DirectoryEntryExport'] = (
        1 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
    )
    
    features['ImageDirectoryEntryExport'] = (
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
        ].Size
    )
    
    features['ImageDirectoryEntryImport'] = (
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ].Size
    )
    
    features['ImageDirectoryEntryResource'] = (
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
        ].Size
    )
    
    features['ImageDirectoryEntryException'] = (
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']
        ].Size
    )
    
    features['ImageDirectoryEntrySecurity'] = (
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        ].Size
    )

    # STACK / HEAP FEATURES

    features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    
    features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    
    features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    
    features['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    
    features['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    
    features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
    
    
    # SUSPICIOUS SECTION NAME
    
    suspicious_sections = ['UPX', '.packed', '.rsrc']
    
    features['SuspiciousNameSection'] = 0
    
    for section in pe.sections:
    
        section_name = section.Name.decode(
            errors='ignore'
        ).strip('\x00')
    
        if section_name in suspicious_sections:
    
            features['SuspiciousNameSection'] = 1
            break
    return features