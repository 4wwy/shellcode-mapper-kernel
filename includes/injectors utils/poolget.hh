#pragma once
#include "definitions.hh"



static unsigned char* FileData = NULL;
static ULONG          FileSize = 0;



#define PE_ERROR_VALUE   ((ULONG)-1)
#define RANDOM_SEED_INIT 0x3AF84E05U
static ULONG RandomSeed = RANDOM_SEED_INIT;

NTKERNELAPI ULONG NTAPI RtlRandomEx(_Inout_ PULONG Seed);

static inline ULONG RtlNextRandom(ULONG Min, ULONG Max)
{
    if (RandomSeed == RANDOM_SEED_INIT)
        RandomSeed = (ULONG)__rdtsc();
    const ULONG Scale = (ULONG)(MAXINT32) / (Max - Min);
    return RtlRandomEx(&RandomSeed) / Scale + Min;
}

static inline ULONG GetPoolTag(void)
{
    static const ULONG PoolTags[] = {
        ' prI', '+prI', 'eliF', 'atuM', 'sFtN',
        'ameS', 'RwtE', 'nevE', ' daV', 'sdaV',
        'aCmM', '  oI', 'tiaW', 'eSmM', 'CPLA',
        'GwtE', ' ldM', 'erhT', 'cScC', 'KgxD',
    };
    const ULONG NumPoolTags = ARRAYSIZE(PoolTags);
    const ULONG Index = RtlNextRandom(0, NumPoolTags);
    return PoolTags[Index];
}

static inline PVOID RtlAllocateMemory(BOOLEAN InZeroMemory, SIZE_T InSize)
{
    PVOID Result = ExAllocatePool2(POOL_FLAG_NON_PAGED, InSize, GetPoolTag());
    if (InZeroMemory && Result)
        RtlZeroMemory(Result, InSize);
    return Result;
}

static inline VOID RtlFreeMemory(PVOID InPointer)
{
    ExFreePool(InPointer);
}



static inline NTSTATUS NTDLL_Initialize(void)
{
    UNICODE_STRING       FileName;
    OBJECT_ATTRIBUTES    ObjectAttributes;
    HANDLE               FileHandle;
    IO_STATUS_BLOCK      IoStatusBlock;
    FILE_STANDARD_INFORMATION StandardInformation = {0};
    LARGE_INTEGER        ByteOffset = {0};
    NTSTATUS             NtStatus;

    RtlInitUnicodeString(&FileName, L"\\SystemRoot\\system32\\ntdll.dll");
    InitializeObjectAttributes(&ObjectAttributes, &FileName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_UNSUCCESSFUL;

    NtStatus = ZwCreateFile(&FileHandle, GENERIC_READ, &ObjectAttributes,
        &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(NtStatus))
        return NtStatus;

    NtStatus = ZwQueryInformationFile(FileHandle, &IoStatusBlock,
        &StandardInformation, sizeof(StandardInformation), FileStandardInformation);
    if (!NT_SUCCESS(NtStatus)) { ZwClose(FileHandle); return NtStatus; }

    FileSize = StandardInformation.EndOfFile.LowPart;
    FileData = (unsigned char*)RtlAllocateMemory(TRUE, FileSize);

    NtStatus = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock,
        FileData, FileSize, &ByteOffset, NULL);
    if (!NT_SUCCESS(NtStatus))
        RtlFreeMemory(FileData);

    ZwClose(FileHandle);
    return NtStatus;
}



typedef struct _SSDTStruct {
    LONG*  pServiceTable;
    PVOID  pCounterTable;
#ifdef _WIN64
    ULONGLONG NumberOfServices;
#else
    ULONG     NumberOfServices;
#endif
    PCHAR  pArgumentTable;
} SSDTStruct;

NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);

static inline PVOID GetKernelBase(PULONG pImageSize)
{
    typedef struct _SYSTEM_MODULE_ENTRY {
        HANDLE Section; PVOID MappedBase; PVOID ImageBase;
        ULONG ImageSize; ULONG Flags;
        USHORT LoadOrderIndex; USHORT InitOrderIndex;
        USHORT LoadCount; USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
    typedef struct _SYSTEM_MODULE_INFORMATION {
        ULONG Count;
        SYSTEM_MODULE_ENTRY Module[0];
    } SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

    PVOID pModuleBase = NULL;
    PSYSTEM_MODULE_INFORMATION pSysInfo = NULL;
    ULONG SysInfoSize = 0;
    NTSTATUS status;

    status = ZwQuerySystemInformation(11, &SysInfoSize, 0, &SysInfoSize);
    if (!SysInfoSize) return NULL;

    pSysInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, SysInfoSize * 2, GetPoolTag());
    if (!pSysInfo) return NULL;

    RtlZeroMemory(pSysInfo, SysInfoSize * 2);
    status = ZwQuerySystemInformation(11, pSysInfo, SysInfoSize * 2, &SysInfoSize);

    if (NT_SUCCESS(status)) {
        pModuleBase = pSysInfo->Module[0].ImageBase;
        if (pImageSize) *pImageSize = pSysInfo->Module[0].ImageSize;
    }
    ExFreePool(pSysInfo);
    return pModuleBase;
}

static inline SSDTStruct* SSDTfind(void)
{
    static SSDTStruct* SSDT = NULL;
    if (!SSDT)
    {
#ifndef _WIN64
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
        SSDT = (SSDTStruct*)MmGetSystemRoutineAddress(&routineName);
#else
        ULONG kernelSize = 0;
        ULONG_PTR kernelBase = (ULONG_PTR)GetKernelBase(&kernelSize);
        if (!kernelBase || !kernelSize) return NULL;

        PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader((PVOID)kernelBase);
        PIMAGE_SECTION_HEADER textSection = NULL;
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

        ULONG i;
        for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
            RtlCopyMemory(sectionName, section->Name, IMAGE_SIZEOF_SHORT_NAME);
            sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
            if (strncmp(sectionName, ".text", sizeof(".text") - 1) == 0)
            { textSection = section; break; }
            section++;
        }
        if (!textSection) return NULL;

        static const unsigned char KiPattern[] = {
            0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20,
            0x25, 0xFF, 0x0F, 0x00, 0x00 };
        const ULONG sigSize = sizeof(KiPattern);
        ULONG kOffset;
        BOOLEAN found = FALSE;
        for (kOffset = 0; kOffset < textSection->Misc.VirtualSize - sigSize; kOffset++)
        {
            if (RtlCompareMemory(
                (unsigned char*)kernelBase + textSection->VirtualAddress + kOffset,
                KiPattern, sigSize) == sigSize)
            { found = TRUE; break; }
        }
        if (!found) return NULL;

        ULONG_PTR address = kernelBase + textSection->VirtualAddress + kOffset + sigSize;
        LONG relOffset = 0;
        if (*(unsigned char*)address == 0x4C &&
            *(unsigned char*)(address + 1) == 0x8D &&
            *(unsigned char*)(address + 2) == 0x15)
        {
            relOffset = *(LONG*)(address + 3);
        }
        if (!relOffset) return NULL;
        SSDT = (SSDTStruct*)(address + relOffset + 7);
#endif
    }
    return SSDT;
}



static inline ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG ArgFileSize)
{
    PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth);
    USHORT n = pnth->FileHeader.NumberOfSections;
    int i;
    for (i = 0; i < n; i++, psh++)
    {
        if (psh->VirtualAddress <= Rva &&
            (psh->VirtualAddress + psh->Misc.VirtualSize) > Rva)
        {
            Rva -= psh->VirtualAddress;
            Rva += psh->PointerToRawData;
            return Rva < ArgFileSize ? Rva : PE_ERROR_VALUE;
        }
    }
    return PE_ERROR_VALUE;
}

static inline ULONG GetExportOffset(const unsigned char* ArgFileData, ULONG ArgFileSize, const char* ExportName)
{
    PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)ArgFileData;
    if (pdh->e_magic != IMAGE_DOS_SIGNATURE) return PE_ERROR_VALUE;

    PIMAGE_NT_HEADERS pnth = (PIMAGE_NT_HEADERS)(ArgFileData + pdh->e_lfanew);
    if (pnth->Signature != IMAGE_NT_SIGNATURE) return PE_ERROR_VALUE;

    PIMAGE_DATA_DIRECTORY pdd = NULL;
    if (pnth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        pdd = ((PIMAGE_NT_HEADERS64)pnth)->OptionalHeader.DataDirectory;
    else
        pdd = ((PIMAGE_NT_HEADERS32)pnth)->OptionalHeader.DataDirectory;

    ULONG ExpRva    = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG ExpSize   = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    ULONG ExpOff    = RvaToOffset(pnth, ExpRva, ArgFileSize);
    if (ExpOff == PE_ERROR_VALUE) return PE_ERROR_VALUE;

    PIMAGE_EXPORT_DIRECTORY ExpDir = (PIMAGE_EXPORT_DIRECTORY)(ArgFileData + ExpOff);

    ULONG  nNames       = ExpDir->NumberOfNames;
    ULONG  FuncOff      = RvaToOffset(pnth, ExpDir->AddressOfFunctions,    ArgFileSize);
    ULONG  OrdOff       = RvaToOffset(pnth, ExpDir->AddressOfNameOrdinals, ArgFileSize);
    ULONG  NamesOff     = RvaToOffset(pnth, ExpDir->AddressOfNames,        ArgFileSize);
    if (FuncOff == PE_ERROR_VALUE || OrdOff == PE_ERROR_VALUE || NamesOff == PE_ERROR_VALUE)
        return PE_ERROR_VALUE;

    ULONG*  Funcs  = (ULONG*)  (ArgFileData + FuncOff);
    USHORT* Ords   = (USHORT*) (ArgFileData + OrdOff);
    ULONG*  Names  = (ULONG*)  (ArgFileData + NamesOff);

    ULONG i;
    for (i = 0; i < nNames; i++)
    {
        ULONG nameOff = RvaToOffset(pnth, Names[i], ArgFileSize);
        if (nameOff == PE_ERROR_VALUE) continue;
        const char* curName = (const char*)(ArgFileData + nameOff);
        ULONG funcRva = Funcs[Ords[i]];
        if (funcRva >= ExpRva && funcRva < ExpRva + ExpSize) continue;
        if (!strcmp(curName, ExportName))
            return RvaToOffset(pnth, funcRva, ArgFileSize);
    }
    return PE_ERROR_VALUE;
}

static inline int GetExportSsdtIndex(const char* ExportName)
{
    ULONG_PTR ExportOffset = GetExportOffset(FileData, FileSize, ExportName);
    if (ExportOffset == PE_ERROR_VALUE) return -1;

    unsigned char* ExportData = FileData + ExportOffset;
    int i;
    for (i = 0; i < 32 && ExportOffset + i < FileSize; i++)
    {
        if (ExportData[i] == 0xC2 || ExportData[i] == 0xC3) break;
        if (ExportData[i] == 0xB8)
            return *(int*)(ExportData + i + 1);
    }
    return -1;
}


static inline PVOID GetFunctionAddress(const char* apiname)
{
    SSDTStruct* SSDT = SSDTfind();
    if (!SSDT) return NULL;

    ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
    if (!SSDTbase) return NULL;

    int readOffset = GetExportSsdtIndex(apiname);
    if (readOffset < 0 || (ULONG)readOffset >= (ULONG)SSDT->NumberOfServices)
        return NULL;

#ifdef _WIN64
    return (PVOID)((SSDT->pServiceTable[readOffset] >> 4) + SSDTbase);
#else
    return (PVOID)(ULONG_PTR)SSDT->pServiceTable[readOffset];
#endif
}
