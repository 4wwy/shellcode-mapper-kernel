#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>

#ifndef BOOL
typedef int BOOL;
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef BYTE
typedef unsigned char BYTE;
#endif
#ifndef PBYTE
typedef unsigned char* PBYTE;
#endif
#ifndef DWORD
typedef unsigned long DWORD;
#endif
#ifndef WORD
typedef unsigned short WORD;
#endif



static inline PVOID UtilsAllocateMemory(ULONG Size)
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'enoN');
}



static inline int HexToInt(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

static inline BOOLEAN CheckMask(PCHAR base, PCHAR pattern, PCHAR mask)
{
    for (; *mask; ++base, ++pattern, ++mask)
        if (*mask == 'x' && *base != *pattern)
            return FALSE;
    return TRUE;
}

static inline PVOID FindPatternRaw(PVOID base, ULONG length, PCHAR pattern, PCHAR mask)
{
    length -= (ULONG)strlen(mask);
    for (ULONG i = 0; i <= length; ++i)
    {
        PVOID addr = (PVOID)((ULONG_PTR)base + i);
        if (!MmIsAddressValid(addr)) continue;
        __try { if (CheckMask((PCHAR)addr, pattern, mask)) return addr; }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
    }
    return NULL;
}

static inline PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
    ULONG_PTR Instr = (ULONG_PTR)Instruction;
    if (!MmIsAddressValid((PVOID)(Instr + OffsetOffset))) return NULL;
    LONG RipOffset = 0;
    __try { RipOffset = *(PLONG)(Instr + OffsetOffset); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return NULL; }
    return (PVOID)(Instr + InstructionSize + RipOffset);
}

#define MAX_SIG_SIZE 128

static inline PVOID FindPattern(PVOID Base, ULONG Size, char* Signature, int Offset, BOOL Deref, int DerefOffset)
{
    char pattern[MAX_SIG_SIZE] = {0};
    char mask[MAX_SIG_SIZE]    = {0};
    int  len = 0;
    char* s  = Signature;

    while (*s && len < MAX_SIG_SIZE)
    {
        if (*s == ' ') { s++; continue; }
        if (*s == '?')
        {
            mask[len]    = '?';
            pattern[len] = 0;
            s++;
            if (*s == '?') s++;
        }
        else
        {
            mask[len]    = 'x';
            pattern[len] = (char)((HexToInt(s[0]) << 4) | HexToInt(s[1]));
            s += 2;
        }
        len++;
    }
    mask[len] = 0;

    PVOID match = FindPatternRaw(Base, Size, pattern, mask);
    if (match)
    {
        match = (PVOID)((ULONG_PTR)match + Offset);
        if (Deref)
            match = ResolveRelativeAddress(match, (ULONG)DerefOffset, (ULONG)(DerefOffset + 4));
    }
    return match;
}



static inline NTSTATUS SafeWrite(PVOID dest, PVOID src, ULONG size)
{
    PMDL mdl = IoAllocateMdl(dest, size, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    __try { MmProbeAndLockPages(mdl, KernelMode, IoReadAccess); }
    __except (EXCEPTION_EXECUTE_HANDLER) { IoFreeMdl(mdl); return STATUS_ACCESS_VIOLATION; }

    PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (!mapped) { MmUnlockPages(mdl); IoFreeMdl(mdl); return STATUS_INSUFFICIENT_RESOURCES; }

    NTSTATUS status = STATUS_SUCCESS;
    __try { RtlCopyMemory(mapped, src, size); }
    __except (EXCEPTION_EXECUTE_HANDLER) { status = STATUS_ACCESS_VIOLATION; }

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return status;
}


static inline int MySwprintf(wchar_t* buffer, const wchar_t* format, ...)
{
    va_list args;
    va_start(args, format);
    NTSTATUS st = RtlStringCbVPrintfW(buffer, 256 * sizeof(wchar_t), format, args);
    va_end(args);
    return NT_SUCCESS(st) ? 0 : -1;
}
#define swprintf MySwprintf



typedef struct _DRIVER_GLOBAL_DATA {
    ULONG_PTR ul_ntos_krnl_base;
    ULONG     ul_ntos_krnl_size;
} DRIVER_GLOBAL_DATA, *PDRIVER_GLOBAL_DATA;

static DRIVER_GLOBAL_DATA g_DriverData = {0};
static PDRIVER_GLOBAL_DATA p_driver    = &g_DriverData;


typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;



#ifndef SystemModuleInformation
#define SystemModuleInformation 11
#endif

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID (NTAPI* PKNORMAL_ROUTINE)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2);

typedef VOID (NTAPI* PKKERNEL_ROUTINE)(
    _In_    PKAPC               Apc,
    _Inout_ PKNORMAL_ROUTINE*   NormalRoutine,
    _Inout_ PVOID*              NormalContext,
    _Inout_ PVOID*              SystemArgument1,
    _Inout_ PVOID*              SystemArgument2);

typedef VOID (NTAPI* PKRUNDOWN_ROUTINE)(
    _In_ PKAPC Apc);



NTKERNELAPI VOID KeInitializeApc(
    _Out_     PRKAPC              Apc,
    _In_      PRKTHREAD           Thread,
    _In_      KAPC_ENVIRONMENT    Environment,
    _In_      PKKERNEL_ROUTINE    KernelRoutine,
    _In_opt_  PKRUNDOWN_ROUTINE   RundownRoutine,
    _In_opt_  PKNORMAL_ROUTINE    NormalRoutine,
    _In_opt_  KPROCESSOR_MODE     ApcMode,
    _In_opt_  PVOID               NormalContext);

NTKERNELAPI BOOLEAN KeInsertQueueApc(
    _Inout_  PRKAPC  Apc,
    _In_opt_ PVOID   SystemArgument1,
    _In_opt_ PVOID   SystemArgument2,
    _In_     KPRIORITY Increment);

NTKERNELAPI BOOLEAN KeAlertThread(
    _In_ PKTHREAD Thread,
    _In_ KPROCESSOR_MODE ProcessorMode);

NTKERNELAPI BOOLEAN KeTestAlertThread(
    _In_ KPROCESSOR_MODE ProcessorMode);

NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    IN ULONG SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    IN     HANDLE   ProcessHandle,
    IN OUT PVOID*   BaseAddress,
    IN OUT PSIZE_T  RegionSize,
    IN     ULONG    NewProtect,
    OUT    PULONG   OldProtect);

NTSYSAPI NTSTATUS NTAPI ZwOpenThread(
    OUT PHANDLE             ThreadHandle,
    IN  ACCESS_MASK         DesiredAccess,
    IN  POBJECT_ATTRIBUTES  ObjectAttributes,
    IN  PCLIENT_ID          ClientId OPTIONAL);




static const GUID EFI_GLOBAL_VARIABLE = {
    0x8BE4DF61, 0x93CA, 0x11D2,
    { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C }
};

NTSTATUS ZwQuerySystemEnvironmentValueEx(
    _In_                                    PUNICODE_STRING VariableName,
    _In_                                    PGUID           VendorGuid,
    _Out_writes_bytes_opt_(*ValueLength)    PVOID           Value,
    _Inout_                                 PULONG          ValueLength,
    _Out_opt_                               PULONG          Attributes);

NTSTATUS ZwSetSystemEnvironmentValueEx(
    _In_                            PUNICODE_STRING VariableName,
    _In_                            PGUID           VendorGuid,
    _In_reads_bytes_opt_(ValueLength) PVOID         Value,
    _In_                            ULONG           ValueLength,
    _In_                            ULONG           Attributes);
