#pragma once

#define DRIVER_TAG 'amrA'



typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    KPRIORITY     Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    KWAIT_REASON  WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO {
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   WorkingSetPrivateSize;
    ULONG           HardFaultCount;
    ULONG           NumberOfThreadsHighWatermark;
    ULONGLONG       CycleTime;
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    KPRIORITY       BasePriority;
    HANDLE          UniqueProcessId;
    HANDLE          InheritedFromUniqueProcessId;
    ULONG           HandleCount;
    ULONG           SessionId;
    ULONG_PTR       UniqueProcessKey;
    SIZE_T          PeakVirtualSize;
    SIZE_T          VirtualSize;
    ULONG           PageFaultCount;
    SIZE_T          PeakWorkingSetSize;
    SIZE_T          WorkingSetSize;
    SIZE_T          QuotaPeakPagedPoolUsage;
    SIZE_T          QuotaPagedPoolUsage;
    SIZE_T          PeakQuotaNonPagedPoolUsage;
    SIZE_T          QuotaNonPagedPoolUsage;
    SIZE_T          PagefileUsage;
    SIZE_T          PeakPagefileUsage;
    SIZE_T          PrivatePageCount;
    LARGE_INTEGER   ReadOperationCount;
    LARGE_INTEGER   WriteOperationCount;
    LARGE_INTEGER   OtherOperationCount;
    LARGE_INTEGER   ReadTransferCount;
    LARGE_INTEGER   WriteTransferCount;
    LARGE_INTEGER   OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;



#define WIN_2004 19041

static ULONG WindowsBuildNumber = 0;

#ifndef POOL_FLAG_PAGED
#define POOL_FLAG_PAGED             0x00000002ULL
#endif
#ifndef POOL_FLAG_NON_PAGED_EXECUTE
#define POOL_FLAG_NON_PAGED_EXECUTE 0x00000020ULL
#endif

static inline void GetWindowsVersion(void)
{
    RTL_OSVERSIONINFOW vi = {0};
    vi.dwOSVersionInfoSize = sizeof(vi);
    RtlGetVersion(&vi);
    WindowsBuildNumber = vi.dwBuildNumber;
}

static inline PVOID AllocateMemory(SIZE_T size, BOOLEAN paged)
{
    if (WindowsBuildNumber >= WIN_2004)
    {
        POOL_FLAGS flags = paged ? POOL_FLAG_PAGED : POOL_FLAG_NON_PAGED_EXECUTE;
        return ExAllocatePool2(flags, size, DRIVER_TAG);
    }
#pragma warning(push)
#pragma warning(disable: 4996)
    return paged
        ? ExAllocatePoolWithTag(PagedPool,    size, DRIVER_TAG)
        : ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
#pragma warning(pop)
}



NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS       SourceProcess,
    PVOID           SourceAddress,
    PEPROCESS       TargetProcess,
    PVOID           TargetAddress,
    SIZE_T          BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T         ReturnSize);

NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    IN     HANDLE  ProcessHandle,
    IN OUT PVOID*  BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN     ULONG   NewProtect,
    OUT    PULONG  OldProtect);



NTKERNELAPI BOOLEAN KeInsertQueueApc(
    _Inout_  PRKAPC    Apc,
    _In_opt_ PVOID     SystemArgument1,
    _In_opt_ PVOID     SystemArgument2,
    _In_     KPRIORITY Increment);

NTKERNELAPI BOOLEAN KeAlertThread(
    _In_ PKTHREAD        Thread,
    _In_ KPROCESSOR_MODE ProcessorMode);

NTKERNELAPI BOOLEAN KeTestAlertThread(
    _In_ KPROCESSOR_MODE ProcessorMode);

#ifndef _KTRAP_FRAME_DEFINED
#define _KTRAP_FRAME_DEFINED
#endif
