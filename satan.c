#include <ntddk.h>


NTSTATUS RunAutoInjection(VOID);


NTSTATUS DriverEntry(
    PDRIVER_OBJECT  pDriverObject,
    PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);


    if (pDriverObject)
        pDriverObject->DriverUnload = NULL;

    return RunAutoInjection();
}
