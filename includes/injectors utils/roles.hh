#pragma once
#include "definitions.hh"



static inline PVOID GetKernelBaseCleaner(PULONG pSize)
{
    PVOID pModuleBase = NULL;
    ULONG moduleSize  = 0;
    ULONG bytes       = 0;


    ZwQuerySystemInformation(11, NULL, 0, &bytes);
    if (!bytes) return NULL;

    PRTL_PROCESS_MODULES modules =
        (PRTL_PROCESS_MODULES)UtilsAllocateMemory(bytes);
    if (!modules) return NULL;

    if (NT_SUCCESS(ZwQuerySystemInformation(11, modules, bytes, &bytes)))
    {
        pModuleBase = modules->Modules[0].ImageBase;
        moduleSize  = modules->Modules[0].ImageSize;
    }

    if (pSize) *pSize = moduleSize;
    ExFreePool(modules);
    return pModuleBase;
}
