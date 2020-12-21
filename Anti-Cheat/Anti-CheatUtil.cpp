#include "Anti-CheatBase.h"
#include "zwapi.h"

extern GLOBAL_DATA g_Global_Data;

NTSTATUS KrnlGetPspLoadImageNotifyRoutine(_Out_ PULONG_PTR pOutAddress)
{
    NTSTATUS ntStatus = STATUS_NOT_FOUND;
    UCHAR *ScanfBase = 0;
    ULONG i = 0;
    ULONG dwOffset = 0;
    UNICODE_STRING uSystemRoutineName = { 0x00 };
    ULONG_PTR f_PsSetLoadImageFuncAddr = NULL;

#ifdef _WIN64
#if NTDDI_VERSION >= NTDDI_WIN10
    RtlInitUnicodeString(&uSystemRoutineName, L"PsSetLoadImageNotifyRoutineEx");

    f_PsSetLoadImageFuncAddr = (ULONG_PTR)MmGetSystemRoutineAddress((PUNICODE_STRING)&uSystemRoutineName);

#else
#if NTDDI_VERSION >= NTDDI_WIN8
    RtlInitUnicodeString(&uSystemRoutineName, L"PsSetLoadImageNotifyRoutine");
    f_PsSetLoadImageFuncAddr = (ULONG_PTR)MmGetSystemRoutineAddress((PUNICODE_STRING)&uSystemRoutineName);
    
#else 
#if NTDDI_VERSION >= NTDDI_WIN7
    RtlInitUnicodeString(&uSystemRoutineName, L"PsSetLoadImageNotifyRoutine");
    f_PsSetLoadImageFuncAddr = (ULONG_PTR)MmGetSystemRoutineAddress((PUNICODE_STRING)&uSystemRoutineName);

#endif //NTDDI_VERSION >= NTDDI_WIN7

#endif //NTDDI_VERSION >= NTDDI_WIN8

#endif //NTDDI_VERSION >= NTDDI_WIN10

    if (!f_PsSetLoadImageFuncAddr)
    {
        goto finish;
    }
    ScanfBase = (UCHAR*)f_PsSetLoadImageFuncAddr;
    
    for (i = 0; i < 0x100; ++i)
    {
        //lea,rcx,PspLoadIamgeNotifyRoutine  48 8d 0d 28 80 da ff 
        if (*(ScanfBase + i) == 0x48 &&
            *(ScanfBase + i + 1) == 0x8d &&
            *(ScanfBase + i + 2) == 0x0d)
        {
            dwOffset = *(ULONG*)(ScanfBase + i + 3);

            if (!dwOffset)
                break;

            //PspLoadImageNotifyRoutine = ScanfBase + i + dwOffset + 7 - 0x100000000
            *pOutAddress = (ULONG_PTR)(ScanfBase + i + dwOffset + 7 - 0x100000000);
            ntStatus = STATUS_SUCCESS;
            break;
        }
    }
#else
#endif //_WIN64

finish:
    return ntStatus;
}

NTSTATUS 
KrnlGetImageNameByPath(
    _In_ UNICODE_STRING* pQueryString,
    _Out_ WCHAR** pImageName, 
    _Out_ ULONG_PTR *pLen
)
{
    NTSTATUS Status;
    WCHAR* pName = NULL;
    Status = STATUS_OBJECT_NAME_NOT_FOUND;

    if (!pQueryString || !pImageName || !pLen)
        return Status;
        
    if (pQueryString->Length == 0 || pQueryString->Buffer == NULL)
        return Status;

    pName = pQueryString->Buffer + ((pQueryString->Length - 1 ) / sizeof(WCHAR));

    while (pName != pQueryString->Buffer)
    {
        if (*pName == '\\')
        {
            Status = STATUS_SUCCESS;
            ++pName;
            break;
        }
        --pName;
    }
    if (NT_SUCCESS(Status))
    {
        *pImageName = pName;
        *pLen = ((ULONG_PTR)pQueryString->Buffer + pQueryString->Length - (ULONG_PTR)pName);
    }
    return Status;
}

NTSTATUS
KrnlGetImageNameByPathW(
    _In_ WCHAR* pQueryString,
    _Out_ WCHAR** pImageName,
    _Out_ ULONG_PTR* pLen
)
{
    UNICODE_STRING uStr = { 0x00 };
    RtlInitUnicodeString(&uStr, pQueryString);
    return KrnlGetImageNameByPath(&uStr, pImageName, pLen);
}

NTSTATUS 
KrnlGetImageNameByPathA(
    _In_ PUCHAR pQueryString, 
    _Out_ PUCHAR* pImageName, 
    _Out_ ULONG_PTR* pLen
)
{
    NTSTATUS ntStatus = STATUS_NOT_FOUND;
    UCHAR* pName = NULL;
    SIZE_T dwQueryLen = 0;

    if (!pQueryString || !pImageName || !pLen)
        return ntStatus;
    
    dwQueryLen = strlen((const char *)pQueryString) - sizeof(UCHAR);
    pName = pQueryString + dwQueryLen;
    while (pName && pName >= pQueryString)
    {
        if (*pName == '\\')
        {
            ++pName;
            *pImageName = pName;
            *pLen = pQueryString + dwQueryLen - pName;
            ntStatus = STATUS_SUCCESS;
            break;
        }
        --pName;
    }
    return ntStatus;
}

NTSTATUS KrnlGetProcessName(_In_ PEPROCESS Eprocess,_Out_ UNICODE_STRING *ProcessName)
{
    UNREFERENCED_PARAMETER(Eprocess);

    NTSTATUS Status = STATUS_OBJECTID_NOT_FOUND;
    KAPC_STATE kapc = { 0x00 };
    ULONG dwRet = 0;
    UNICODE_STRING* pQueryString = NULL;
    WCHAR* pName = NULL;
    ULONG_PTR dwLen = 0;

    if (!ProcessName)
        return Status;

    do 
    {
        Status = ZwQueryInformationProcess(NtCurrentProcess(),
            ProcessImageFileName,
            NULL,
            NULL,
            &dwRet);
        if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH)
            break;

        pQueryString = (UNICODE_STRING*)ExAllocatePoolWithTag(NonPagedPool, dwRet, '0syS');
        if (!pQueryString)
        {
            Status = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }
        
        Status = ZwQueryInformationProcess(NtCurrentProcess(),
            ProcessImageFileName,
            pQueryString,
            dwRet,
            &dwRet);
        if (!NT_SUCCESS(Status))
            break;

        if (!MmIsAddressValid(pQueryString))
        {
            Status = STATUS_INVALID_ADDRESS;
            break;
        }

        Status = KrnlGetImageNameByPath(pQueryString, &pName, &dwLen);
        if (NT_SUCCESS(Status))
        {
            RtlUnicodeStringCbCopyStringN(ProcessName, pName, dwLen);
        }
        break;
    } while (FALSE);
    

    if (pQueryString)
        ExFreePoolWithTag(pQueryString, 0);

    return Status;
}

void LockList(ERESOURCE* pLock)
{
    ExEnterCriticalRegionAndAcquireResourceExclusive(pLock);
}

void UnlockList(ERESOURCE *pLock)
{
    ExReleaseResourceAndLeaveCriticalRegion(pLock);
}

void LookupList(LIST_ENTRY* pListHeader)
{
    LIST_ENTRY* pEntry = pListHeader->Flink;

    AkrOsPrint("Start List:********************************************\n");
    while (pEntry != pListHeader)
    {
        ANTI_CHEAT_BLACK_WHITE_DATA* pWhiteData = CONTAINING_RECORD(pEntry, ANTI_CHEAT_BLACK_WHITE_DATA, m_Entry);
        if (pWhiteData)
        {
            AkrOsPrint("%ws!\n", pWhiteData->m_ProcessName);
        }
        pEntry = pEntry->Flink;
    }

    AkrOsPrint("End List:********************************************\n");
}

BOOLEAN KrnlCheckPE(VOID* ImageBase, SIZE_T ImageSize)
{
    IMAGE_DOS_HEADER* pDos = NULL;
    IMAGE_NT_HEADERS* pNt = NULL;

    if (ImageBase == NULL || ImageSize == 0)
        return FALSE;

    pDos = (IMAGE_DOS_HEADER*)ImageBase;

    if (!MmIsAddressValid(pDos) || pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    pNt = (IMAGE_NT_HEADERS*)((ULONG_PTR)ImageBase + pDos->e_lfanew);
    
    if (!MmIsAddressValid(pNt) || pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    return TRUE;
}

//Gets the destination module address
ULONG_PTR KrnlGetModuleBase(UCHAR* pModuleName)
{
    ULONG_PTR ModuleBase = NULL;
    NTSTATUS Status = STATUS_NOT_FOUND;
    ULONG ModuleSize = 0;
    RTL_PROCESS_MODULES* pModules = NULL;
    ULONG i = 0; 
    UCHAR* pCompName = NULL;
    ULONG_PTR dwCompSize = 0;
    
    Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &ModuleSize);
    if (Status != STATUS_INFO_LENGTH_MISMATCH)
        return ModuleBase;
    pModules = (RTL_PROCESS_MODULES*)ExAllocatePoolWithTag(PagedPool, ModuleSize, '0doM');
    if (!pModules)
        return ModuleBase;

    RtlZeroMemory(pModules, ModuleSize);
    Status = ZwQuerySystemInformation(SystemModuleInformation, pModules, ModuleSize, NULL);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(pModules, 0);
        return ModuleBase;
    }

    for (i = 0; i < pModules->NumberOfModules; ++i)
    {
        KrnlGetImageNameByPathA(pModules->Modules[i].FullPathName, &pCompName, &dwCompSize);
        if (_stricmp((const char *)pModuleName, (const char *)pCompName) == 0)
        {
            ModuleBase = (ULONG_PTR)pModules->Modules[i].ImageBase;
            break;
        }
    }

    ExFreePoolWithTag(pModules, 0);
    pModules = NULL;
    
    return ModuleBase;
}

VOID
__cdecl
AkrOsPrint(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
)
{
#if AKROS_DBG == 1
    va_list valist;
    CHAR Buffer[MAX_PATH * 2] = { 0x00 };
    ULONG dwRet = 0;

    va_start(valist, Format);
    dwRet = _vsnprintf_s(Buffer, sizeof(Buffer), Format, valist);
    Buffer[dwRet] = '\0';
    vDbgPrintExWithPrefix("[AKROS_DBG]", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Buffer, valist);
    va_end(valist);

#endif
}