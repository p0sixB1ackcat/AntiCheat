#include "Anti-CheatBase.h"
#include "zwapi.h"

extern GLOBAL_DATA g_Global_Data;

NTSTATUS 
KrnlGetImageNameByPath(
    _In_ UNICODE_STRING* pQueryString,
    _Out_ WCHAR** pImageName, 
    _Out_ ULONG_PTR *pLen
)
{
    NTSTATUS Status;
    WCHAR* pName = NULL;

    pName = pQueryString->Buffer + pQueryString->Length / sizeof(WCHAR);
    Status = STATUS_OBJECT_NAME_NOT_FOUND;

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

NTSTATUS KrnlGetProcessName(_In_ PEPROCESS Eprocess,_Out_ UNICODE_STRING *ProcessName)
{
    NTSTATUS Status = STATUS_OBJECTID_NOT_FOUND;
    KAPC_STATE kapc = { 0x00 };
    ULONG dwRet = 0;
    UNICODE_STRING* pQueryString = NULL;
    WCHAR* pName = NULL;
    ULONG_PTR dwLen = 0;

    if (!ProcessName)
        return Status;

    __try
    {
        KeStackAttachProcess(Eprocess, &kapc);
        
        Status = ZwQueryInformationProcess(NtCurrentProcess(),
            ProcessImageFileName,
            NULL,
            NULL,
            &dwRet);
        if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH)
            __leave;

        pQueryString = (UNICODE_STRING *)ExAllocatePoolWithTag(NonPagedPool, dwRet, '0syS');
        if (!pQueryString)
        {
            Status = STATUS_MEMORY_NOT_ALLOCATED;
            __leave;
        }

        Status = ZwQueryInformationProcess(NtCurrentProcess(),
            ProcessImageFileName,
            pQueryString,
            dwRet,
            &dwRet);
        if (!NT_SUCCESS(Status))
            __leave;

        if (!MmIsAddressValid(pQueryString))
        {
            Status = STATUS_INVALID_ADDRESS;
            __leave;
        }

        Status = KrnlGetImageNameByPath(pQueryString, &pName, &dwLen);
        if (NT_SUCCESS(Status))
        {
            RtlUnicodeStringCbCopyStringN(ProcessName, pName, dwLen);
        }
        __leave;

    }

    __finally
    {
        KeUnstackDetachProcess(&kapc);
    }

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

    KdPrint(("Start White List:********************************************\n"));
    while (pEntry != pListHeader)
    {
        ANTI_CHEAT_BLACK_WHITE_DATA* pWhiteData = CONTAINING_RECORD(pEntry, ANTI_CHEAT_BLACK_WHITE_DATA, m_Entry);
        if (pWhiteData)
        {
            KdPrint(("%ws!\n", pWhiteData->m_ProcessName));
        }
        pEntry = pEntry->Flink;
    }

    KdPrint(("End White List:********************************************\n"));
}

BOOLEAN KrnlCheckPE(VOID* ImageBase, SIZE_T ImageSize)
{
    if (ImageBase == NULL || ImageSize == 0)
        return FALSE;

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)ImageBase;
    IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)((ULONG_PTR)ImageBase + pDos->e_lfanew);
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    return TRUE;
}