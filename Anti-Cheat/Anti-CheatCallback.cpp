#include "Anti-CheatCallback.h"
#include "zwapi.h"

extern GLOBAL_DATA g_Global_Data;

OB_PREOP_CALLBACK_STATUS
AntiCheatOBPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    NTSTATUS Status = OB_PREOP_SUCCESS;
    DECLARE_UNICODE_STRING_SIZE(pTargetProcName, 260);
    DECLARE_UNICODE_STRING_SIZE(pCurrentProcName, 260);
    SIZE_T szCmpLen = 0;

    do
    {
        Status = KrnlGetProcessName((PEPROCESS)OperationInformation->Object,&pTargetProcName);
        if (!NT_SUCCESS(Status))
            break;
        Status = KrnlGetProcessName((PEPROCESS)PsGetCurrentProcess(), &pCurrentProcName);
        if (!NT_SUCCESS(Status))
            break;

        if (OperationInformation->ObjectType == *PsProcessType)
        {
            if (wcscmp(pTargetProcName.Buffer, L"notepad.exe") == 0)
            {
                KdPrint(("%wZ Access %wZ!\n", &pCurrentProcName, &pTargetProcName));
                szCmpLen = pCurrentProcName.Length / sizeof(WCHAR);
                //When whitelist, release...
                LockList(&g_Global_Data.m_WhiteListLock);
                if (MatchBlackWhitelistByProcessName(&pCurrentProcName, &g_Global_Data.m_WhiteListHeader))
                {
                    Status = OB_PREOP_SUCCESS;
                    UnlockList(&g_Global_Data.m_WhiteListLock);
                    break;
                }
                UnlockList(&g_Global_Data.m_WhiteListLock);

                //Erase relevant access rights
                if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
                {
                    if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) ==
                        PROCESS_VM_OPERATION)
                        (OperationInformation->Parameters->CreateHandleInformation.DesiredAccess) &= ~PROCESS_VM_OPERATION;
                    
                    if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
                        (OperationInformation->Parameters->CreateHandleInformation.DesiredAccess) &= ~PROCESS_VM_READ;

                    if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
                        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
                }
                else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
                {
                    if ((OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
                        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;

                    if ((OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
                        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;

                    if ((OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
                        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= PROCESS_VM_WRITE;
                }

            }
        }

    } while (false);

    return (OB_PREOP_CALLBACK_STATUS)Status;
}

VOID
AnticheatObPostOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
)
{
    KdPrint(("Anti-Cheat:Ob Post Callback!\n"));
}

NTSTATUS Hook_DriverEntryPointer(PDRIVER_OBJECT* pDriverObject, UNICODE_STRING* pRegPath)
{
    return STATUS_UNSUCCESSFUL;
}

VOID
AnticheatLoadImageRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,                
    _In_ PIMAGE_INFO ImageInfo
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PEPROCESS Process = NULL;
    DECLARE_UNICODE_STRING_SIZE(uCurrentProcessName, MAX_PATH);
    UNICODE_STRING uImageName = { 0x00 };
    WCHAR* szImageName = NULL;
    ULONG_PTR ImageNameSize = 0;
    IMAGE_DOS_HEADER* pDos = NULL;
    IMAGE_NT_HEADERS* pNt = NULL;
    PVOID ImageEntryPointer = NULL;
    PMDL pMdl = NULL;
    ULONG Size = 0x10;
    PVOID pNewMapVa = NULL;

    do
    {
        Status = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &Process);
        if (!NT_SUCCESS(Status))
            break;

        KrnlGetProcessName(Process, &uCurrentProcessName);
        
        Status = KrnlGetImageNameByPath(FullImageName, &szImageName, &ImageNameSize);
        if (!NT_SUCCESS(Status))
            break;

        RtlInitUnicodeString(&uImageName, szImageName);
        uImageName.Length = ImageNameSize;

        LockList(&g_Global_Data.m_BlackListLock);

        KdPrint(("%wZ Loading %wZ!\n", &uCurrentProcessName, &uImageName));
        
        //compare target driver
        if (MatchBlackWhitelistByProcessName(&uImageName, &g_Global_Data.m_BlackListHeader))
        {
            //x it
            pDos = (IMAGE_DOS_HEADER*)ImageInfo->ImageBase;
            if (!MmIsAddressValid(pDos) || pDos->e_magic != IMAGE_DOS_SIGNATURE)
                goto finish;

            pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDos + pDos->e_lfanew);
            if (!MmIsAddressValid(pNt) || pNt->Signature != IMAGE_NT_SIGNATURE)
                goto finish;

            if (pNt->OptionalHeader.AddressOfEntryPoint == 0)
            {
                pNt->OptionalHeader.AddressOfEntryPoint = pNt->OptionalHeader.BaseOfCode;
            }

            ImageEntryPointer = (PVOID)(ULONG_PTR)(pNt->OptionalHeader.ImageBase + pNt->OptionalHeader.AddressOfEntryPoint);

            pMdl = IoAllocateMdl(ImageEntryPointer, Size, FALSE, FALSE, NULL);
            if (!pMdl)
                goto finish;

            MmBuildMdlForNonPagedPool(pMdl);

            __try
            {
                pNewMapVa = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
            }
            __finally
            {
                KdPrint(("MmMapLockedPagesSpecifyCache Fail!\n"));
            }
            if (pNewMapVa)
            {
                RtlCopyMemory(pNewMapVa, Hook_DriverEntryPointer, 0x10);
                MmUnmapLockedPages(pNewMapVa, pMdl);
            }
            
            IoFreeMdl(pMdl);

            UnlockList(&g_Global_Data.m_BlackListLock);
            break;
        }
        finish:
        UnlockList(&g_Global_Data.m_BlackListLock);

    } while (FALSE);

    return;
}

FLT_PREOP_CALLBACK_STATUS
AnticheatFltAcquireSectionSyncPreRoutine(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    FLT_FILE_NAME_INFORMATION *pFileInfo = NULL;
    PEPROCESS EprocessOperation;
    HANDLE ProcessId = NULL;
    DECLARE_UNICODE_STRING_SIZE(uOperationProcessPath, MAX_PATH);
    WCHAR* pTargetImageName;
    ULONG_PTR dwRet = 0;
    LARGE_INTEGER Offset = { 0x00 };
    ULONG dwBufferSize = 0;
    PUCHAR pTargetImageBuffer = NULL;
    BOOLEAN bIs = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection)
    {
        status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pFileInfo);
        if (!NT_SUCCESS(status))
            goto finish;

        ProcessId = PsGetThreadProcessId(Data->Thread);

        status = PsLookupProcessByProcessId(ProcessId, &EprocessOperation);
        if (!NT_SUCCESS(status))
            goto finish;
        status = KrnlGetProcessName(EprocessOperation, &uOperationProcessPath);
        if (!NT_SUCCESS(status))
            goto finish;

        KrnlGetImageNameByPath(&pFileInfo->Name, &pTargetImageName, &dwRet);

        pTargetImageBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, 0x1000, 'khC');
        if (!pTargetImageBuffer)
            goto finish;

        status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &Offset, 0x1000, pTargetImageBuffer, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &dwBufferSize, NULL, NULL);
        if (!NT_SUCCESS(status))
            goto finish;
        if (!KrnlCheckPE(pTargetImageBuffer, 0x1000))
        {
            goto finish;
        }
        
        //KdPrint(("%wZ Create Section With %ws!\n", uOperationProcessPath, pTargetImageName));
        if(MatchBlackWhitelistByProcessName(&uOperationProcessPath,&g_Global_Data.m_BlackListHeader))
        {
            if (_wcsicmp(pTargetImageName, L"Ring3App.exe") == 0)
            {
                bIs = TRUE;
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                goto finish;
            }
            
        }
    }

finish:
    if (pFileInfo)
        FltReleaseFileNameInformation(pFileInfo);
    if (pTargetImageBuffer)
        ExFreePoolWithTag(pTargetImageBuffer, 0);
    if (bIs)
    {
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
AntiCheatFltAcquireSectionSyncPostRoutine(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}