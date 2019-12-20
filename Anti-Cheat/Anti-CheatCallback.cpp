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
    KAPC_STATE kApc = { 0x00 };
    
    Status = KrnlGetProcessName((PEPROCESS)PsGetCurrentProcess(), &pCurrentProcName);
    if (!NT_SUCCESS(Status))
        goto ret;

    __try
    {
        KeStackAttachProcess((PEPROCESS)OperationInformation->Object, &kApc);
        Status = KrnlGetProcessName((PEPROCESS)OperationInformation->Object, &pTargetProcName);
        if (!NT_SUCCESS(Status))
            __leave;

        if (OperationInformation->ObjectType == *PsProcessType)
        {
            LockList(&g_Global_Data.m_ProtectProcessListLock);
            //if (wcscmp(pTargetProcName.Buffer, L"Target.exe") == 0)
            if(KrnlIsProtectName(&pTargetProcName, &g_Global_Data.m_ProtectProcessListHeader))
            {
                UnlockList(&g_Global_Data.m_ProtectProcessListLock);

                //When whitelist or process self, release...
                LockList(&g_Global_Data.m_WhiteListLock);
                if (MatchBlackWhitelistByProcessName(&pCurrentProcName, &g_Global_Data.m_WhiteListHeader))
                {
                    AkrOsPrint("WhiteList Process %wZ ACCESS READ/WRITE/QUERY %wZ!\n", &pCurrentProcName, &pTargetProcName);
                    Status = OB_PREOP_SUCCESS;
                    UnlockList(&g_Global_Data.m_WhiteListLock);
                    __leave;
                }
                
                UnlockList(&g_Global_Data.m_WhiteListLock);

                //Erase relevant access rights
                if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
                {
                    if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) ==
                        PROCESS_VM_OPERATION)
                    {
                        (OperationInformation->Parameters->CreateHandleInformation.DesiredAccess) &= ~PROCESS_VM_OPERATION;
                    }  

                    if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
                    {
                        (OperationInformation->Parameters->CreateHandleInformation.DesiredAccess) &= ~PROCESS_VM_READ;
                    }   

                    if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
                    {
                        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
                    } 
                }
                else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
                {
                    if ((OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
                    {
                        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
                    }  

                    if ((OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
                    {
                        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
                    }   
                    if ((OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
                    {
                        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= PROCESS_VM_WRITE;
                    }  
                }
            }
            else
            {
                UnlockList(&g_Global_Data.m_ProtectProcessListLock);
            }
        }
    }
    __finally
    {
        KeUnstackDetachProcess(&kApc);
    }
    ret:
    return (OB_PREOP_CALLBACK_STATUS)Status;
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

    //For driverentry that overrides the target driver, 10 bytes is sufficient
    ULONG Size = 0x10;
    PVOID pNewMapVa = NULL;
    KAPC_STATE kApc = { 0x00 };
    wchar_t* pExeName = NULL;

    PROCESS_BASIC_INFORMATION ProcInfo = { 0x00 };
    ULONG dwInfoSize = 0;

    Status = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &Process);
    if (!NT_SUCCESS(Status))
        goto ret;

    __try
    {
        KeStackAttachProcess(Process, &kApc);
        KrnlGetProcessName(Process, &uCurrentProcessName);

        Status = KrnlGetImageNameByPath(FullImageName, &szImageName, &ImageNameSize);
        if (!NT_SUCCESS(Status))
            __leave;
        
    }
    __finally
    {
        KeUnstackDetachProcess(&kApc);
    }

    RtlInitUnicodeString(&uImageName, szImageName);
    uImageName.Length = ImageNameSize;

    pDos = (IMAGE_DOS_HEADER*)ImageInfo->ImageBase;
    if (!MmIsAddressValid(pDos) || pDos->e_magic != IMAGE_DOS_SIGNATURE)
        goto ret;

    pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDos + pDos->e_lfanew);
    if (!MmIsAddressValid(pNt) || pNt->Signature != IMAGE_NT_SIGNATURE)
        goto ret;

    pExeName = wcschr(uImageName.Buffer, L'.');
    if (!pExeName)
        goto ret;

    //compare target driver With Black List
    LockList(&g_Global_Data.m_BlackListLock);
    if (MatchBlackWhitelistByProcessName(&uImageName, &g_Global_Data.m_BlackListHeader))
    {
        //Load .sys
        //if (wcscmp(pExeName, L".sys") == 0)
        if(ProcessId == (HANDLE)0)
        {
            if (pNt->OptionalHeader.AddressOfEntryPoint == 0)
            {
                pNt->OptionalHeader.AddressOfEntryPoint = pNt->OptionalHeader.BaseOfCode;
            }

            ImageEntryPointer = (PVOID)(ULONG_PTR)(pNt->OptionalHeader.ImageBase + pNt->OptionalHeader.AddressOfEntryPoint);

            pMdl = IoAllocateMdl(ImageEntryPointer, Size, FALSE, FALSE, NULL);
            if (!pMdl)
                goto finish;

            MmProbeAndLockPages(pMdl, KernelMode, (LOCK_OPERATION)(IoReadAccess | IoWriteAccess | IoModifyAccess));
            
            __try
            {
                pNewMapVa = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
            }
            __finally
            {
                AkrOsPrint("MmMapLockedPagesSpecifyCache Fail!\n");
            }
            if (pNewMapVa)
            {
                RtlCopyMemory(pNewMapVa, Hook_DriverEntryPointer, 0x10);
                MmUnmapLockedPages(pNewMapVa, pMdl);
            }

            IoFreeMdl(pMdl);
        }
        else if (wcscmp(pExeName, L".exe") == 0)
        {
            __try
            {
                KeStackAttachProcess(Process, &kApc);
                Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &ProcInfo, sizeof(PROCESS_BASIC_INFORMATION),&dwInfoSize);
                if (!NT_SUCCESS(Status))
                    __leave;

            }
            __finally
            {
                KeUnstackDetachProcess(&kApc);
            }
        }
    }
finish:
    UnlockList(&g_Global_Data.m_BlackListLock);

    //Load Dll
    //For loading DLLS, block loading if the target process is protected
    if ((pNt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0)
    {
        LockList(&g_Global_Data.m_ProtectProcessListLock);
        //if it is Protect Process
        if (KrnlIsProtectName(&uCurrentProcessName, &g_Global_Data.m_ProtectProcessListHeader))
        {
            //This is reserved for future use
        }
        UnlockList(&g_Global_Data.m_ProtectProcessListLock);
    }

ret:
    if(Process)
        ObDereferenceObject(Process);
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
    PEPROCESS EprocessOperation = NULL;
    HANDLE ProcessId = NULL;
    DECLARE_UNICODE_STRING_SIZE(uOperationProcessPath, MAX_PATH);
    WCHAR* pTargetImageName = NULL;
    UNICODE_STRING uniStr = { 0x00 };
    ULONG_PTR dwRet = 0;
    LARGE_INTEGER Offset = { 0x00 };
    ULONG dwBufferSize = 0;
    PUCHAR pTargetImageBuffer = NULL;
    BOOLEAN bIs = FALSE;
    KAPC_STATE kApc = { 0x00 };

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pFileInfo);
    if (!NT_SUCCESS(status))
        goto finish;

    ProcessId = (HANDLE)FltGetRequestorProcessId(Data);

    status = PsLookupProcessByProcessId(ProcessId, &EprocessOperation);
    if (!NT_SUCCESS(status))
        goto finish;

    __try
    {
        KeStackAttachProcess(EprocessOperation, &kApc);

        status = KrnlGetProcessName(EprocessOperation, &uOperationProcessPath);
    }
    __finally
    {
        KeUnstackDetachProcess(&kApc);
    }

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
        goto finish;

    RtlInitUnicodeString(&uniStr, pTargetImageName);
    LockList(&g_Global_Data.m_ProtectProcessListLock);
    
    if (KrnlIsProtectName(&uniStr, &g_Global_Data.m_ProtectProcessListHeader) &&
        Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection
        )
    {
        UnlockList(&g_Global_Data.m_ProtectProcessListLock);
        if ((Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection & PAGE_EXECUTE) == 0)
            goto finish;
        AkrOsPrint("%wZ Create Section With %ws!\n", uOperationProcessPath, pTargetImageName);

        LockList(&g_Global_Data.m_WhiteListLock);
        if (!MatchBlackWhitelistByProcessName(&uOperationProcessPath, &g_Global_Data.m_WhiteListHeader))
        {
            bIs = TRUE;
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        }

        UnlockList(&g_Global_Data.m_WhiteListLock);
    }
    else
    {
        UnlockList(&g_Global_Data.m_ProtectProcessListLock);
    }

finish:
    if (EprocessOperation)
        ObDereferenceObject(EprocessOperation);
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

VOID
AntiCheatCreateProcessNotifyRoutine(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PEPROCESS Eprocess = NULL;
    KAPC_STATE kApc = { 0x00 };
    DECLARE_UNICODE_STRING_SIZE(uCurrentProcessName, MAX_PATH);
    ULONG dwRet = 0;
    LIST_ENTRY* pEntry = NULL;
    ANTI_CHEAT_PROTECT_PROCESS_DATA* pProtectData = NULL;
    
    if (Create == TRUE)
    {
        do 
        {
            Status = PsLookupProcessByProcessId(ProcessId, &Eprocess);
            if (!NT_SUCCESS(Status))
                return;

            __try
            {
                KeStackAttachProcess(Eprocess, &kApc);
                KrnlGetProcessName(Eprocess, &uCurrentProcessName);
                if (!NT_SUCCESS(Status))
                    __leave;

            }
            __finally
            {
                KeUnstackDetachProcess(&kApc);
            }

            LockList(&g_Global_Data.m_ProtectProcessListLock);
            if (IsListEmpty(&g_Global_Data.m_ProtectProcessListHeader))
            {
                UnlockList(&g_Global_Data.m_ProtectProcessListLock);
                break;
            }

            pEntry = g_Global_Data.m_ProtectProcessListHeader.Flink;
            UnlockList(&g_Global_Data.m_ProtectProcessListLock);
            pProtectData = CONTAINING_RECORD(pEntry, ANTI_CHEAT_PROTECT_PROCESS_DATA, m_Entry);
            if (!pProtectData || !MmIsAddressValid(pProtectData))
                break;

            //Find Protect.exe is Create...
            if (_wcsnicmp(uCurrentProcessName.Buffer, pProtectData->m_Name,wcslen(pProtectData->m_Name)) == 0)
            {
                //Wake up waiting for
                KeSetEvent(&g_Global_Data.m_WaitProcessEvent, IO_NO_INCREMENT, FALSE);
            }

        } while (FALSE);

        if(Eprocess)
            ObDereferenceObject(Eprocess);
    }

}