#include "Anti-CheatCallback.h"
#include "zwapi.h"


#define PSP_MAX_LOAD_IMAGE_NOTIFY 8

BOOLEAN KrnlCheckLoadImageNorifyRoutineCallback(VOID)
{
    BOOLEAN bRet = TRUE;
    PEX_CALLBACK_ROUTINE_BLOCK *PspLoadImageNotifyRoutines = 0;
    ULONG_PTR *pCallback = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i;
    
    do
    {
        Status = KrnlGetPspLoadImageNotifyRoutine((PULONG_PTR)&PspLoadImageNotifyRoutines);
        if (!NT_SUCCESS(Status) || PspLoadImageNotifyRoutines == NULL)
            break;

        //dq *PspLoadImageNotifyRoutine
        //fffff800`d4894cf0  ffff980d`c8ce101f ffff980d`c8dd660f
        //fffff800`d4894d00  ffff980d`cac620bf 00000000`00000000
        //dq ffff980d`cac620bf & (~0111b)
        //ffff980d`cac620b8  fffff800`d3b34960 00000000`00000000
        //ffff980d`cac620c8  badbadfa`badbadfa 616d6553`02080003
         //AnticheatLoadImageNotifyRoutine = fffff800`d3b34960
        
        for (i = 0; i < PSP_MAX_LOAD_IMAGE_NOTIFY; ++i)
        {
            //last is null,ret FALSE
            if (PspLoadImageNotifyRoutines[i] == NULL)
            {
                bRet = FALSE;
                break;
            }
            
            //The callback function address is handled by referring to WRK
            pCallback = (ULONG_PTR *)((ULONG_PTR)PspLoadImageNotifyRoutines[i] & (~7));
            if (*pCallback == (ULONG_PTR)AnticheatLoadImageRoutine)
                break;
        }

    } while (FALSE);

    return bRet;
}


extern GLOBAL_DATA g_Global_Data;
extern SYSTEM_DYNAMIC_DATA g_System_Dynamic_Data;

BOOLEAN KrnlCheckObCallbackRoutine(PVOID pObRegistrationHandle)
{
    BOOLEAN bRemObCallBackRoutine = TRUE;
    POBCALLBACK_NODE pCallbackNode = (POBCALLBACK_NODE)pObRegistrationHandle;
    LIST_ENTRY* pEntry = NULL;   
    LIST_ENTRY* Flink = NULL;
    LIST_ENTRY* Blink = NULL;
    OBCALLBACK_BODY *pCallbackBody = {0x00};
    ULONG i = 0;

    //Traverse callbackbody
    if (pCallbackNode->usCallbackBodyCount > 0)
    {
        for (i = 0; i < pCallbackNode->usCallbackBodyCount; ++i)
        {
            pCallbackBody = &pCallbackNode->CallbackBodies[i];

            //Before access, the spin lock is exclusive
            ExAcquirePushLockExclusiveEx((PULONG_PTR)&(((OBJECT_TYPE*)pCallbackBody->pObjectType)->TypeLock), 0);

            //Determine if our callbackbody->ListEntry.flink->Blink & callbackbody->ListEntry.Blink->Flink is pointing to ourselves
            Flink = pCallbackBody->ListEntry.Flink;
            Blink = pCallbackBody->ListEntry.Blink;
            pEntry = &pCallbackBody->ListEntry;
            if (Flink->Blink == pEntry &&
                Blink->Flink == pEntry)
            {
                bRemObCallBackRoutine = FALSE;
            }
            ExReleasePushLockExclusiveEx((PULONG_PTR)&((OBJECT_TYPE*)pCallbackBody->pObjectType)->TypeLock, 0);
        }
    }

    return !bRemObCallBackRoutine;
}

constexpr
FORCEINLINE
LONGLONG
KrnlMsToTicks(
    _In_ ULONG Milliseconds
)
{
    return 10000LL * (LONGLONG)(Milliseconds);
}

FORCEINLINE
VOID
KrnlSleep(
    _In_ ULONG Milliseconds
)
{
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -1 * KrnlMsToTicks(Milliseconds);
    KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
}

BOOLEAN ProtectProcessIsPresent(VOID)
{
    BOOLEAN bRet = TRUE;
    LIST_ENTRY* pEntry = NULL;
    ANTI_CHEAT_PROTECT_PROCESS_DATA* pData = NULL;

    if (IsListEmpty(&g_Global_Data.m_ProtectProcessListHeader))
        return bRet;
    LockList(&g_Global_Data.m_ProtectProcessListLock);
    pEntry = g_Global_Data.m_ProtectProcessListHeader.Flink;
    pData = CONTAINING_RECORD(pEntry, ANTI_CHEAT_PROTECT_PROCESS_DATA, m_Entry);
    if (!pData || !MmIsAddressValid(pData))
        goto ret;
    if (!pData->m_Eprocess || !MmIsAddressValid(pData->m_Eprocess))
        goto ret;
    //EPROCESS->Flags == 0 (WIN8.1) || EPROCESS->Flags.ProcessExiting is 1 (WIN10),Note Process is Over...
    if (*(ULONG *)((PUCHAR)pData->m_Eprocess + g_System_Dynamic_Data.EProcessFlags2Offset) == 0 ||
        (*(UCHAR *)((UCHAR*)pData->m_Eprocess + g_System_Dynamic_Data.EProcessFlagsOffset) & (~0xfb)) >> 2 == 1)
        bRet = FALSE;

ret:
    UnlockList(&g_Global_Data.m_ProtectProcessListLock);
    return bRet;
}

//A thread specifically used for detection
VOID ProtectWorkThread(PVOID pThreadContext)
{
    UNREFERENCED_PARAMETER(pThreadContext);

    while (1)
    {
        //If DriverUnload is performed, the thread needs to be terminated first
        if (g_Global_Data.m_isUnloaded)
        {
            PsTerminateSystemThread(STATUS_SUCCESS);
        }

        //Check ObRegisterCallbackRoutine
        if (!KrnlCheckObCallbackRoutine((PVOID*)g_Global_Data.m_ObRegistrationHandle))
        {
            AkrOsPrint("ObCallback is Removed, So,here is BSOD!\n");
            ASSERT(FALSE);
        }
        if (!KrnlCheckLoadImageNorifyRoutineCallback())
        {
            AkrOsPrint("PsLoadImageCallbackNotifyRoutine is Removed!\n");
            ASSERT(FALSE);
        }
        if (!ProtectProcessIsPresent())
        {
            AkrOsPrint("Protect Process is Over...!\n");

            //reset Unload Function...
            g_Global_Data.m_DriverObject->DriverUnload = DriverUnload;
            PsTerminateSystemThread(STATUS_SUCCESS);
        }

        //Find Protect Process.exe, Don't Unload...
        if (g_Global_Data.m_DriverObject->DriverUnload != NULL)
        {
            g_Global_Data.m_DriverObject->DriverUnload = NULL;
        }

        //sleep 3 second
        KrnlSleep(3000);
    }
}

VOID Protect(PVOID pContext)
{
    UNREFERENCED_PARAMETER(pContext);

    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE hThread = NULL;
    PVOID pThreadObject = NULL;

    Status = PsCreateSystemThread(&hThread,
        0,
        NULL,
        (HANDLE)0,
        NULL,
        ProtectWorkThread,
        NULL);

    if (!NT_SUCCESS(Status))
        return;

    Status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &pThreadObject, NULL);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(hThread);
    }

    KeWaitForSingleObject(pThreadObject, Executive, KernelMode, FALSE, NULL);
    if(g_Global_Data.m_isUnloaded)
        KeSetEvent(&g_Global_Data.m_WaitUnloadEvent, IO_NO_INCREMENT, FALSE);
    else
    {
        StopAntiCheat();
        KeSetEvent(&g_Global_Data.m_ProtectProcessOverEvent, IO_NO_INCREMENT, FALSE);
    }
    
    ObDereferenceObject(pThreadObject);
    ZwClose(hThread);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

//Protection of related functions of the main switch function
VOID KrnlProtectSelf(VOID)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE hThread = NULL;

    Status = PsCreateSystemThread(&hThread,
        0,
        NULL,
        (HANDLE)0,
        NULL,
        Protect,
        NULL);
    
    ZwClose(hThread);
}