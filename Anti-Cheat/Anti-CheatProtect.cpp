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
                ExReleasePushLockExclusiveEx((PULONG_PTR)&((OBJECT_TYPE*)pCallbackBody->pObjectType)->TypeLock, 0);
                break;
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

//A thread specifically used for detection
VOID ProtectWorkThread(PVOID pThreadContext)
{
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
        //sleep 3 second
        KrnlSleep(3000);
    }
}

VOID Protect(PVOID pContext)
{
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
    KeSetEvent(&g_Global_Data.m_WaitEvent, IO_NO_INCREMENT, FALSE);
    ObDereferenceObject(pThreadObject);
    ZwClose(hThread);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

//Protection of related functions of the main switch function
VOID KrnlProtectSelf(VOID)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE hThread = NULL;
    PVOID pThreadObject = NULL;

    Status = PsCreateSystemThread(&hThread,
        0,
        NULL,
        (HANDLE)0,
        NULL,
        Protect,
        NULL);
    
    ZwClose(hThread);
}