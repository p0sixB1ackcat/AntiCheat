#include "Anti-CheatBase.h"
#include "zwapi.h"
#include "Anti-CheatCallback.h"
#include "Anti-CheatMiniFilter.h"
#include "strings.h"

GLOBAL_DATA g_Global_Data = { 0x00 };

#ifdef __cplusplus
extern "C"
{ 
NTSTATUS FindSystemProcess(_In_ HANDLE ProcessId,
    _In_ UNICODE_STRING* ProcessName,
    _Out_ PEPROCESS* pSystemProcess
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
    PSYSTEM_PROCESS_INFORMATION pCurrentProcInfo = NULL;
    ULONG dwRet = 0;

    do
    {
        ntStatus = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwRet);
        if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_INFO_LENGTH_MISMATCH)
            break;
        if (dwRet == 0)
        {
            ntStatus = STATUS_UNSUCCESSFUL;
            break;
        }
        pProcInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(PagedPool, 2 * dwRet,'PsyS');
        if (!pProcInfo)
        {
            ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }

        ntStatus = NtQuerySystemInformation(SystemProcessInformation, pProcInfo, 2 * dwRet,&dwRet);
        if (!NT_SUCCESS(ntStatus))
            break;
        if (dwRet == 0)
        {
            ntStatus = STATUS_UNSUCCESSFUL;
            break;
        }

        pCurrentProcInfo = pProcInfo;
        while (1)
        {
            if (ProcessId != 0)
            {
                if (pCurrentProcInfo->UniqueProcessId == ProcessId)
                {
                    ntStatus = PsLookupProcessByProcessId(pCurrentProcInfo->UniqueProcessId,pSystemProcess);
                    if (!NT_SUCCESS(ntStatus))
                        break;

                    ntStatus = STATUS_SUCCESS;
                    break;
                }
            }
            else
            {
                if (pCurrentProcInfo->ImageName.Buffer != NULL &&
                    RtlCompareUnicodeString(&pCurrentProcInfo->ImageName, ProcessName, FALSE) == 0)
                {
                    ntStatus = PsLookupProcessByProcessId(pCurrentProcInfo->UniqueProcessId,pSystemProcess);
                    if (!NT_SUCCESS(ntStatus))
                        break;

                    ntStatus = STATUS_SUCCESS;
                    break;
                }
            }

            if (pCurrentProcInfo->NextEntryOffset == 0)
                break;

            pCurrentProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrentProcInfo +pCurrentProcInfo->NextEntryOffset);

        }
    } while (FALSE);

    if (pProcInfo)
        ExFreePoolWithTag(pProcInfo, 0);

    return ntStatus;
}
 //Generic distribution function
 NTSTATUS DispatchCommon(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
 {
     NTSTATUS ntStatus = STATUS_SUCCESS;
     pIrp->IoStatus.Status = ntStatus;
     pIrp->IoStatus.Information = 0;

     IoCompleteRequest(pIrp, IO_NO_INCREMENT);

     return ntStatus;
 }

 NTSTATUS StartLoadImageRoutine()
 {
     return PsSetLoadImageNotifyRoutine(AnticheatLoadImageRoutine);
 }

 NTSTATUS StopLoadImageRoutine()
 {
     return PsRemoveLoadImageNotifyRoutine(AnticheatLoadImageRoutine);
 }

 VOID StopObRegisterCallback(VOID)
 {
     ObUnRegisterCallbacks(g_Global_Data.m_ObRegistrationHandle);
 }


 NTSTATUS DispatchIoControl(PDEVICE_OBJECT pDevicceObject, PIRP pIrp)
 {
     NTSTATUS ntStatus = STATUS_SUCCESS;
     IO_STACK_LOCATION* pCurrentIrpStack = IoGetCurrentIrpStackLocation(pIrp);
     ULONG dwControlCode = pCurrentIrpStack->Parameters.DeviceIoControl.IoControlCode;
     WCHAR *pSystemInputBuffer = (WCHAR *)pIrp->AssociatedIrp.SystemBuffer;
     ULONG dwSystemInputSize = pCurrentIrpStack->Parameters.DeviceIoControl.InputBufferLength;
     ULONG_PTR H_KeUserModuleCallback = 0;
     ULONG_PTR Original_KeUserModuleCallback = 0;
     PEPROCESS pEprocess = NULL;
     KAPC_STATE kApcState = { 0x00 };

     //Execute different logicand parse different SystemBuffers according to different control codes
     switch (dwControlCode)
     {
        case ACCTL_CODE_REMOVE_OBCALLBACK:
        {
            StopObRegisterCallback();
        }
        break;
        case ACCTL_CODE_REMOVE_PSLOADIMAGECALLBACK:
        {
            StopLoadImageRoutine();
        }
        break;
     }
     
     pIrp->IoStatus.Status = ntStatus;
     pIrp->IoStatus.Information = 0;
     IoCompleteRequest(pIrp, IO_NO_INCREMENT);
     return ntStatus;
 }

 VOID DriverUnload(PDRIVER_OBJECT pDrvObject)
 {
     UNICODE_STRING uSymboliclinkName = { 0x00 };
     WCHAR lpSymboliclinkName[decltype(EncryptedDosDevicesAntiyCheatString)::Length];

     DecryptString(EncryptedDosDevicesAntiyCheatString, lpSymboliclinkName);
     
     RtlInitUnicodeString(&uSymboliclinkName, lpSymboliclinkName);

     if (g_Global_Data.m_isUnloaded == FALSE)
     {
         g_Global_Data.m_isUnloaded = TRUE;
         //Before uninstalling, close the detection thread, and after confirming that it is closed, perform subsequent work
         KeWaitForSingleObject(&g_Global_Data.m_WaitEvent, Executive, KernelMode, FALSE, 0);
     }

     if(g_Global_Data.m_ObRegistrationHandle)
        ObUnRegisterCallbacks((PVOID)g_Global_Data.m_ObRegistrationHandle);

     StopLoadImageRoutine();

     LockList(&g_Global_Data.m_BlackListLock);
     KrnlRemoveBlackWhiteList(&g_Global_Data.m_BlackListHeader);
     UnlockList(&g_Global_Data.m_BlackListLock);

     LockList(&g_Global_Data.m_WhiteListLock);
     KrnlRemoveBlackWhiteList(&g_Global_Data.m_WhiteListHeader);
     UnlockList(&g_Global_Data.m_WhiteListLock);

     LockList(&g_Global_Data.m_ProtectProcessListLock);
     KrnlRemoveProtectProcessList(&g_Global_Data.m_ProtectProcessListHeader);
     UnlockList(&g_Global_Data.m_ProtectProcessListLock);

     IoDeleteSymbolicLink(&uSymboliclinkName);
     IoDeleteDevice(pDrvObject->DeviceObject);

     RtlSecureZeroMemory(lpSymboliclinkName, decltype(EncryptedDosDevicesAntiyCheatString)::Length);

     KdPrint(("Unload Anti-Cheat!\n"));
 }

 NTSTATUS StartObCallbackRoutine()
 {
     DECLARE_UNICODE_STRING_SIZE(uAltitude, MAX_PATH);
     NTSTATUS Status = STATUS_UNSUCCESSFUL;
     UNICODE_STRING uSystemProcessName = { 0x00 };
     PEPROCESS pEprocess = NULL;
     HANDLE RegHandle = NULL;
     OB_CALLBACK_REGISTRATION obCallBackReg = { 0x00 };
     OB_OPERATION_REGISTRATION obOperationReg = { 0x00 };
     WCHAR lpProessName[decltype(EncryptedLsassString)::Length];
     
     obOperationReg.ObjectType = PsProcessType;
     obOperationReg.PreOperation = AntiCheatOBPreOperationCallback;
     //obOperationReg.PostOperation = AnticheatObPostOperationCallback;
     obOperationReg.Operations = obOperationReg.Operations | OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

     RtlUnicodeStringCbCopyStringN(&uAltitude, L"0x909090", sizeof(L"0x909090")); 
     obCallBackReg.Altitude = uAltitude;
     obCallBackReg.OperationRegistrationCount = 1;
     obCallBackReg.Version = OB_FLT_REGISTRATION_VERSION;
     obCallBackReg.OperationRegistration = &obOperationReg;
     
     Status = ObRegisterCallbacks(&obCallBackReg, (PVOID*)&g_Global_Data.m_ObRegistrationHandle);
     if (!NT_SUCCESS(Status))
         goto finish;
     
     DecryptString(EncryptedLsassString, lpProessName);
     RtlInitUnicodeString(&uSystemProcessName, lpProessName);

     //Not at the moment, but at some point in the future
     Status = FindSystemProcess(0, &uSystemProcessName, &pEprocess);
     RtlSecureZeroMemory(lpProessName, decltype(EncryptedLsassString)::Length);

     if (!NT_SUCCESS(Status))
         goto finish;
     if (pEprocess == NULL)
     {
         Status = STATUS_OBJECTID_NOT_FOUND;
         goto finish;
     }
     KdPrint(("Find lsass.exe Eprocess Address is 0x%x!\n", pEprocess));

 finish:
     return Status;
 }

 NTSTATUS StartAntiyCheat()
 {
     NTSTATUS Status = STATUS_UNSUCCESSFUL;
     
     do 
     {
         Status = StartObCallbackRoutine();
         if(!NT_SUCCESS(Status))
             break;

         Status = StartLoadImageRoutine();
         if (!NT_SUCCESS(Status))
             break;
         
         
         KrnlProtectSelf();

     } while (FALSE);

     return Status;
 }

 NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObject, PUNICODE_STRING pRegPath)
 {
     NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
     ULONG i;
     UNICODE_STRING uDeviceName = { 0x00 };
     UNICODE_STRING uSymboliclinkName = { 0x00 };
     DEVICE_OBJECT* pDeviceObject = { 0x00 };
     WCHAR lpDeviceName[decltype(EncryptedDeviceAntiyCheatString)::Length];
     WCHAR lpSymboliclinkName[decltype(EncryptedDosDevicesAntiyCheatString)::Length];

     do
     {
         DecryptString(EncryptedDeviceAntiyCheatString, lpDeviceName);
         RtlInitUnicodeString(&uDeviceName, lpDeviceName);
         ntStatus = IoCreateDevice(pDrvObject,
             0,
             &uDeviceName,
             FILE_DEVICE_UNKNOWN,
             0,
             FALSE,
             &pDeviceObject
         );

         if (!NT_SUCCESS(ntStatus))
         {
             KdPrint(("Create Device Object Fail:%d!\n", ntStatus));
             break;
         }

         DecryptString(EncryptedDosDevicesAntiyCheatString, lpSymboliclinkName);
         RtlInitUnicodeString(&uSymboliclinkName, lpSymboliclinkName);
         ntStatus = IoCreateSymbolicLink(&uSymboliclinkName, &uDeviceName);

         RtlSecureZeroMemory(lpDeviceName, decltype(EncryptedDeviceAntiyCheatString)::Length);
         RtlSecureZeroMemory(lpSymboliclinkName, decltype(EncryptedDosDevicesAntiyCheatString)::Length);

         if (!NT_SUCCESS(ntStatus))
         {
             KdPrint(("Create SymbolicLink Fail:%d!\n", ntStatus));
             break;
         }

         for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
         {
             pDrvObject->MajorFunction[i] = DispatchCommon;
         }

         pDrvObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
         pDrvObject->DriverUnload = DriverUnload;

         InitializeListHead(&g_Global_Data.m_WhiteListHeader);
         ExInitializeResource(&g_Global_Data.m_WhiteListLock);

         InitializeListHead(&g_Global_Data.m_BlackListHeader);
         ExInitializeResource(&g_Global_Data.m_BlackListLock);

         InitializeListHead(&g_Global_Data.m_ProtectProcessListHeader);
         ExInitializeResource(&g_Global_Data.m_ProtectProcessListLock);

         ntStatus = InitMiniFilter(pDrvObject, pRegPath);
         if(!NT_SUCCESS(ntStatus))
             break;

         //setup Whitelist...
         LockList(&g_Global_Data.m_WhiteListLock);
         UpdateWhiteList(&g_Global_Data.m_WhiteListHeader);
         LookupList(&g_Global_Data.m_WhiteListHeader);
         UnlockList(&g_Global_Data.m_WhiteListLock);

         //setup BlackList
         LockList(&g_Global_Data.m_BlackListLock);
         UpdateBlackList(&g_Global_Data.m_BlackListHeader);
         UnlockList(&g_Global_Data.m_BlackListLock);

         //setup Protect Process
         LockList(&g_Global_Data.m_ProtectProcessListLock);
         UpdateProtectProcessList(&g_Global_Data.m_ProtectProcessListHeader);
         UnlockList(&g_Global_Data.m_ProtectProcessListLock);

         g_Global_Data.m_DriverObject = pDrvObject;

         g_Global_Data.m_isUnloaded = FALSE;
         KeInitializeEvent(&g_Global_Data.m_WaitEvent, NotificationEvent, FALSE);
         //General switch
         ntStatus = StartAntiyCheat();
         if(!NT_SUCCESS(ntStatus))
             break;

     } while (FALSE);

     if (NT_SUCCESS(ntStatus))
     {
         KdPrint(("Anti-Cheat Driver Start Success!\n"));
     }
     else
     {
         if (pDeviceObject)
         {
             g_Global_Data.m_isUnloaded = TRUE;
             DriverUnload(pDrvObject);
         }
     }
     return ntStatus;
 }
#endif

#ifdef __cplusplus
}
#endif