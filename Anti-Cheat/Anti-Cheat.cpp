#include "Anti-CheatBase.h"
#include "zwapi.h"
#include "Anti-CheatCallback.h"
#include "Anti-CheatMiniFilter.h"
#include "strings.h"

GLOBAL_DATA g_Global_Data = { 0x00 };
SYSTEM_DYNAMIC_DATA g_System_Dynamic_Data;

#ifdef __cplusplus
extern "C"
{ 
NTSTATUS FindSystemProcess(_In_ HANDLE ProcessId,
    _In_ UNICODE_STRING* ProcessName,
    _Out_ PEPROCESS* pSystemProcess
)
{
    NTSTATUS ntStatus = STATUS_NOT_FOUND;
    PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
    PSYSTEM_PROCESS_INFORMATION pCurrentProcInfo = NULL;
    ULONG dwRet = 0;
    LIST_ENTRY* pEntry = NULL;
    ANTI_CHEAT_PROTECT_PROCESS_DATA* pCheatData;

    do
    {
        ntStatus = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwRet);
        if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_INFO_LENGTH_MISMATCH)
            break;
        if (dwRet == 0)
        {
            ntStatus = STATUS_NOT_FOUND;
            break;
        }
        pProcInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(PagedPool, 2 * dwRet,'PsyS');
        if (!pProcInfo)
        {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ntStatus = NtQuerySystemInformation(SystemProcessInformation, pProcInfo, 2 * dwRet,&dwRet);
        if (!NT_SUCCESS(ntStatus))
            break;
        if (dwRet == 0)
        {
            ntStatus = STATUS_NOT_FOUND;
            break;
        }

        pCurrentProcInfo = pProcInfo;
        while (1)
        {
            //reset ntStatus
            ntStatus = STATUS_NOT_FOUND;
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
                    ntStatus = PsLookupProcessByProcessId(pCurrentProcInfo->UniqueProcessId, pSystemProcess);
                    if (!NT_SUCCESS(ntStatus))
                        break;

                    LockList(&g_Global_Data.m_ProtectProcessListLock);

                    do 
                    {
                        if (IsListEmpty(&g_Global_Data.m_ProtectProcessListHeader))
                        {
                            ntStatus = STATUS_NOT_FOUND;
                            break;
                        }

                        pEntry = g_Global_Data.m_ProtectProcessListHeader.Flink;
                        if (!pEntry || !MmIsAddressValid(pEntry))
                        {
                            ntStatus = STATUS_NOT_FOUND;
                            break;
                        }

                        pCheatData = CONTAINING_RECORD(pEntry, ANTI_CHEAT_PROTECT_PROCESS_DATA, m_Entry);
                        if (!pCheatData || !MmIsAddressValid(pCheatData))
                        {
                            ntStatus = STATUS_NOT_FOUND;
                            break;
                        }

                        pCheatData->m_Eprocess = *pSystemProcess;

                        ntStatus = STATUS_SUCCESS;

                    } while (FALSE);

                    
                    UnlockList(&g_Global_Data.m_ProtectProcessListLock);
                    
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
     UNREFERENCED_PARAMETER(pDeviceObject);

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

 VOID RemoveObCallback()
 {
     ObUnRegisterCallbacks((PVOID)g_Global_Data.m_ObRegistrationHandle);
     g_Global_Data.m_IsSetObCallback = FALSE;
 }

 NTSTATUS StopLoadImageRoutine()
 {
     NTSTATUS Status = STATUS_UNSUCCESSFUL;
     Status = PsRemoveLoadImageNotifyRoutine(AnticheatLoadImageRoutine);
     if (NT_SUCCESS(Status))
     {
         g_Global_Data.m_IsSetPsSetLoadImage = FALSE;
     }
     return Status;
 }

 VOID StopObRegisterCallback(VOID)
 {
     ObUnRegisterCallbacks(g_Global_Data.m_ObRegistrationHandle);
     g_Global_Data.m_IsSetObCallback = FALSE;
 }

 NTSTATUS DispatchIoControl(PDEVICE_OBJECT pDevicceObject, PIRP pIrp)
 {
     UNREFERENCED_PARAMETER(pDevicceObject);

     NTSTATUS ntStatus = STATUS_SUCCESS;
     IO_STACK_LOCATION* pCurrentIrpStack = IoGetCurrentIrpStackLocation(pIrp);
     ULONG dwControlCode = pCurrentIrpStack->Parameters.DeviceIoControl.IoControlCode;
     KAPC_STATE kApcState = { 0x00 };

     //Execute different logicand parse different SystemBuffers according to different control codes
     switch (dwControlCode)
     {
        case ACCTL_CODE_CONFIG:
        {
            StopObRegisterCallback();
        }
        break;
     }
     
     pIrp->IoStatus.Status = ntStatus;
     pIrp->IoStatus.Information = 0;
     IoCompleteRequest(pIrp, IO_NO_INCREMENT);
     return ntStatus;
 }

 VOID StopAntiCheat(VOID)
 {
     if (g_Global_Data.m_isUnloaded)
     {
         //Only if everything is initialized successfully,Indicates that the protection thread is open and needs to wait for unloading

         //for g_Global_Data.m_IsInitMiniFilter, FltUnRegisterFilter,This is set to FALSE, so don't need to judge this field   
         if (g_Global_Data.m_IsSetObCallback &&
             g_Global_Data.m_IsSetPsSetLoadImage)
         {
             //Before uninstalling, close the detection thread, and after confirming that it is closed, perform subsequent work
             KeWaitForSingleObject(&g_Global_Data.m_WaitUnloadEvent, Executive, KernelMode, FALSE, NULL);
             //Until then, in ProtectThreadWork, the sleeping tasks are not complete, and wait for them to finish
             KrnlSleep(5000);
         }

         //If the system thread created by the driver is still waiting for the protection process while unloading, we need to set the event to wake up the wait
         KeSetEvent(&g_Global_Data.m_WaitProcessEvent, IO_NO_INCREMENT, FALSE);
     }

     //Wait a minute 
     KrnlSleep(1000);

     if (g_Global_Data.m_IsSetObCallback)
     {
         RemoveObCallback();
     }
     if (g_Global_Data.m_IsSetPsSetLoadImage)
     {
         StopLoadImageRoutine();
     }
     if (g_Global_Data.m_IsInitMiniFilter)
     {
         UnloadMiniFilter(0);
     }
 }

 VOID DriverUnload(PDRIVER_OBJECT pDrvObject)
 {
     UNICODE_STRING uSymboliclinkName = { 0x00 };
     WCHAR lpSymboliclinkName[decltype(EncryptedDosDevicesAntiyCheatString)::Length];

     DecryptString(EncryptedDosDevicesAntiyCheatString, lpSymboliclinkName);
     
     RtlInitUnicodeString(&uSymboliclinkName, lpSymboliclinkName);

     if (g_Global_Data.m_isUnloaded == FALSE)
         g_Global_Data.m_isUnloaded = TRUE;
     //close Protect...
     StopAntiCheat();

     LockList(&g_Global_Data.m_BlackListLock);
     KrnlRemoveBlackWhiteList(&g_Global_Data.m_BlackListHeader);
     UnlockList(&g_Global_Data.m_BlackListLock);

     LockList(&g_Global_Data.m_WhiteListLock);
     KrnlRemoveBlackWhiteList(&g_Global_Data.m_WhiteListHeader);
     UnlockList(&g_Global_Data.m_WhiteListLock);

     LockList(&g_Global_Data.m_ProtectProcessListLock);
     KrnlRemoveProtectProcessList(&g_Global_Data.m_ProtectProcessListHeader);
     UnlockList(&g_Global_Data.m_ProtectProcessListLock);

     ExDeleteResourceLite(&g_Global_Data.m_WhiteListLock);
     ExDeleteResourceLite(&g_Global_Data.m_BlackListLock);
     ExDeleteResourceLite(&g_Global_Data.m_ProtectProcessListLock);
     
     IoDeleteSymbolicLink(&uSymboliclinkName);
     IoDeleteDevice(pDrvObject->DeviceObject);

     RtlSecureZeroMemory(lpSymboliclinkName, decltype(EncryptedDosDevicesAntiyCheatString)::Length);

     AkrOsPrint(("Unload Anti-Cheat!\n"));
 }

 NTSTATUS StartObCallbackRoutine()
 {
     DECLARE_UNICODE_STRING_SIZE(uAltitude, MAX_PATH);
     NTSTATUS Status = STATUS_UNSUCCESSFUL;
     UNICODE_STRING uSystemProcessName = { 0x00 };
     OB_CALLBACK_REGISTRATION obCallBackReg = { 0x00 };
     OB_OPERATION_REGISTRATION obOperationReg = { 0x00 };
     
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
     
     return Status;
 }

 NTSTATUS StartAntiyCheat()
 {
     NTSTATUS Status = STATUS_UNSUCCESSFUL;
     
     do 
     {
         Status = InitMiniFilter(g_Global_Data.m_DriverObject);
         if (!NT_SUCCESS(Status))
             break;
         g_Global_Data.m_IsInitMiniFilter = TRUE;

         Status = StartObCallbackRoutine();
         if(!NT_SUCCESS(Status))
             break;
         g_Global_Data.m_IsSetObCallback = TRUE;

         Status = StartLoadImageRoutine();
         if (!NT_SUCCESS(Status))
             break;

         g_Global_Data.m_IsSetPsSetLoadImage = TRUE;
         KrnlProtectSelf();

     } while (FALSE);

     return Status;
 }

VOID AntiCheatWork(PVOID pContext)
 {
     NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
     LIST_ENTRY* pEntry = NULL;
     ANTI_CHEAT_PROTECT_PROCESS_DATA* ProtectData = NULL;
     PEPROCESS ProtectEprocess = NULL;
     UNICODE_STRING uProcessName = { 0x00 };
     PVOID pObjects[2] = {0x00};

     __try
     {
         LockList(&g_Global_Data.m_ProtectProcessListLock);
         if (IsListEmpty(&g_Global_Data.m_ProtectProcessListHeader))
         {
             UnlockList(&g_Global_Data.m_ProtectProcessListLock);
             __leave;
         }
         pEntry = g_Global_Data.m_ProtectProcessListHeader.Flink;

         UnlockList(&g_Global_Data.m_ProtectProcessListLock);

         ProtectData = CONTAINING_RECORD(pEntry, ANTI_CHEAT_PROTECT_PROCESS_DATA, m_Entry);
         if (!ProtectData || !MmIsAddressValid(ProtectData))
             __leave;

         RtlInitUnicodeString(&uProcessName, ProtectData->m_Name);

         ntStatus = FindSystemProcess(0, &uProcessName, &ProtectEprocess);
         if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_NOT_FOUND)
             __leave;
         if (ntStatus == STATUS_NOT_FOUND)
         {
             PsSetCreateProcessNotifyRoutine(AntiCheatCreateProcessNotifyRoutine, FALSE);

             AkrOsPrint("Wait Protect %wZ..........!\n", &uProcessName);
              
             //Wait for the protection process to start
             KeWaitForSingleObject(&g_Global_Data.m_WaitProcessEvent, Executive, KernelMode, FALSE, NULL);
             PsSetCreateProcessNotifyRoutine(AntiCheatCreateProcessNotifyRoutine, TRUE);
         }

         //If the WaitProcessEvent is not awakened by the unload
         if (!g_Global_Data.m_isUnloaded)
         {
             //Wait Protect Process Init...
             KrnlSleep(5000);

             AkrOsPrint("Find Launch Protect Process:%wZ!\n", &uProcessName);

             //General switch
             ntStatus = StartAntiyCheat();
             if (!NT_SUCCESS(ntStatus))
                 __leave;
         }
     }
     __finally
     {
         pObjects[0] = (PVOID)&g_Global_Data.m_WaitUnloadEvent;
         pObjects[1] = (PVOID)&g_Global_Data.m_ProtectProcessOverEvent;
         
         KeWaitForMultipleObjects(2, pObjects, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);

         if (g_Global_Data.m_isUnloaded)
         {
             KeSetEvent(&g_Global_Data.m_WaitUnloadEvent, IO_NO_INCREMENT, FALSE);
             PsTerminateSystemThread(ntStatus);
         }  
         else
         {
             AntiCheatWork(pContext);
         }
     }
 }

 /*
    1¡¢Install Anti-Cheat.inf File"

    2¡¢cmd.exe execute Command "net start Anti-Cheat

 */
 NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObject, PUNICODE_STRING pRegPath)
 {
     UNREFERENCED_PARAMETER(pRegPath);

     NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
     ULONG i;
     UNICODE_STRING uDeviceName = { 0x00 };
     UNICODE_STRING uSymboliclinkName = { 0x00 };
     DEVICE_OBJECT* pDeviceObject = { 0x00 };
     WCHAR lpDeviceName[decltype(EncryptedDeviceAntiyCheatString)::Length];
     WCHAR lpSymboliclinkName[decltype(EncryptedDosDevicesAntiyCheatString)::Length];
     HANDLE hThread = NULL;

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
             AkrOsPrint("Create Device Object Fail:%d!\n", ntStatus);
             break;
         }

         DecryptString(EncryptedDosDevicesAntiyCheatString, lpSymboliclinkName);
         RtlInitUnicodeString(&uSymboliclinkName, lpSymboliclinkName);
         ntStatus = IoCreateSymbolicLink(&uSymboliclinkName, &uDeviceName);

         RtlSecureZeroMemory(lpDeviceName, decltype(EncryptedDeviceAntiyCheatString)::Length);
         RtlSecureZeroMemory(lpSymboliclinkName, decltype(EncryptedDosDevicesAntiyCheatString)::Length);

         if (!NT_SUCCESS(ntStatus))
         {
             AkrOsPrint("Create SymbolicLink Fail:%d!\n", ntStatus);
             break;
         }

         for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
         {
             pDrvObject->MajorFunction[i] = DispatchCommon;
         }

         pDrvObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
         pDrvObject->DriverUnload = DriverUnload;

         InitializeListHead(&g_Global_Data.m_WhiteListHeader);
         ExInitializeResourceLite (&g_Global_Data.m_WhiteListLock);

         InitializeListHead(&g_Global_Data.m_BlackListHeader);
         ExInitializeResourceLite(&g_Global_Data.m_BlackListLock);

         InitializeListHead(&g_Global_Data.m_ProtectProcessListHeader);
         ExInitializeResourceLite (&g_Global_Data.m_ProtectProcessListLock);

         //init System Data...
         RtlZeroMemory(&g_System_Dynamic_Data, sizeof(SYSTEM_DYNAMIC_DATA));
         InitDynamicData(&g_System_Dynamic_Data);

         //setup Whitelist...
         LockList(&g_Global_Data.m_WhiteListLock);
         UpdateWhiteList(&g_Global_Data.m_WhiteListHeader);
         LookupList(&g_Global_Data.m_WhiteListHeader);
         UnlockList(&g_Global_Data.m_WhiteListLock);

         //setup BlackList
         LockList(&g_Global_Data.m_BlackListLock);
         UpdateBlackList(&g_Global_Data.m_BlackListHeader);
         LookupList(&g_Global_Data.m_BlackListHeader);
         UnlockList(&g_Global_Data.m_BlackListLock);

         //setup Protect Process
         LockList(&g_Global_Data.m_ProtectProcessListLock);
         UpdateProtectProcessList(&g_Global_Data.m_ProtectProcessListHeader);
         LookupList(&g_Global_Data.m_ProtectProcessListHeader);
         UnlockList(&g_Global_Data.m_ProtectProcessListLock);

         g_Global_Data.m_DriverObject = pDrvObject;
         g_Global_Data.m_isUnloaded = FALSE;

         KeInitializeEvent(&g_Global_Data.m_WaitUnloadEvent, SynchronizationEvent, FALSE);
         KeInitializeEvent(&g_Global_Data.m_WaitProcessEvent, SynchronizationEvent, FALSE);
         KeInitializeEvent(&g_Global_Data.m_ProtectProcessOverEvent, SynchronizationEvent, FALSE);
         ntStatus = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), NULL, AntiCheatWork, NULL);
         if (!NT_SUCCESS(ntStatus))
         {
             AkrOsPrint("Create System Thread Fail:0x%x!\n", ntStatus);
             break;
         }

         ZwClose(hThread);
     } while (FALSE);

     if (NT_SUCCESS(ntStatus))
     {
         AkrOsPrint("Anti-Cheat Driver Start Success!\n");
     }
     else
     {
         if (pDeviceObject)
         {
             AkrOsPrint("Anti-Cheat Driver Start Fail!\n");
             g_Global_Data.m_isUnloaded = TRUE;
             DriverUnload(pDrvObject);
         }
     }
     return ntStatus;
 }

 NTSTATUS InitDynamicData(_Out_ PSYSTEM_DYNAMIC_DATA pData)
 {
     NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
     OSVERSIONINFOEXW VersionInfo = { sizeof(OSVERSIONINFOEXW) };
     ULONG ShortVersion = 0;

     do 
     {
         ntStatus = RtlGetVersion((PRTL_OSVERSIONINFOW)&VersionInfo);
         if (!NT_SUCCESS(ntStatus))
         {
             break;
         }

         ShortVersion = (VersionInfo.dwMajorVersion << 8) | (VersionInfo.dwMinorVersion << 4) | (VersionInfo.wServicePackMajor);
         
         pData->Version = (_WinVer)ShortVersion;

         if (ShortVersion < WINVER_7)
         {
             ntStatus = STATUS_NOT_SUPPORTED;
             break;
         }

         switch (ShortVersion)
         {
             case WINVER_7:
             case WINVER_7_SP1:
             {
                 pData->EProcessFlagsOffset = 0x440;
             }
             break;
             case WINVER_81:
             {
                 pData->EProcessFlagsOffset = 0x2fc;
             }
             break;
             case WINVER_10:
             {
                 if (VersionInfo.dwBuildNumber == 16299 ||
                     VersionInfo.dwBuildNumber == 17134 || 
                     VersionInfo.dwBuildNumber == 17763)
                 {
                     pData->EProcessFlagsOffset = 0x304;
                 }
                 else if (VersionInfo.dwBuildNumber >= 18362)
                 {
                     pData->EProcessFlagsOffset = 0x30c;
                 }
             }
             break;
         }


     } while (FALSE);
     

     return ntStatus;
 }

#endif

#ifdef __cplusplus
}
#endif