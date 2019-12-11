#include "Anti-CheatBase.h"
#include "zwapi.h"

BOOLEAN SafeExchangeFunc(PVOID pImageThunkFunc, ULONG_PTR pFakeFunction)
{
    BOOLEAN bRet = FALSE;
    PVOID pImageThunkFuncEntry = NULL;
    PMDL pImageThunkFuncEntry_Mdl = NULL;
    ULONG_PTR pNewImageThunkFuncAddr = NULL;

    if (!pImageThunkFunc || !pFakeFunction)
        return bRet;

    pImageThunkFuncEntry = pImageThunkFunc;
    pImageThunkFuncEntry_Mdl = IoAllocateMdl(pImageThunkFuncEntry, sizeof(ULONG_PTR), FALSE, FALSE, NULL);

    if (!pImageThunkFuncEntry_Mdl)
        return bRet;

    __try
    {
        MmProbeAndLockPages(pImageThunkFuncEntry_Mdl, KernelMode, (LOCK_OPERATION)(IoReadAccess | IoModifyAccess || IoWriteAccess));
        if (pImageThunkFuncEntry_Mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL))
            pNewImageThunkFuncAddr = (ULONG_PTR)pImageThunkFuncEntry_Mdl->MappedSystemVa;
        else
        {
            pNewImageThunkFuncAddr = (ULONG_PTR)MmMapLockedPagesSpecifyCache(pImageThunkFuncEntry_Mdl, KernelMode, MmCached, NULL, NULL, NormalPagePriority);
            if (MmIsAddressValid((PVOID)pNewImageThunkFuncAddr))
            {
                InterlockedExchange((LONG*)pNewImageThunkFuncAddr, pFakeFunction);
                bRet = TRUE;
            }
        }
    }
    __finally
    {
        if (pImageThunkFuncEntry_Mdl)
            IoFreeMdl(pImageThunkFuncEntry_Mdl);
    }

    return bRet;
    
}

BOOLEAN 
IATHook(
    PVOID ModuleBase, 
    UCHAR* pModuleName, 
    UCHAR* pImportName, 
    PVOID pFakeFunctionAddress, 
    ULONG_PTR *pOriginalFunctionAddress
)
{
    IMAGE_IMPORT_DESCRIPTOR* pImportDir = nullptr;
    ULONG dwImportSize = 0;
    BOOLEAN bResult = FALSE;
    ULONG dwRvaNameOffset = 0;
    UCHAR* scDllName = nullptr;
    ULONG* pFirstThunk = nullptr;
    ULONG* pOriginalFirstThunk = nullptr;
    ULONG i = 0;
    IMAGE_IMPORT_BY_NAME* pImportByName = nullptr;

    if (!ModuleBase || !pModuleName || !pImportName || !pFakeFunctionAddress || !pOriginalFunctionAddress)
        return bResult;

    __try
    {
        pImportDir = (IMAGE_IMPORT_DESCRIPTOR *)RtlImageDirectoryEntryToData(ModuleBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &dwImportSize);
        
        //if have dll name
        while (pImportDir && pImportDir->Name)
        {
            dwRvaNameOffset = pImportDir->Name;

            scDllName = (PUCHAR)((UCHAR *)ModuleBase + dwRvaNameOffset);

            //find Module...
            if (scDllName && _stricmp((const char *)pModuleName, (const char *)scDllName) == 0)
            {
                pFirstThunk = (ULONG*)((UCHAR*)ModuleBase + pImportDir->FirstThunk);
                pOriginalFirstThunk = (ULONG*)((UCHAR*)ModuleBase + pImportDir->OriginalFirstThunk);

                for (i = 0; pFirstThunk[i]; ++i)
                {
                    pImportByName = (IMAGE_IMPORT_BY_NAME *)(pOriginalFirstThunk[i]);
                    if (pImportByName < (IMAGE_IMPORT_BY_NAME*)ModuleBase)
                        pImportByName = (IMAGE_IMPORT_BY_NAME *)((UCHAR*)ModuleBase + (UINT_PTR)pImportByName);

                    KdPrint(("%s\n", (PUCHAR)&pImportByName->Name[0]));
                    if (pImportByName)
                    {
                        if (strncmp((const char*)&pImportByName->Name[0], (const char*)pImportName, strlen((const char*)pImportName)) == 0)
                        {
                            KdPrint(("Find IAT Entry:0x%x,IAT Address is 0x%x,ImportName is %s,HookFunctionName is %s!\n", (ULONG_PTR)ModuleBase + pImportDir->FirstThunk + i * 4, pFirstThunk[i], (UCHAR*)&pImportByName->Name[0], pImportName));

                            *pOriginalFunctionAddress = pFirstThunk[i];
                            SafeExchangeFunc(&pFirstThunk[i], (ULONG_PTR)pFakeFunctionAddress);

                        }
                        
                    }
                }
            }

            pImportDir++;
        }
    }
    __finally
    {

    }

}

BOOLEAN 
Hook_KeUserModuleCallback(
    _In_ PVOID pFakeFunctionAddress, 
    _Out_ ULONG_PTR* pOriginalFunctionAddress
)
{
    BOOLEAN bRet = FALSE;
    ULONG_PTR ModuleBase = NULL;

    if (!pFakeFunctionAddress || !pOriginalFunctionAddress)
        return bRet;

    ModuleBase = KrnlGetModuleBase((UCHAR *)"win32kfull.sys");
    if (!ModuleBase)
        return bRet;

    bRet = IATHook((PVOID)ModuleBase, (UCHAR*)"ntoskrnl.exe", (UCHAR*)"KeUserModeCallback", pFakeFunctionAddress, pOriginalFunctionAddress); 


    return bRet;
}

