#include "Anti-CheatBase.h"
#include "strings.h"

BOOLEAN MatchBlackWhitelistByProcessName(_In_ UNICODE_STRING* ProcessName,LIST_ENTRY *pWhiteList)
{
    BOOLEAN bResult = FALSE;
    ANTI_CHEAT_BLACK_WHITE_DATA* pWhiteData = NULL;
    LIST_ENTRY* pEntry = NULL;
    UNICODE_STRING uCompProcessName = { 0x00 };

    if (!ProcessName || !pWhiteList)
        return bResult;

    if (IsListEmpty(pWhiteList))
        return TRUE;

    pEntry = pWhiteList->Flink;
    while (pEntry != pWhiteList)
    {
        pWhiteData = (ANTI_CHEAT_BLACK_WHITE_DATA *)CONTAINING_RECORD(pEntry, ANTI_CHEAT_BLACK_WHITE_DATA, m_Entry);
        if (pWhiteData)
        {
            RtlInitUnicodeString(&uCompProcessName, pWhiteData->m_ProcessName);
            if (RtlCompareUnicodeString(ProcessName, &uCompProcessName, TRUE) == 0)
            {
                return TRUE;
            }
        }
        pEntry = pEntry->Flink;
    }

    return bResult;
}

BOOLEAN KrnlIsProtectName(UNICODE_STRING* puName, LIST_ENTRY* pListHeader)
{
    BOOLEAN bRet = FALSE;
    LIST_ENTRY* pEntry = NULL;
    ANTI_CHEAT_PROTECT_PROCESS_DATA* pData = NULL;
    UNICODE_STRING uCompNameStr = { 0x00 };

    if (!puName || !pListHeader)
        return bRet;
    if (IsListEmpty(pListHeader))
        return bRet;

    pEntry = pListHeader->Flink;
    while (pEntry != pListHeader)
    {
        pData = (ANTI_CHEAT_PROTECT_PROCESS_DATA*)CONTAINING_RECORD(pEntry, ANTI_CHEAT_PROTECT_PROCESS_DATA, m_Entry);
        if (pData)
        {
            RtlInitUnicodeString(&uCompNameStr, pData->m_Name);
            if (RtlCompareUnicodeString(&uCompNameStr, puName, FALSE) == 0)
            {
                bRet = TRUE;
                break;
            }
        }
        pEntry = pEntry->Flink;
    }
    return bRet;
}

NTSTATUS UpdateWhiteList(_Inout_ LIST_ENTRY* pWhiteListHeader)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    LIST_ENTRY* pEntry = NULL;
    LIST_ENTRY* pRemoveEntry = NULL;
    ANTI_CHEAT_BLACK_WHITE_DATA* pWhiteData = NULL;
    ULONG i;
    WCHAR swDecryptedAkrosExeString[decltype(EncryptedakrosExeString)::Length] = { 0x00 };
    WCHAR swDecryptedAkrosLauncherExeString[decltype(EncryptedakroslauncherExeString)::Length] = { 0x00 };
    WCHAR swDecryptedCsrssExeString[decltype(EncryptedcsrssExeString)::Length] = { 0x00 };

    DecryptString(EncryptedakrosExeString, swDecryptedAkrosExeString);
    DecryptString(EncryptedakroslauncherExeString, swDecryptedAkrosLauncherExeString);
    DecryptString(EncryptedcsrssExeString, swDecryptedCsrssExeString);
    

    WCHAR* pWhiteListBuffer[] = {swDecryptedAkrosExeString, swDecryptedAkrosLauncherExeString,  swDecryptedCsrssExeString ,0x00};

    do
    {
        pEntry = pWhiteListHeader->Flink;
        while (pEntry != pWhiteListHeader)
        {
            pRemoveEntry = pEntry;
            pWhiteData = CONTAINING_RECORD(pEntry, ANTI_CHEAT_BLACK_WHITE_DATA, m_Entry);
            pEntry = pEntry->Flink;
            if (pWhiteData)
            {
                RemoveEntryList(pRemoveEntry);
                ExFreePoolWithTag(pWhiteData, 0);
            }
        }

        for (i = 0; pWhiteListBuffer[i] != 0x00; ++i)
        { 
            pWhiteData = (PANTI_CHEAT_BLACK_WHITE_DATA)ExAllocatePoolWithTag(PagedPool, sizeof(ANTI_CHEAT_BLACK_WHITE_DATA), 'tlhW');
            if (pWhiteData)
            {
                RtlZeroMemory(pWhiteData, sizeof(ANTI_CHEAT_BLACK_WHITE_DATA));
                RtlCopyMemory(pWhiteData->m_ProcessName, pWhiteListBuffer[i],wcslen(pWhiteListBuffer[i]) * sizeof(WCHAR));
                InsertTailList(pWhiteListHeader, &pWhiteData->m_Entry);
            }
        }
    } while (FALSE);

    RtlSecureZeroMemory(swDecryptedAkrosExeString, decltype(EncryptedakrosExeString)::Length);
    RtlSecureZeroMemory(swDecryptedAkrosLauncherExeString, decltype(EncryptedakroslauncherExeString)::Length);
    RtlSecureZeroMemory(swDecryptedCsrssExeString, decltype(EncryptedcsrssExeString)::Length);

    return Status;
}

NTSTATUS UpdateBlackList(_Inout_ LIST_ENTRY *pBlackListHeader)
{
    LIST_ENTRY* pEntry = NULL;
    LIST_ENTRY* pRemEntry = NULL;
    WCHAR swDecryptBlackBone[decltype(EncryptedBlackBoneDrv10SysString)::Length] = { 0x00 };
    WCHAR swDecryptx64Dbg[decltype(Encryptedx64dbgExeString)::Length] = { 0x00 };
    ULONG i = 0;

    DecryptString(EncryptedBlackBoneDrv10SysString, swDecryptBlackBone);
    DecryptString(Encryptedx64dbgExeString, swDecryptx64Dbg);
    
    WCHAR* pBlackList[] = { swDecryptBlackBone,swDecryptx64Dbg ,0x00 };

    if (!pBlackListHeader)
        return STATUS_INVALID_PARAMETER;

    pEntry = pBlackListHeader->Flink;
    while (pEntry != pBlackListHeader)
    {
        ANTI_CHEAT_BLACK_WHITE_DATA* pOldData = (ANTI_CHEAT_BLACK_WHITE_DATA *)CONTAINING_RECORD(pEntry, ANTI_CHEAT_BLACK_WHITE_DATA, m_Entry);
        pRemEntry = pEntry;
        pEntry = pEntry->Flink;
        if (pOldData)
        {
            RemoveEntryList(pRemEntry);
            ExFreePoolWithTag(pOldData, 0);
            pOldData = NULL;
        }
    }
    
    for (i = 0; pBlackList[i] != 0x00; ++i)
    {
        ANTI_CHEAT_BLACK_WHITE_DATA* pData = (ANTI_CHEAT_BLACK_WHITE_DATA *)ExAllocatePoolWithTag(PagedPool, sizeof(ANTI_CHEAT_BLACK_WHITE_DATA), '0klB');
        if (!pData)
            continue;
        RtlZeroMemory(pData, sizeof(ANTI_CHEAT_BLACK_WHITE_DATA));
        RtlCopyMemory(pData->m_ProcessName, pBlackList[i], wcslen(pBlackList[i]) * sizeof(WCHAR));
        InsertTailList(pBlackListHeader, &pData->m_Entry);
    }

    RtlSecureZeroMemory(swDecryptBlackBone, decltype(EncryptedBlackBoneDrv10SysString)::Length);
    RtlSecureZeroMemory(swDecryptx64Dbg, decltype(Encryptedx64dbgExeString)::Length);
    return STATUS_SUCCESS;
}

VOID KrnlRemoveProtectProcessList(LIST_ENTRY* pListHeader)
{
    LIST_ENTRY* pEntry = NULL;
    LIST_ENTRY* pRemoveEntry = NULL;
    ANTI_CHEAT_PROTECT_PROCESS_DATA* pData = NULL;

    if (!pListHeader)
        return;
    pEntry = pListHeader->Flink;

    while (pEntry != pListHeader)
    {
        pRemoveEntry = pEntry;
        pData = (ANTI_CHEAT_PROTECT_PROCESS_DATA*)CONTAINING_RECORD(pEntry, ANTI_CHEAT_PROTECT_PROCESS_DATA, m_Entry);
        pEntry = pEntry->Flink;
        if (pData)
        {
            RemoveEntryList(pRemoveEntry);
            ExFreePool(pData);
        }
    }
}

NTSTATUS UpdateProtectProcessList(LIST_ENTRY* pListHeader)
{
    LIST_ENTRY* pEntry = NULL;
    ANTI_CHEAT_PROTECT_PROCESS_DATA* pData = NULL;
    WCHAR* ProtectNames[] = {L"csgo.exe", L"notepad.exwe", NULL};
    ULONG i = 0;

    if (!pListHeader)
        return STATUS_INVALID_PARAMETER;

    KrnlRemoveProtectProcessList(pListHeader);
    while (ProtectNames[i] != NULL)
    {
        pData = (ANTI_CHEAT_PROTECT_PROCESS_DATA*)ExAllocatePoolWithTag(PagedPool, sizeof(ANTI_CHEAT_PROTECT_PROCESS_DATA), 'torP');
        if (pData)
        {
            RtlZeroMemory(pData, sizeof(ANTI_CHEAT_PROTECT_PROCESS_DATA));
            RtlCopyMemory(pData->m_Name, ProtectNames[i], wcslen(ProtectNames[i]) * sizeof(WCHAR));
            InsertTailList(pListHeader, &pData->m_Entry);
        }
        ++i;
    }
    return STATUS_SUCCESS;
}

VOID KrnlRemoveBlackWhiteList(LIST_ENTRY* pBlackWhiteListHeader)
{
    LIST_ENTRY* pEntry = NULL;
    LIST_ENTRY* pRemEntry = NULL;
    ANTI_CHEAT_BLACK_WHITE_DATA* pBlackWhiteListData = NULL;

    pEntry = pBlackWhiteListHeader->Flink;
    while (pEntry != pBlackWhiteListHeader)
    {
        pBlackWhiteListData = (ANTI_CHEAT_BLACK_WHITE_DATA*)CONTAINING_RECORD(pEntry, ANTI_CHEAT_BLACK_WHITE_DATA, m_Entry);

        pRemEntry = pEntry;
        pEntry = pEntry->Flink;
        if (!pBlackWhiteListData)
            continue;

        RemoveEntryList(pRemEntry);
        ExFreePoolWithTag(pBlackWhiteListData, 0);
    }
}