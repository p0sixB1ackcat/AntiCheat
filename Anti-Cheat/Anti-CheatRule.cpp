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

NTSTATUS UpdateWhiteList(_Inout_ LIST_ENTRY* pWhiteListHeader)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    LIST_ENTRY* pEntry = NULL;
    LIST_ENTRY* pRemoveEntry = NULL;
    ANTI_CHEAT_BLACK_WHITE_DATA* pWhiteData = NULL;
    WCHAR swDecryptSystemExeString[decltype(EncryptedSystemExeString)::Length] = { 0x00 };
    WCHAR swDecryptLsassExeString[decltype(EncryptedLsassString)::Length] = { 0x00 };
    WCHAR swDecryptCsrssExeString[decltype(EncryptedcsrssExeString)::Length] = { 0x00 };
    WCHAR swDecryptExplorerString[decltype(EncryptedexplorerExeString)::Length] = { 0x00 };
    WCHAR swDecryptSvchostExeString[decltype(EncryptedsvchostExeString)::Length] = { 0x00 };
    ULONG i;

    DecryptString(EncryptedSystemExeString, swDecryptSystemExeString);
    DecryptString(EncryptedLsassString, swDecryptLsassExeString);
    DecryptString(EncryptedcsrssExeString, swDecryptCsrssExeString);
    DecryptString(EncryptedexplorerExeString, swDecryptExplorerString);
    DecryptString(EncryptedsvchostExeString, swDecryptSvchostExeString);

    WCHAR* pWhiteListBuffer[] = { swDecryptSystemExeString, swDecryptLsassExeString, swDecryptCsrssExeString, swDecryptExplorerString, swDecryptSvchostExeString ,0x00};

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

    RtlSecureZeroMemory(swDecryptSystemExeString, decltype(EncryptedSystemExeString)::Length);
    RtlSecureZeroMemory(swDecryptCsrssExeString, decltype(EncryptedcsrssExeString)::Length);
    RtlSecureZeroMemory(swDecryptLsassExeString, decltype(EncryptedLsassString)::Length);
    RtlSecureZeroMemory(swDecryptSvchostExeString, decltype(EncryptedsvchostExeString)::Length);
    RtlSecureZeroMemory(swDecryptExplorerString, decltype(EncryptedexplorerExeString)::Length);

    return Status;
}

NTSTATUS UpdateBlackList(_Inout_ LIST_ENTRY *pBlackListHeader)
{
    LIST_ENTRY* pEntry = NULL;
    LIST_ENTRY* pRemEntry = NULL;
    WCHAR swDecryptBlackBone[decltype(EncryptedBlackBoneDrv10SysString)::Length] = { 0x00 };
    WCHAR swDecryptExtremeInjectorV3[decltype(EncryptedExtremeInjectorv3ExeString)::Length] = { 0x00 };
    ULONG i = 0;

    DecryptString(EncryptedBlackBoneDrv10SysString, swDecryptBlackBone);
    DecryptString(EncryptedExtremeInjectorv3ExeString, swDecryptExtremeInjectorV3);

    WCHAR* pBlackList[] = { swDecryptBlackBone, swDecryptExtremeInjectorV3, 0x00 };

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
    return STATUS_SUCCESS;
}