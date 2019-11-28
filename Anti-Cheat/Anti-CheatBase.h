#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntstrsafe.h>
#include <fltKernel.h>

#define MAX_PATH 260
//Control Code
#define BASE_CODE 0x8000

#define ACCTL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, BASE_CODE + i, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define ACCTL_CODE_CONFIG ACCTL_CODE(1)

//Data structures used by global scope£¬Can add
typedef struct _GLOBAL_DATA
{
    PVOID m_ObRegistrationHandle;
    PVOID m_MFilterHandle;
    PDRIVER_OBJECT m_DriverObject;
    ERESOURCE m_WhiteListLock;
    LIST_ENTRY m_WhiteListHeader;
    ERESOURCE m_BlackListLock;
    LIST_ENTRY m_BlackListHeader;
}GLOBAL_DATA, * PGLOBAL_DATA;

typedef struct _ANTI_CHEAT_BLACK_WHITE_DATA
{
    ULONG m_ProcessId;
    LIST_ENTRY m_Entry;
    WCHAR m_ProcessName[MAX_PATH];
}ANTI_CHEAT_BLACK_WHITE_DATA,*PANTI_CHEAT_BLACK_WHITE_DATA;

EXTERN_C 
VOID 
DriverUnload(
    PDRIVER_OBJECT pDrvObject
);

NTSTATUS
KrnlGetImageNameByPath(
    _In_ UNICODE_STRING* pQueryString,
    _Out_ WCHAR** pImageName,
    _Out_ ULONG_PTR* pLen
);

NTSTATUS 
KrnlGetProcessName(
    _In_ PEPROCESS Eprocess, 
    _Out_ UNICODE_STRING* ProcessName
);

BOOLEAN 
MatchBlackWhitelistByProcessName(
    _In_ UNICODE_STRING* ProcessName, 
    _In_ LIST_ENTRY* pWhiteList
);

NTSTATUS
UpdateWhiteList(
    _Inout_ LIST_ENTRY* pWhiteListHeader
);

void 
LookupList(
    LIST_ENTRY* pListHeader
);

NTSTATUS 
UpdateBlackList(
    _Inout_ LIST_ENTRY* pBlackListHeader
);

void 
LockList(
    ERESOURCE* pLock
);

void 
UnlockList(
    ERESOURCE* pLock
);

BOOLEAN 
KrnlCheckPE(
    VOID* ImageBase,
    SIZE_T ImageSize
);

NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT SIZE_T* NumberOfBytesToProtect,
    IN ULONG NewAccessProtection,
    OUT PULONG OldAccessProtection
);
