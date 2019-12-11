#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntstrsafe.h>
#include <fltKernel.h>
#include "Native/NativeStructs.h"

#define MAX_PATH 260
//Control Code
#define BASE_CODE 0x8000

#define ACCTL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, BASE_CODE + i, METHOD_BUFFERED, FILE_ALL_ACCESS)

#define ACCTL_CODE_CONFIG                   ACCTL_CODE(1)
#define ACCTL_CODE_START_HOOK               ACCTL_CODE(2)

typedef struct _ANTI_CHEAT_BLACK_WHITE_DATA
{
    ULONG m_ProcessId;
    LIST_ENTRY m_Entry;
    WCHAR m_ProcessName[MAX_PATH];
}ANTI_CHEAT_BLACK_WHITE_DATA, * PANTI_CHEAT_BLACK_WHITE_DATA;

typedef struct _ANTI_CHEAT_PROTECT_PROCESS_DATA
{
    LIST_ENTRY m_Entry;
    WCHAR m_Name[MAX_PATH];

}ANTI_CHEAT_PROTECT_PROCESS_DATA, *PANTI_CHEAT_PROTECT_PROCESS_DATA;

typedef struct _OBCALLBACK_BODY
{
    LIST_ENTRY ListEntry;
    ULONG ulOperations;
    ULONG ulKnow;
    PVOID pCallbackNode;
    PVOID pObjectType;
    PVOID pPreCallbackRoutine;
    PVOID pPostCallbackRoutine;
    ULONG ulRefCount;
}OBCALLBACK_BODY,*POBCALLBACK_BODY;

typedef struct _OBCALLBACK_NODE
{
    USHORT usVersion;
    USHORT usCallbackBodyCount;
    PVOID pContext;
    ULONG ulUnknow;
    WCHAR* wcsAltitude;
    OBCALLBACK_BODY CallbackBodies[1];

}OBCALLBACK_NODE,*POBCALLBACK_NODE;

typedef struct _OBJECT_TYPE_INITIALIZER
{
    USHORT Length;
    UCHAR ObjectTypeFlags;
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG RetainAccess;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    PVOID OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    PVOID ParseProcedure;
    PVOID ParseProcedureEx;
    PVOID SecurityProcedure;
    PVOID QueryNameProcedure;
    PVOID OkayToCloseProcedure;
    ULONG WaitObjectFlagMask;
    USHORT WaitObjectFlagOffset;
    USHORT WaitObjectPointerOffset;
}OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE
{
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    ULONG_PTR DefaultObject;
    UCHAR Index;
    UCHAR PADDING0[0x03];
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    UCHAR PADDING1[0x04];
    OBJECT_TYPE_INITIALIZER TypeInfo;
    _EX_PUSH_LOCK TypeLock;
    ULONG Key;
    UCHAR PADDING2[0x04];
    LIST_ENTRY* CallbackList;
}OBJECT_TYPE,*POBJECT_TYPE;

typedef struct _EX_CALLBACK_ROUTINE_BLOCK
{
    EX_RUNDOWN_REF RunDownProtect;
    PEX_CALLBACK_FUNCTION Function;
    PVOID Context;
}EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;

//Data structures used by global scope£¬Can add
typedef struct _GLOBAL_DATA
{
    OBCALLBACK_NODE *m_ObRegistrationHandle;
    PVOID m_MFilterHandle;
    PDRIVER_OBJECT m_DriverObject;
    ERESOURCE m_WhiteListLock;
    LIST_ENTRY m_WhiteListHeader;
    ERESOURCE m_BlackListLock;
    LIST_ENTRY m_BlackListHeader;
    ERESOURCE m_ProtectProcessListLock;
    LIST_ENTRY m_ProtectProcessListHeader;
    BOOLEAN m_isUnloaded;
    KEVENT m_WaitEvent;
}GLOBAL_DATA, * PGLOBAL_DATA;

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
KrnlGetImageNameByPathW(
    _In_ WCHAR* pQueryString,
    _Out_ WCHAR** pImageName,
    _Out_ ULONG_PTR* pLen
);

NTSTATUS
KrnlGetImageNameByPathA(
    _In_ PUCHAR pQueryString,
    _Out_ PUCHAR* pImageName,
    _Out_ ULONG_PTR* pLen
);

NTSTATUS 
KrnlGetProcessName(
    _In_ PEPROCESS Eprocess, 
    _Out_ UNICODE_STRING* ProcessName
);

ULONG_PTR
KrnlGetModuleBase(
    UCHAR* pModuleName
);

BOOLEAN 
MatchBlackWhitelistByProcessName(
    _In_ UNICODE_STRING* ProcessName, 
    _In_ LIST_ENTRY* pWhiteList
);

BOOLEAN
KrnlIsProtectName(
    UNICODE_STRING* puName,
    LIST_ENTRY* pListHeader
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

NTSTATUS 
UpdateProtectProcessList(
    LIST_ENTRY* pListHeader
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

VOID
KrnlProtectSelf(
    VOID
);

VOID
KrnlRemoveBlackWhiteList(
    LIST_ENTRY* pBlackWhiteListHeader
);

VOID
KrnlRemoveProtectProcessList(
    LIST_ENTRY* pListHeader
);

NTSTATUS
KrnlGetPspLoadImageNotifyRoutine(
    _Out_ PULONG_PTR pOutAddress
);

BOOLEAN
Hook_KeUserModuleCallback(
    _In_ PVOID pFakeFunctionAddress,
    _Out_ ULONG_PTR* pOriginalFunctionAddress
);
