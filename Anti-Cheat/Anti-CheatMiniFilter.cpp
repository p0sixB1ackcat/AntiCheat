#include "Anti-CheatMiniFilter.h"
#include "Anti-CheatCallback.h"
#include <dontuse.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

extern GLOBAL_DATA g_Global_Data;

ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))



//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, InitMiniFilter)
#pragma alloc_text(PAGE, UnloadMiniFilter)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      AnticheatFltAcquireSectionSyncPreRoutine,
      AntiCheatFltAcquireSectionSyncPostRoutine },

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    (PFLT_FILTER_UNLOAD_CALLBACK)UnloadMiniFilter,

    NULL,                    //  InstanceSetup
    NULL,            //  InstanceQueryTeardown
    NULL,            //  InstanceTeardownStart
    NULL,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};


NTSTATUS
InitMiniFilter (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntiCheat!DriverEntry: Entered\n") );

    //  Register with FltMgr to tell it our callback routines
    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                (PFLT_FILTER *)&g_Global_Data.m_MFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        status = FltStartFiltering( (PFLT_FILTER)g_Global_Data.m_MFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter((PFLT_FILTER)g_Global_Data.m_MFilterHandle);
        }
    }

    return status;
}

NTSTATUS
UnloadMiniFilter (
    _In_ ULONG Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntiCheat!AntiCheatUnload: Entered\n") );

    if((PFLT_FILTER)g_Global_Data.m_MFilterHandle)
        FltUnregisterFilter((PFLT_FILTER)g_Global_Data.m_MFilterHandle);

    return STATUS_SUCCESS;
}



