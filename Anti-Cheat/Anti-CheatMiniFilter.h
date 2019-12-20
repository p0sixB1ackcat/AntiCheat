#pragma once
#include "Anti-CheatBase.h"

EXTERN_C  
NTSTATUS
InitMiniFilter(
    _In_ PDRIVER_OBJECT DriverObject
);

EXTERN_C
NTSTATUS
UnloadMiniFilter(
    _In_ ULONG Flags
);