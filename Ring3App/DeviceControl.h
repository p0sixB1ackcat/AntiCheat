#pragma once

#define DEVICE_NAMe

//Control Code
#define BASE_CODE 0x8000
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#define ACCTL_CODE(i) CTL_CODE(0x00000022, BASE_CODE + i, 0, FILE_ALL_ACCESS)
#define ACCTL_CODE_CONFIG ACCTL_CODE(1)
#define ACCTL_CODE_SET_WHITE_LIST ACCTL_CODE(2)

BOOL InstallMiniFilter(void);

BOOL UnInstallMiniFilter(void);

BOOL StartFilter(void);

BOOL StopFilter(void);

int SendDeviceIoControl(int CtrlCode, void* pbBuffer, int cbBuffer);