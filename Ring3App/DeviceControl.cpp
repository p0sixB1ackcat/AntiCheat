#include "pch.h"
#include <winsvc.h>

#define FEPortName L"\\Anti-Cheat"
#define DRIVER_NAME L"Anti-Cheat"
#define DRIVER_PATH L".\\Anti-Cheat.sys"
#define DRIVER_ALTITUDE L"370020"

HANDLE OpenDevice()
{
    HANDLE hDevice = CreateFileW(L"\\\\.\\Anti-Cheat", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0x80, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
        return NULL;
    return hDevice;
}

BOOL InstallMiniFilter(void)
{
    //SCM管理器句柄
    SC_HANDLE hServicesMgr = NULL;
    //NT驱动程序的句柄
    SC_HANDLE hNt = NULL;
    TCHAR DriverFullPathNameBuffer[MAX_PATH] = { 0x00 };
    TCHAR FormatStr[MAX_PATH];
    TCHAR* RegPath = L"SYSTEM\\CurrentControlSet\\Services\\";
    HKEY hKey = 0;
    DWORD dwData = 0;

    hServicesMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (!hServicesMgr)
    {
        CloseServiceHandle(hServicesMgr);
        return FALSE;
    }

    ExpandEnvironmentStrings(L"%systemroot%", DriverFullPathNameBuffer, sizeof(DriverFullPathNameBuffer));
    wcsncat(DriverFullPathNameBuffer, L"\\", 1);
    wcsncat(DriverFullPathNameBuffer, DRIVER_NAME, wcslen(DRIVER_NAME));
    wcsncat(DriverFullPathNameBuffer, L".sys", wcslen(L".sys"));

    //GetFullPathName(pSysPath, MAX_PATH, DriverFullPathNameBuffer, NULL);

    hNt = CreateService(hServicesMgr
        , DRIVER_NAME
        , DRIVER_NAME
        , SERVICE_ALL_ACCESS
        , SERVICE_FILE_SYSTEM_DRIVER
        , SERVICE_DEMAND_START
        , SERVICE_ERROR_IGNORE
        , DriverFullPathNameBuffer
        , L"FSFilter Activity Monitor"
        , NULL
        , L"FltMgr"
        , NULL
        , NULL);

    if (!hNt)
    {
        ULONG error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS || error == 0x00000431)
        {
            CloseServiceHandle(hServicesMgr);
            CloseServiceHandle(hNt);
            return TRUE;
        }
        else
        {
            CloseServiceHandle(hServicesMgr);
            CloseServiceHandle(hNt);
            return FALSE;
        }
    }

    CloseServiceHandle(hServicesMgr);
    CloseServiceHandle(hNt);

    wcsncpy_s(FormatStr, RegPath, wcslen(RegPath));
    wcsncat_s(FormatStr, DRIVER_NAME, sizeof(DRIVER_NAME));
    wcsncat_s(FormatStr, L"\\Instances", wcslen(L"\\Instances"));

    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE
        , FormatStr
        , 0
        , L""
        , REG_OPTION_NON_VOLATILE
        , KEY_ALL_ACCESS
        , NULL
        , &hKey
        , &dwData) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    wcsncpy_s(FormatStr, DRIVER_NAME, wcslen(DRIVER_NAME));
    wcsncat_s(FormatStr, L" Instance", wcslen(L" Instance"));
    if (RegSetValueEx(hKey
        , L"DefaultInstance"
        , 0
        , REG_SZ
        , (const BYTE*)FormatStr
        , wcslen(FormatStr) * sizeof(WCHAR)) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    RegFlushKey(hKey);
    RegCloseKey(hKey);

    //SYSTEM_LOCAL_MACHINE\CurrentControlSet\Services\DriverName\Instances\DriverName Instance
    wcsncpy_s(FormatStr, RegPath, wcslen(RegPath));
    wcsncat_s(FormatStr, DRIVER_NAME, wcslen(DRIVER_NAME));
    wcsncat_s(FormatStr, L"\\Instances\\", wcslen(L"\\Instances\\"));
    wcsncat_s(FormatStr, DRIVER_NAME, wcslen(DRIVER_NAME));
    wcsncat_s(FormatStr, L" Instance", wcslen(L" Instance"));

    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE
        , FormatStr
        , 0
        , L""
        , REG_OPTION_NON_VOLATILE
        , KEY_ALL_ACCESS
        , NULL
        , &hKey
        , &dwData) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    wcsncpy_s(FormatStr, DRIVER_ALTITUDE, wcslen(DRIVER_ALTITUDE));
    if (RegSetValueEx(hKey
        , L"Altitude"
        , 0
        , REG_SZ
        , (const BYTE*)FormatStr
        , (DWORD)(wcslen(FormatStr) * sizeof(WCHAR))) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    dwData = 0;
    if (RegSetValueEx(hKey
        , L"Flags"
        , 0
        , REG_DWORD
        , (const BYTE*)&dwData
        , sizeof(DWORD)) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    RegFlushKey(hKey);
    RegCloseKey(hKey);

    return TRUE;
}

BOOL UnInstallMiniFilter(void)
{
    SC_HANDLE schManager = NULL;
    SC_HANDLE schService = NULL;
    SERVICE_STATUS svcStatus;

    schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schManager)
    {
        return FALSE;
    }

    schService = OpenService(schManager, DRIVER_NAME, SERVICE_ALL_ACCESS);
    if (!schService)
    {
        CloseServiceHandle(schManager);
        return FALSE;
    }

    ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus);
    if (!DeleteService(schService))
    {
        CloseServiceHandle(schManager);
        CloseServiceHandle(schService);
        return FALSE;
    }

    CloseServiceHandle(schManager);
    CloseServiceHandle(schService);
    return TRUE;

}

BOOL StartFilter(void)
{
    SC_HANDLE schManager = NULL;
    SC_HANDLE schService = NULL;
    DWORD errorCode = 0;

    schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schManager)
    {
        CloseServiceHandle(schManager);
        return FALSE;
    }

    schService = OpenService(schManager, DRIVER_NAME, SERVICE_ALL_ACCESS);
    if (!schService)
    {
        CloseServiceHandle(schManager);
        CloseServiceHandle(schService);
        return FALSE;
    }

    if (!StartService(schService, 0, NULL))
    {
        errorCode = GetLastError();
        CloseServiceHandle(schManager);
        CloseServiceHandle(schService);
        if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
        {
            return TRUE;
        }

        return FALSE;
    }

    CloseServiceHandle(schManager);
    CloseServiceHandle(schService);

    return TRUE;
}

BOOL StopFilter(void)
{
    SC_HANDLE schManager = NULL;
    SC_HANDLE schService = NULL;
    SERVICE_STATUS svcStatus;

    schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schManager)
    {
        return FALSE;
    }

    schService = OpenService(schManager, DRIVER_NAME, SERVICE_ALL_ACCESS);
    if (!schService)
    {
        CloseServiceHandle(schManager);
        return FALSE;
    }

    if (!ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus) && svcStatus.dwCurrentState != SERVICE_STOPPED)
    {
        CloseServiceHandle(schManager);
        CloseServiceHandle(schService);
        return FALSE;
    }

    CloseServiceHandle(schManager);
    CloseServiceHandle(schService);
    return TRUE;
}

int SendDeviceIoControl(int CtrlCode, void* pbBuffer, int cbBuffer)
{
    int dwErrorCode = 0;
    int dwRet = 0;
    CString cLocation;
    HANDLE hDevice = NULL;
    
    hDevice = OpenDevice();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        cLocation.Format(TEXT("打开设备出错:%d!"), dwErrorCode);
        MessageBox(0,cLocation, TEXT("Message"), 0);
        return dwErrorCode;
    }

    dwErrorCode = DeviceIoControl(hDevice, CtrlCode, pbBuffer, cbBuffer, NULL, 0, (LPDWORD)&dwRet, NULL);
    CloseHandle(hDevice);
    return dwErrorCode;
}
