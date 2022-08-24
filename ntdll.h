#pragma once

#include <Windows.h>

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
