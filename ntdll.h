#pragma once

#include <Windows.h>
#include <psapi.h>

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

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID EntryPoint;
	ULONG StackZeroBits;
	ULONG StackReserved;
	ULONG StackCommit;
	ULONG ImageSubsystem;
	WORD SubSystemVersionLow;
	WORD SubSystemVersionHigh;
	ULONG Unknown1;
	ULONG ImageCharacteristics;
	ULONG ImageMachineType;
	ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StdInputHandle;
	HANDLE StdOutputHandle;
	HANDLE StdErrorHandle;
	UNICODE_STRING CurrentDirectoryPath;
	HANDLE CurrentDirectoryHandle;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingPositionLeft;
	ULONG StartingPositionTop;
	ULONG Width;
	ULONG Height;
	ULONG CharWidth;
	ULONG CharHeight;
	ULONG ConsoleTextAttributes;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopName;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Size;
	HANDLE ProcessHandle;
	HANDLE ThreadHandle;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;


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
extern NT_CREATE_SECTION NtCreateSection;

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
extern NT_MAP_VIEW_OF_SECTION NtMapViewOfSection;

typedef NTSTATUS(NTAPI* NT_UNMAP_VIEW_OF_SECTION) (
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress
	);
extern NT_UNMAP_VIEW_OF_SECTION NtUnmapViewOfSection;

typedef NTSTATUS(NTAPI* NT_WRITE_VIRTUAL_MEMORY) (
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG NumberOfBytesToWrite,
	OUT PULONG NumberOfBytesWritten OPTIONAL
	);
extern NT_WRITE_VIRTUAL_MEMORY NtWriteVirtualMemory;

typedef VOID(NTAPI* RTL_INIT_UNICODE_STRING) (
	OUT PUNICODE_STRING DestinationString,
	IN PCWSTR SourceString OPTIONAL
	);
extern RTL_INIT_UNICODE_STRING RtlInitUnicodeString;

typedef NTSTATUS(NTAPI* RTL_CREATE_PROCESS_PARAMETERS) (
	OUT PRTL_USER_PROCESS_PARAMETERS* ProcessParameters,
	IN PUNICODE_STRING ImagePathName,
	IN PUNICODE_STRING DllPath OPTIONAL,
	IN PUNICODE_STRING CurrentDirectoryPath OPTIONAL,
	IN PUNICODE_STRING CommandLine OPTIONAL,
	IN PVOID Environment OPTIONAL,
	IN PUNICODE_STRING WindowTitle OPTIONAL,
	IN PUNICODE_STRING DesktopName OPTIONAL,
	IN PUNICODE_STRING ShellInfo OPTIONAL,
	IN PUNICODE_STRING RuntimeData OPTIONAL
	);
extern RTL_CREATE_PROCESS_PARAMETERS RtlCreateProcessParameters;

typedef NTSTATUS(NTAPI* RTL_CREATE_USER_PROCESS) (
	IN PUNICODE_STRING ImagePath,
	IN ULONG ObjectAttributes,
	IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	IN PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
	IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritHandles,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	OUT PRTL_USER_PROCESS_INFORMATION ProcessInformation);
extern RTL_CREATE_USER_PROCESS RtlCreateUserProcess;

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
extern RTL_CREATE_USER_THREAD RtlCreateUserThread;

typedef NTSTATUS(NTAPI* NT_WAIT_FOR_SINGLE_OBJECT) (
	IN HANDLE ObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL
	);
extern NT_WAIT_FOR_SINGLE_OBJECT NtWaitForSingleObject;

typedef NTSTATUS(NTAPI* NT_CLOSE) (
	IN HANDLE ObjectHandle
	);
extern NT_CLOSE NtClose;


/* helper functions */
void unhookNtdll(HMODULE ntdll);
void loadNtdll(HMODULE ntdll);
void checkNtStatus(NTSTATUS status);
