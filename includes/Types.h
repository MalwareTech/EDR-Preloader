#pragma once

#include <winternl.h>

typedef NTSTATUS(WINAPI *t_NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize,
													ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(WINAPI *t_NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect,
												   PULONG OldProtect);
typedef NTSTATUS(WINAPI *t_LdrLoadDll)(PWSTR search_path, PULONG dll_characteristics, UNICODE_STRING* dll_name, PVOID* base_address);
typedef NTSTATUS(WINAPI *t_NtContinue)(PCONTEXT ThreadContext, BOOLEAN RaiseAlert);
typedef LPVOID(WINAPI *t_BaseThreadInitThunk)(DWORD unknown, LPVOID thread_start, LPVOID param);
typedef void (WINAPI *t_OutputDebugStringW)(LPCWSTR lpOutputString);

struct PTR_TABLE {
	t_NtProtectVirtualMemory NtProtectVirtualMemory;
	t_NtAllocateVirtualMemory NtAllocateVirtualMemory;
	t_LdrLoadDll LdrLoadDll;
	t_NtContinue NtContinue;
	t_OutputDebugStringW OutputDebugStringW;
	LPVOID KiUserApcDispatcher;
};

typedef struct _LDR_DATA_TABLE_ENTRY2
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
} LDR_DATA_TABLE_ENTRY2, *PLDR_DATA_TABLE_ENTRY2;