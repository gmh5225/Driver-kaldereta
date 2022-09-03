#pragma once
#include "defs.h"

namespace mem {
	static PVOID g_KernelBase = NULL;
	static ULONG g_KernelSize = 0;

	PVOID getModuleBase(const char* moduleName);
	PVOID getModuleExport(const char* moduleName, LPCSTR routineName);
	bool writeToReadOnly(void* address, void* buffer, size_t size);
	ULONG64 getModuleBase64(PEPROCESS proc, UNICODE_STRING moduleName, ULONGLONG& imageSize);
	bool readBuffer(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
	bool writeBuffer(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
	NTSTATUS virtualProtect(ULONG64 pid, PVOID address, ULONG size, ULONG protection, ULONG& protection_out);
	NTSTATUS virtualAlloc(ULONG64 pid, PVOID& address, SIZE_T size, ULONG allocation_type, ULONG protection);
	NTSTATUS virtualFree(ULONG64 pid, PVOID address, ULONG free_type, SIZE_T& size_out);
	NTSTATUS initMouse(PMOUSE_OBJECT mouse_obj);
	NTSTATUS initKeyboard(PKEYBOARD_OBJECT keyboard_obj);
	bool mouseEvent(MOUSE_OBJECT mouse_obj, long x, long y, USHORT button_flags);
	bool keyboardEvent(KEYBOARD_OBJECT keyboard_obj, USHORT key_flags, USHORT button_flags);
	ULONG getProcessId(UNICODE_STRING process_name);
}