#pragma once
#include "defs.h"

namespace mem {
	static PVOID g_KernelBase = NULL;
	static ULONG g_KernelSize = 0;

	PVOID getModuleBase(const char* moduleName);
	PVOID getModuleExport(const char* moduleName, LPCSTR routineName);
	bool WPM(void* address, void* buffer, size_t size);
	bool WPM2(void* address, void* buffer, size_t size);
	ULONG64 getModuleBase64(PEPROCESS proc, UNICODE_STRING moduleName, ULONGLONG& imageSize);
	bool readMemory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
	bool writeMemory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
	NTSTATUS protectMemory(ULONG64 pid, PVOID address, ULONG size, ULONG protection, ULONG& protection_out);
	NTSTATUS allocateMemory(ULONG64 pid, SIZE_T size, ULONG protection, PVOID& address_out);
	NTSTATUS freeMemory(ULONG64 pid, PVOID address, SIZE_T& size_out);
}