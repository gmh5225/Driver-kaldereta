#include "memory.h"

PVOID mem::getModuleBase(const char* moduleName)
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes)
		return NULL;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x54697465);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
		return NULL;

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	PVOID moduleBase = 0, moduleSize = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp((char*)module[i].FullPathName, moduleName) == 0)
		{
			moduleBase = module[i].ImageBase;
			moduleSize = (PVOID)module[i].ImageBase;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, NULL);

	if (moduleBase <= NULL)
		return NULL;

	return moduleBase;
}

PVOID mem::getModuleExport(const char* moduleName, LPCSTR routineName)
{
	PVOID lpModule = getModuleBase(moduleName);

	if (!lpModule)
		return NULL;

	return RtlFindExportedRoutineByName(lpModule, routineName);
}

bool mem::WPM(void* address, void* buffer, size_t size)
{
	return (!RtlCopyMemory(address, buffer, size)) ? false : true;
}

bool mem::WPM2(void* address, void* buffer, size_t size)
{
	PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!mdl)
		return false;

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

	WPM(Mapping, buffer, size);

	MmUnmapLockedPages(Mapping, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return true;
}

ULONG64 mem::getModuleBase64(PEPROCESS proc, UNICODE_STRING moduleName, ULONGLONG& imageSize)
{
	PPEB pPeb = PsGetProcessPeb(proc);
	if (!pPeb)
		return 0;

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr)
	{
		KeUnstackDetachProcess(&state);
		return 0;
	}

	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink; list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &moduleName, TRUE) == 0)
		{
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			imageSize = pEntry->SizeOfImage;

			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}

	KeUnstackDetachProcess(&state);
	return 0;
}

bool mem::readMemory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	if (!address || !buffer || !size)
		return false;

	SIZE_T bytes = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	status = MmCopyVirtualMemory(process, (void*)address, (PEPROCESS)PsGetCurrentProcess(), (void*)buffer, size, KernelMode, &bytes);

	if (!NT_SUCCESS(status))
		return false;
	return true;
}

bool mem::writeMemory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	if (!address || !buffer || !size)
		return false;

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId(pid, &process);

	KAPC_STATE state;
	KeStackAttachProcess((PKPROCESS)process, &state);

	MEMORY_BASIC_INFORMATION info;

	status = ZwQueryVirtualMemory(ZwCurrentProcess(), (PVOID)address, MemoryBasicInformation, &info, sizeof(info), NULL);

	if (!NT_SUCCESS(status)) {
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (((uintptr_t)info.BaseAddress + info.RegionSize) < (address + size))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (!(info.State & MEM_COMMIT) || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if ((info.Protect & PAGE_EXECUTE_READWRITE) || (info.Protect & PAGE_EXECUTE_WRITECOPY) || (info.Protect & PAGE_READWRITE) || (info.Protect & PAGE_WRITECOPY))
	{
		RtlCopyMemory((void*)address, buffer, size);
	}

	KeUnstackDetachProcess(&state);
	return true;
}

NTSTATUS mem::protectMemory(ULONG64 pid, PVOID address, ULONG size, ULONG protection, ULONG& protection_out)
{
	if (!pid || !address || !size || !protection)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process = nullptr;

	if (NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &process)))
	{
		//PVOID address = reinterpret_cast<PVOID>( memory_struct->address );
		//ULONG size = (ULONG)( memory_struct->size );
		//ULONG protection = memory_struct->protection;
		ULONG protection_old = 0;

		KAPC_STATE state;
		KeStackAttachProcess(process, &state);

		status = ZwProtectVirtualMemory(NtCurrentProcess(), &address, &size, protection, &protection_old);

		KeUnstackDetachProcess(&state);

		if (NT_SUCCESS(status))
			protection_out = protection_old;

		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS mem::allocateMemory(ULONG64 pid, SIZE_T size, ULONG protection, PVOID& address_out)
{
	if (!pid || !size || !protection)
		return STATUS_INVALID_PARAMETER;

	DbgPrintEx(0, 0, "Kaldereta: [AllocateMemory] Starting\n");

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process = nullptr;

	if (NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &process)))
	{
		PVOID address = NULL;
		KAPC_STATE state;

		KeStackAttachProcess(process, &state);

		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, protection);

		KeUnstackDetachProcess(&state);

		if (NT_SUCCESS(status))
			address_out = address;
		else
			DbgPrintEx(0, 0, "Kaldereta: [AllocateMemory] Failed Allocation Memory %08X\n", address);

		ObDereferenceObject(process);
	}
	else
		DbgPrintEx(0, 0, "Kaldereta: [AllocateMemory] Cant Find ID\n");

	return status;
}

NTSTATUS mem::freeMemory(ULONG64 pid, PVOID address, SIZE_T& size_out)
{
	if (!pid)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process = nullptr;

	if (NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &process)))
	{
		SIZE_T size = 0;
		KAPC_STATE state;

		KeStackAttachProcess(process, &state);

		status = ZwFreeVirtualMemory(NtCurrentProcess(), &address, &size, MEM_RELEASE);

		KeUnstackDetachProcess(&state);

		if (NT_SUCCESS(status))
			size_out = size;
		else
			DbgPrintEx(0, 0, "Kaldereta: [AllocateMemory] Failed freeing memory\n");

		ObDereferenceObject(process);
	}

	return status;
}