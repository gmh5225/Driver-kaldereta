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

bool mem::writeToReadOnly(void* address, void* buffer, size_t size)
{
	PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!mdl) {
		return false;
	}

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

	RtlCopyMemory(Mapping, buffer, size);

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

bool mem::readBuffer(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
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

bool mem::writeBuffer(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
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

NTSTATUS mem::virtualProtect(ULONG64 pid, PVOID address, ULONG size, ULONG protection, ULONG& protection_out)
{
	if (!pid || !address || !size || !protection) {
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process = nullptr;

	if (NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &process))) {
		ULONG old_protection = 0;
		KAPC_STATE state;

		KeStackAttachProcess(process, &state);

		status = ZwProtectVirtualMemory(NtCurrentProcess(), &address, &size, protection, &old_protection);

		KeUnstackDetachProcess(&state);

		if (NT_SUCCESS(status)) {
			protection_out = old_protection;
		}

		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS mem::virtualAlloc(ULONG64 pid, PVOID address, SIZE_T size, ULONG allocation_type, ULONG protection)
{
	if (!pid || !size || !allocation_type || !protection) {
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process = nullptr;

	if (NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &process))) {
		KAPC_STATE state;

		KeStackAttachProcess(process, &state);

		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &size, allocation_type, protection);

		KeUnstackDetachProcess(&state);

		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS mem::virtualFree(ULONG64 pid, PVOID address, SIZE_T size, ULONG free_type)
{
	if (!pid || !address || !size || !free_type) {
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process = nullptr;

	if (NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &process)))
	{
		SIZE_T size = 0;
		KAPC_STATE state;

		KeStackAttachProcess(process, &state);

		status = ZwFreeVirtualMemory(NtCurrentProcess(), &address, &size, free_type);

		KeUnstackDetachProcess(&state);

		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS mem::initMouse(PMOUSE_OBJECT mouse_obj)
{
	UNICODE_STRING class_string;
	RtlInitUnicodeString(&class_string, L"\\Driver\\MouClass");

	PDRIVER_OBJECT class_driver_object = NULL;
	NTSTATUS status = ObReferenceObjectByName(&class_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&class_driver_object);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "Kaldereta: [Mouse] Failed Initializing Mouse 0x1, Code: %08X\n", status);
		return status; 
	}

	UNICODE_STRING hid_string;
	RtlInitUnicodeString(&hid_string, L"\\Driver\\MouHID");

	PDRIVER_OBJECT hid_driver_object = NULL;
	status = ObReferenceObjectByName(&hid_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&hid_driver_object);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "Kaldereta: [Mouse] Failed Initializing Mouse 0x2, Code: %08X\n", status);
		if (class_driver_object) { ObDereferenceObject(class_driver_object); }
		return status;
	}

	PVOID class_driver_base = NULL;

	PDEVICE_OBJECT hid_device_object = hid_driver_object->DeviceObject;
	while (hid_device_object && !mouse_obj->service_callback)
	{
		PDEVICE_OBJECT class_device_object = class_driver_object->DeviceObject;
		while (class_device_object && !mouse_obj->service_callback)
		{
			if (!class_device_object->NextDevice && !mouse_obj->mouse_device)
			{
				mouse_obj->mouse_device = class_device_object;
			}

			PULONG_PTR device_extension = (PULONG_PTR)hid_device_object->DeviceExtension;
			ULONG_PTR device_ext_size = ((ULONG_PTR)hid_device_object->DeviceObjectExtension - (ULONG_PTR)hid_device_object->DeviceExtension) / 4;
			class_driver_base = class_driver_object->DriverStart;
			for (ULONG_PTR i = 0; i < device_ext_size; i++)
			{
				if (device_extension[i] == (ULONG_PTR)class_device_object && device_extension[i + 1] > (ULONG_PTR)class_driver_object)
				{
					mouse_obj->service_callback = (MouseClassServiceCallback)(device_extension[i + 1]);
					break;
				}
			}
			class_device_object = class_device_object->NextDevice;
		}
		hid_device_object = hid_device_object->AttachedDevice;
	}

	if (!mouse_obj->mouse_device)
	{
		PDEVICE_OBJECT target_device_object = class_driver_object->DeviceObject;
		while (target_device_object)
		{
			if (!target_device_object->NextDevice)
			{
				mouse_obj->mouse_device = target_device_object;
				break;
			}
			target_device_object = target_device_object->NextDevice;
		}
	}

	ObDereferenceObject(class_driver_object);
	ObDereferenceObject(hid_driver_object);

	DbgPrintEx(0, 0, "Kaldereta: [Mouse] Mouse Initialized\n");

	return STATUS_SUCCESS;
}

bool mem::mouseEvent(MOUSE_OBJECT mouse_obj, long x, long y, USHORT button_flags) {
	ULONG input_data;
	KIRQL irql;
	MOUSE_INPUT_DATA mid = { 0 };

	mid.LastX = x;
	mid.LastY = y;
	mid.ButtonFlags = button_flags;

	KeRaiseIrql(DISPATCH_LEVEL, &irql);
	mouse_obj.service_callback(mouse_obj.mouse_device, &mid, (PMOUSE_INPUT_DATA)&mid + 1, &input_data);
	KeLowerIrql(irql);

	return true;
}

NTSTATUS mem::initKeyboard(PKEYBOARD_OBJECT keyboard_obj)
{
	UNICODE_STRING class_string;
	RtlInitUnicodeString(&class_string, L"\\Driver\\KbdClass");

	PDRIVER_OBJECT class_driver_object = NULL;
	NTSTATUS status = ObReferenceObjectByName(&class_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&class_driver_object);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "Kaldereta: [Keyboard] Failed Initializing Keyboard 0x1, Code: %08X\n", status);
		return status;
	}

	UNICODE_STRING hid_string;
	RtlInitUnicodeString(&hid_string, L"\\Driver\\KbdHID");

	PDRIVER_OBJECT hid_driver_object = NULL;
	status = ObReferenceObjectByName(&hid_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&hid_driver_object);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "Kaldereta: [Keyboard] Failed Initializing Keyboard 0x2, Code: %08X\n", status);
		if (class_driver_object) { ObDereferenceObject(class_driver_object); }
		return status;
	}

	PVOID class_driver_base = NULL;

	PDEVICE_OBJECT hid_device_object = hid_driver_object->DeviceObject;
	while (hid_device_object && !keyboard_obj->service_callback)
	{
		PDEVICE_OBJECT class_device_object = class_driver_object->DeviceObject;
		while (class_device_object && !keyboard_obj->service_callback)
		{
			if (!class_device_object->NextDevice && !keyboard_obj->keyboard_device)
			{
				keyboard_obj->keyboard_device = class_device_object;
			}

			PULONG_PTR device_extension = (PULONG_PTR)hid_device_object->DeviceExtension;
			ULONG_PTR device_ext_size = ((ULONG_PTR)hid_device_object->DeviceObjectExtension - (ULONG_PTR)hid_device_object->DeviceExtension) / 4;
			class_driver_base = class_driver_object->DriverStart;
			for (ULONG_PTR i = 0; i < device_ext_size; i++)
			{
				if (device_extension[i] == (ULONG_PTR)class_device_object && device_extension[i + 1] > (ULONG_PTR)class_driver_object)
				{
					keyboard_obj->service_callback = (KeyboardClassServiceCallback)(device_extension[i + 1]);
					break;
				}
			}
			class_device_object = class_device_object->NextDevice;
		}
		hid_device_object = hid_device_object->AttachedDevice;
	}

	if (!keyboard_obj->keyboard_device)
	{
		PDEVICE_OBJECT target_device_object = class_driver_object->DeviceObject;
		while (target_device_object)
		{
			if (!target_device_object->NextDevice)
			{
				keyboard_obj->keyboard_device = target_device_object;
				break;
			}
			target_device_object = target_device_object->NextDevice;
		}
	}

	ObDereferenceObject(class_driver_object);
	ObDereferenceObject(hid_driver_object);

	DbgPrintEx(0, 0, "Kaldereta: [Keyboard] Keyboard Initialized\n");

	return STATUS_SUCCESS;
}

bool mem::keyboardEvent(KEYBOARD_OBJECT keyboard_obj, USHORT keyCode, USHORT button_flags) {
	ULONG input_data;
	KIRQL irql;
	KEYBOARD_INPUT_DATA kid = { 0 };

	kid.MakeCode = keyCode;
	kid.Flags = button_flags;

	KeRaiseIrql(DISPATCH_LEVEL, &irql);
	keyboard_obj.service_callback(keyboard_obj.keyboard_device, &kid, (PKEYBOARD_INPUT_DATA)&kid + 1, &input_data);
	KeLowerIrql(irql);

	return true;
}

ULONG mem::getProcessId(UNICODE_STRING process_name) {
	ULONG proc_id = 0;
	NTSTATUS status = STATUS_SUCCESS;
	
	PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, 1024 * 1024, 'enoN');
	if (!buffer) {
		DbgPrintEx(0, 0, "Kaldereta: [ProcessID] Failed 0x1\n");
		return 0;
	}

	PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	
	status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, 1024 * 1024, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "Kaldereta: [ProcessID] Failed 0x2\n");
		return 0;
	}

	for (;;) {
		if (RtlEqualUnicodeString(&pInfo->ImageName, &process_name, TRUE)) {
			return (ULONG)pInfo->UniqueProcessId;
		}
		else if (pInfo->NextEntryOffset)
			pInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
		else
			break;
	}

	ExFreePoolWithTag(buffer, 'enoN');

	return proc_id;
}