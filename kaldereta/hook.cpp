#include "hook.h"

MOUSE_OBJECT mouse_obj = { 0 };
KEYBOARD_OBJECT keyboard_obj = { 0 };

bool hook::callKernelFunc(void* kernelFunctionAddress)
{
	if (!kernelFunctionAddress) {
		DbgPrintEx(0, 0, "Kaldereta: [CallKernelFunction] kernel function address not found\n");
		return false;
	}

	uintptr_t hookAddress = reinterpret_cast<uintptr_t>(kernelFunctionAddress);

	PVOID* function = reinterpret_cast<PVOID*>(mem::getModuleExport("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtTokenManagerGetAnalogExclusiveTokenEvent"));

	if (!function)
	{
		DbgPrintEx(0, 0, "Kaldereta: [CallKernelFunction] function not found\n");
		return false;
	}

	BYTE orig[] = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00 };

	BYTE shellCodeStart[]
	{
		0x48, 0xB8 //mov rax, FFFFFFFFFF
	};

	BYTE shellCodeEnd[]
	{
		0xFF, 0xE0, // jmp rax
		0xCC
	};

	RtlSecureZeroMemory(&orig, sizeof(orig));

	memcpy((PVOID)((ULONG_PTR)orig), shellCodeStart, sizeof(shellCodeStart));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shellCodeStart)), &hookAddress, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shellCodeStart) + sizeof(void*)), &shellCodeEnd, sizeof(shellCodeEnd));

	mem::writeToReadOnly(function, &orig, sizeof(orig));

	return true;
}

NTSTATUS hook::hookHandler(PVOID calledParam)
{
	KALDERETA_MEMORY* pMem = (KALDERETA_MEMORY*)calledParam;
	
	if (!mouse_obj.service_callback || !mouse_obj.mouse_device) {
		mem::initMouse(&mouse_obj);
	}

	if (!keyboard_obj.service_callback || !keyboard_obj.keyboard_device) {
		mem::initKeyboard(&keyboard_obj);
	}

	// get process id
	if (pMem->reqProcessId != FALSE) {
		ANSI_STRING AS;
		UNICODE_STRING process_name;

		RtlInitAnsiString(&AS, pMem->moduleName);
		RtlAnsiStringToUnicodeString(&process_name, &AS, TRUE);

		ULONG proc_id = mem::getProcessId(process_name);
		pMem->pid = proc_id;

		DbgPrintEx(0, 0, "Kaldereta: [ProcessID] - %08X\n", pMem->pid);

		RtlFreeUnicodeString(&process_name);
	}

	// getting base address and image size
	if (pMem->reqBaseAddress != FALSE)
	{
		ANSI_STRING AS;
		UNICODE_STRING moduleName;

		RtlInitAnsiString(&AS, pMem->moduleName);
		RtlAnsiStringToUnicodeString(&moduleName, &AS, TRUE);

		PEPROCESS process;
		PsLookupProcessByProcessId((HANDLE)pMem->pid, &process);
		ULONG64 baseAddress64 = NULL;

		ULONGLONG imageSize = 0;

		baseAddress64 = mem::getModuleBase64(process, moduleName, imageSize);
		pMem->baseAddress = baseAddress64;
		pMem->imageSize = imageSize;

		DbgPrintEx(0, 0, "Kaldereta: [BaseAddress] - %012X\n", pMem->baseAddress);
		DbgPrintEx(0, 0, "Kaldereta: [ImageSize] - %012X\n", imageSize);

		RtlFreeUnicodeString(&moduleName);
	}

	// changing memory protection
	if (pMem->virtualProtect != FALSE)
	{
		ULONG old_protection;
		NTSTATUS status = mem::virtualProtect(pMem->pid, (PVOID)pMem->address, pMem->size, pMem->protection, old_protection);

		if (NT_SUCCESS(status)) {
			DbgPrintEx(0, 0, "Kaldereta: [VirtualProtect] Changed Protection at %012X\n", pMem->address);
		}
		else {
			DbgPrintEx(0, 0, "Kaldereta: [VirtualProtect] Failed Changing Page Protection, Code: %08X\n", status);
		}

		pMem->oldProtection = old_protection;
	}

	// allocate memory
	if (pMem->virtualAlloc != FALSE)
	{
		NTSTATUS status = mem::virtualAlloc(pMem->pid, (PVOID)pMem->address, pMem->size, pMem->allocationType, pMem->protection);

		if (NT_SUCCESS(status)) {
			DbgPrintEx(0, 0, "Kaldereta: [VirtualAlloc] Allocated Memory at %012X\n", pMem->address);
		}
		else {
			DbgPrintEx(0, 0, "Kaldereta: [VirtualAlloc] Failed Allocating Memory, Code: %08X\n", status);
		}
	}

	// free memory
	if (pMem->virtualFree != FALSE)
	{
		NTSTATUS status = mem::virtualFree(pMem->pid, (PVOID)pMem->address, pMem->size, pMem->freeType);

		if (NT_SUCCESS(status)) {
			DbgPrintEx(0, 0, "Kaldereta: [VirtualFree] Freed %08X at %012X\n", pMem->size, pMem->address);
		}
		else {
			DbgPrintEx(0, 0, "Kaldereta: [VirtualFree] Failed Freeing Memory, Code: %08X\n", status);
		}
	}

	// write to memory
	if (pMem->write != FALSE)
	{
		PVOID kernelBuff = ExAllocatePool(NonPagedPool, pMem->size);

		if (!kernelBuff)
			return STATUS_UNSUCCESSFUL;

		if (!memcpy(kernelBuff, pMem->bufferAddress, pMem->size))
			return STATUS_UNSUCCESSFUL;

		PEPROCESS Process;
		PsLookupProcessByProcessId((HANDLE)pMem->pid, &Process);
		mem::writeBuffer((HANDLE)pMem->pid, pMem->address, kernelBuff, pMem->size);

		DbgPrintEx(0, 0, "Kaldereta: [WriteMemory] Wrote Memory at %012X\n", pMem->address);

		ExFreePool(kernelBuff);
	}

	// write to memory from buffer
	if (pMem->writeBuffer != FALSE)
	{
		PVOID kernelBuffer = ExAllocatePool(NonPagedPool, pMem->size);

		if (!kernelBuffer)
			return STATUS_UNSUCCESSFUL;

		if (!memcpy(kernelBuffer, pMem->bufferAddress, pMem->size))
			return STATUS_UNSUCCESSFUL;

		PEPROCESS Process;

		PsLookupProcessByProcessId((HANDLE)pMem->pid, &Process);

		mem::writeBuffer((HANDLE)pMem->pid, pMem->address, kernelBuffer, pMem->size);

		DbgPrintEx(0, 0, "Kaldereta: [WriteToBuffer] Wrote Buffer to %012X\n", pMem->address);

		ExFreePool(kernelBuffer);
	}

	// read from memory
	if (pMem->read != FALSE)
	{
		void* ReadOutput = NULL;
		mem::readBuffer((HANDLE)pMem->pid, pMem->address, &ReadOutput, pMem->size);

		DbgPrintEx(0, 0, "Kaldereta: [ReadMemory] Read Memory at %012X\n", pMem->address);

		pMem->output = ReadOutput;
	}

	// read from memory to buffer
	if (pMem->readBuffer != FALSE)
	{
		PVOID kernelBuffer = ExAllocatePool(NonPagedPool, pMem->size);

		if (!kernelBuffer)
			return STATUS_UNSUCCESSFUL;


		if (!memcpy(kernelBuffer, pMem->bufferAddress, pMem->size))
			return STATUS_UNSUCCESSFUL;

		mem::readBuffer((HANDLE)pMem->pid, pMem->address, kernelBuffer, pMem->size);

		DbgPrintEx(0, 0, "Kaldereta: [ReadToBuffer] Read from Buffer at %012X\n", pMem->address);

		RtlZeroMemory(pMem->bufferAddress, pMem->size);

		if (!memcpy(pMem->bufferAddress, kernelBuffer, pMem->size))
			return STATUS_UNSUCCESSFUL;

		ExFreePool(kernelBuffer);
	}

	// mouse event
	if (pMem->mouseEvent != FALSE) {
		mem::mouseEvent(mouse_obj, pMem->x, pMem->y, pMem->buttonFlags);

		DbgPrintEx(0, 0, "Kaldereta: [MouseEvent] MouseEvent Flags: %08X\n", pMem->buttonFlags);
	}

	// keyboard event
	if (pMem->keyboardEvent != FALSE) {
		mem::keyboardEvent(keyboard_obj, pMem->keyCode, pMem->buttonFlags);

		DbgPrintEx(0, 0, "Kaldereta: [KeyboardEvent] MouseEvent KeyCode: %08X, Flags: %08X\n", pMem->keyCode, pMem->buttonFlags);
	}

	return STATUS_SUCCESS;
}