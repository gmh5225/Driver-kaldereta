#include "hook.h"

MOUSE_OBJECT mouse_obj = { 0 };

bool hook::callKernelFunc(void* kernelFunctionAddress)
{
	if (!kernelFunctionAddress) {
		DbgPrintEx(0, 0, "Kaldereta: [CallKernelFunction] kernel function address not found\n");
		return false;
	}

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

	uintptr_t hookAddress = reinterpret_cast<uintptr_t>(kernelFunctionAddress);

	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shellCodeStart)), &hookAddress, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shellCodeStart) + sizeof(void*)), &shellCodeEnd, sizeof(shellCodeEnd));

	mem::WPM2(function, &orig, sizeof(orig));

	return true;
}

NTSTATUS hook::hookHandler(PVOID calledParam)
{
	KALDERETA_MEMORY* pMem = (KALDERETA_MEMORY*)calledParam;
	
	if (!mouse_obj.service_callback || !mouse_obj.mouse_device) {
		DbgPrintEx(0, 0, "Kaldereta: [MouseEvent] Initializing Mouse Service\n");
		mem::initMouse(&mouse_obj);
	}

	// getting base address and image size
	if (pMem->reqBase != FALSE)
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
		if (NT_SUCCESS(mem::protectMemory(pMem->pid, (PVOID)pMem->address, pMem->size, pMem->protection, pMem->oldProtection)))
			DbgPrintEx(0, 0, "Kaldereta: [VirtualProtect] Succefully Changed Protection at %012X\n", pMem->address);
		else
			DbgPrintEx(0, 0, "Kaldereta: [VirtualProtect] Failed Changing Page Protection\n");
	}

	// allocate memory
	if (pMem->allocateMemory != FALSE)
	{
		PVOID address;
		if (NT_SUCCESS(mem::allocateMemory(pMem->pid, pMem->size, pMem->protection, address)))
			DbgPrintEx(0, 0, "Kaldereta: [AllocateMemory] Allocated Memory at %012X\n", address);
		else
			DbgPrintEx(0, 0, "Kaldereta: [AllocateMemory] Failed Allocating Memory\n");

		pMem->address = (UINT_PTR)address;
	}

	// free memory
	if (pMem->freeMemory != FALSE)
	{
		SIZE_T size;
		if (NT_SUCCESS(mem::freeMemory(pMem->pid, (PVOID)pMem->address, size)))
			DbgPrintEx(0, 0, "Kaldereta: [FreeMemory] Freed %012X at %012X\n", size, pMem->address);

		pMem->size = size;
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
		mem::writeMemory((HANDLE)pMem->pid, pMem->address, kernelBuff, pMem->size);

		DbgPrintEx(0, 0, "Kaldereta: [WriteMemory] Wrote Memory at %012X\n", pMem->address);

		ExFreePool(kernelBuff);
	}

	// write string to memory
	if (pMem->writeString != FALSE)
	{
		PVOID kernelBuffer = ExAllocatePool(NonPagedPool, pMem->size);

		if (!kernelBuffer)
			return STATUS_UNSUCCESSFUL;

		if (!memcpy(kernelBuffer, pMem->bufferAddress, pMem->size))
			return STATUS_UNSUCCESSFUL;

		PEPROCESS Process;

		PsLookupProcessByProcessId((HANDLE)pMem->pid, &Process);

		mem::writeMemory((HANDLE)pMem->pid, pMem->address, kernelBuffer, pMem->size);

		DbgPrintEx(0, 0, "Kaldereta: [WriteMemoryString] Wrote Memory String at %012X\n", pMem->address);

		ExFreePool(kernelBuffer);
	}

	// read from memory
	if (pMem->read != FALSE)
	{
		void* ReadOutput = NULL;
		mem::readMemory((HANDLE)pMem->pid, pMem->address, &ReadOutput, pMem->size);

		DbgPrintEx(0, 0, "Kaldereta: [ReadMemory] Read Memory at %012X\n", pMem->address);

		pMem->output = ReadOutput;
	}

	// read string from memory
	if (pMem->readString != FALSE)
	{
		PVOID kernelBuffer = ExAllocatePool(NonPagedPool, pMem->size);

		if (!kernelBuffer)
			return STATUS_UNSUCCESSFUL;


		if (!memcpy(kernelBuffer, pMem->bufferAddress, pMem->size))
			return STATUS_UNSUCCESSFUL;

		mem::readMemory((HANDLE)pMem->pid, pMem->address, kernelBuffer, pMem->size);

		DbgPrintEx(0, 0, "Kaldereta: [ReadMemoryString] Read Memory String at %012X\n", pMem->address);

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

	return STATUS_SUCCESS;
}