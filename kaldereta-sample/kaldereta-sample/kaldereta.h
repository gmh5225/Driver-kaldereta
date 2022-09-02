#pragma once

#include <string>
#include <locale>
#include <codecvt>
#include <memory>
#include <thread>
#include <system_error>
#include <TlHelp32.h>
#include "kalderata_defs.h"

typedef struct __KALDERETA_MEMORY
{
	ULONG pid;
	ULONG protection;
	ULONG oldProtection;
	UINT_PTR address;
	ULONG64 baseAddress;
	ULONGLONG imageSize;
	ULONGLONG size;
	ULONG x;
	ULONG y;
	USHORT buttonFlags;

	BOOLEAN reqBase;
	BOOLEAN virtualProtect;
	BOOLEAN allocateMemory;
	BOOLEAN freeMemory;
	BOOLEAN write;
	BOOLEAN writeString;
	BOOLEAN read;
	BOOLEAN readString;
	BOOLEAN mouseEvent;

	const char* moduleName;

	void* output;
	void* bufferAddress;
}KALDERETA_MEMORY;

struct HandleDisposer
{
	using pointer = HANDLE;
	void operator()(HANDLE handle) const {
		if (handle != NULL || handle != INVALID_HANDLE_VALUE) {
			CloseHandle(handle);
		}
	}
};

using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;

namespace kdt {
	static std::uint32_t procID;
	static ULONGLONG imageSize;
	static std::uintptr_t baseAddress;
	
	// hook win function to communicate with driver
	template<typename ... A>
	uint64_t callHook(const A ... args)
	{
		LoadLibrary(L"user32.dll");
		void* controlFunction = (void*)GetProcAddress(LoadLibrary(L"win32u.dll"), "NtTokenManagerGetAnalogExclusiveTokenEvent");
		const auto control = static_cast<uint64_t(__stdcall*)(A...)>(controlFunction);
		return control(args ...);
	}

	namespace {
		int iSizeOfArray(int* iArray)
		{
			for (int iLength = 1; iLength < MAX_PATH; iLength++)
				if (iArray[iLength] == '*')
					return iLength;
			return 0;
		}

		bool simulateMouseEvent(USHORT flags) {
			KALDERETA_MEMORY m = { 0 };

			m.pid = procID;
			m.mouseEvent = TRUE;
			m.buttonFlags = flags;

			callHook(&m);

			return true;
		}
	}

	// get process id of a program
	static std::uint32_t getProcID(const std::string processName)
	{
		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
		std::wstring procName = converter.from_bytes(processName);

		PROCESSENTRY32 pe32{ 0 };
		const unique_handle snapshotHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));

		if (snapshotHandle.get() == INVALID_HANDLE_VALUE)
			return 0;

		pe32.dwSize = sizeof(pe32);

		if (Process32First(snapshotHandle.get(), &pe32)) {
			while (Process32Next(snapshotHandle.get(), &pe32) == TRUE) {
				if (procName.compare(pe32.szExeFile) == 0)
				{
					printf("[+] Process ID: %d\n", pe32.th32ProcessID);
					return pe32.th32ProcessID;
				}
			}
		}

		return 0;
	}

	// get base address of an image
	static ULONG64 getBaseAddress(const char* moduleName)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.reqBase = TRUE;
		m.moduleName = moduleName;

		callHook(&m);
		
		imageSize = m.imageSize;

		return m.baseAddress;
	}

	// change protection of a memory region
	static ULONG64 virtualProtect(uint64_t address, uint32_t pageProtection, std::size_t size)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.address = address;
		m.protection = pageProtection;
		m.size = size;
		m.virtualProtect = TRUE;

		return callHook(&m);
	}

	// add memory region
	static ULONG64 allocateMemory(std::size_t size, uint32_t protection)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.protection = protection;
		m.size = size;
		m.allocateMemory = TRUE;

		callHook(&m);

		return m.address;
	}

	// free memory
	static bool freeMemory(UINT_PTR address)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.freeMemory = TRUE;

		callHook(&m);

		return true;
	}

	// read from address
	template <class T>
	T read(UINT_PTR readAddress)
	{
		T response{};
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.size = sizeof(T);
		m.address = readAddress;
		m.read = TRUE;
		m.output = &response;

		callHook(&m);
		return *(T*)&m.output;
	}

	// read from address with offset
	template <class T>
	T read(DWORD dwAddress, char* Offset, BOOL isAddress = false)
	{
		int iSize = iSizeOfArray((int*)Offset) - 1;
		dwAddress = read<DWORD>(dwAddress);

		for (int i = 0; i < iSize; i++)
			dwAddress = read<DWORD>(dwAddress + Offset[i]);

		if (isAddress)
			return dwAddress + Offset[iSize];
		else
			return read<T>(dwAddress + Offset[iSize]);
	}

	// write to address
	template <class T>
	bool write(UINT_PTR writeAddress, const T& value)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.address = writeAddress;
		m.write = TRUE;
		m.bufferAddress = (void*)((UINT_PTR)&value);
		m.size = sizeof(T);

		callHook(&m);

		return true;
	}

	// write to address with offset
	template <class T>
	bool write(DWORD dwAddress, char* Offset, T Value)
	{
		return write<T>(read<T>(dwAddress, Offset, false), Value);
	}

	// read string from address
	static bool readString(UINT_PTR address, void* buffer, SIZE_T size)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.readString = TRUE;
		m.address = address;
		m.bufferAddress = buffer;
		m.size = size;

		callHook(&m);
		
		return true;
	}

	// write string to address
	static bool writeString(UINT_PTR address, void* buffer, SIZE_T size)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.writeString = TRUE;
		m.address = address;
		m.bufferAddress = buffer;
		m.size = size;

		callHook(&m);

		return true;
	}

	// mouse events
	static void click() {
		simulateMouseEvent(MOUSE_LEFT_BUTTON_DOWN);
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		simulateMouseEvent(MOUSE_LEFT_BUTTON_UP);
	}
}