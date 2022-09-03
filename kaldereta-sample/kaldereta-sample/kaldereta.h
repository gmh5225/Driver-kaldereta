#pragma once

#include <Windows.h>
#include <string>
#include <memory>
#include <thread>
#include <system_error>
#include <TlHelp32.h>
#include "kalderata_defs.h"

typedef struct __KALDERETA_MEMORY
{
	ULONG pid;
	ULONG protection;
	ULONG allocationType;
	ULONG freeType;
	ULONG oldProtection;
	UINT_PTR address;
	ULONG64 baseAddress;
	ULONGLONG imageSize;
	ULONGLONG size;
	long x;
	long y;
	USHORT buttonFlags;
	USHORT keyCode;

	BOOLEAN reqProcessId;
	BOOLEAN reqBaseAddress;
	BOOLEAN virtualProtect;
	BOOLEAN virtualAlloc;
	BOOLEAN virtualFree;
	BOOLEAN write;
	BOOLEAN writeBuffer;
	BOOLEAN read;
	BOOLEAN readBuffer;
	BOOLEAN mouseEvent;
	BOOLEAN keyboardEvent;

	const char* moduleName;

	void* output;
	void* bufferAddress;
}KALDERETA_MEMORY;

namespace kdt {
	static std::uint32_t procID;
	static ULONGLONG imageSize;
	static std::uintptr_t baseAddress;
	static HWND windowHandle;
	
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

		uintptr_t compare(char* base, unsigned int size, char* pattern, char* mask)
		{
			size_t patternLength = strlen(mask);

			for (uintptr_t i = 0; i < size - patternLength; i++)
			{
				bool found = true;
				for (uintptr_t j = 0; j < patternLength; j++)
				{
					if (mask[j] != '?' && pattern[j] != *(char*)(base + i + j))
					{
						found = false;
						break;
					}
				}

				if (found)
				{
					return (uintptr_t)base + i;
				}
			}
			return 0;
		}

		// simulate mouse events
		bool mouseEvent(USHORT flags, long x = -1, long y = -1) {
			KALDERETA_MEMORY m = { 0 };

			m.mouseEvent = TRUE;
			if (x != -1 && y != -1) {
				m.x = x;
				m.y = y;
			}
			m.buttonFlags = flags;

			callHook(&m);

			return true;
		}

		// simulate keyboard events
		bool keyboardEvent(USHORT keyCode, USHORT flags) {
			KALDERETA_MEMORY m = { 0 };

			m.keyboardEvent = TRUE;
			m.keyCode = (USHORT)MapVirtualKey(keyCode, 0);
			m.buttonFlags = flags;

			callHook(&m);

			return true;
		}
	}

	// get process id
	static ULONG getProcessId(const char* process_name) {
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.reqProcessId = TRUE;
		m.moduleName = process_name;

		callHook(&m);

		return m.pid;
	}

	// get base address of an image
	static ULONG64 getBaseAddress(const char* moduleName)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.reqBaseAddress = TRUE;
		m.moduleName = moduleName;

		callHook(&m);
		
		imageSize = m.imageSize;

		return m.baseAddress;
	}

	// change protection of a memory region
	static bool virtualProtect(uint64_t address, uint32_t protection, std::size_t size, uint32_t &old_protection)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.address = address;
		m.protection = protection;
		m.size = size;
		m.virtualProtect = TRUE;

		callHook(&m);

		old_protection = m.oldProtection;

		return true;
	}

	// allocate memory region
	static bool virtualAlloc(uint64_t& address, std::size_t size, uint32_t allocation_type, uint32_t protection)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.address = address;
		m.size = size;
		m.allocationType = allocation_type;
		m.protection = protection;
		m.virtualAlloc = TRUE;

		callHook(&m);

		address = m.address;

		return true;
	}

	// free memory
	static bool virtualFree(UINT_PTR address, uint32_t free_type)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.address = address;
		m.freeType = free_type;
		m.virtualFree = TRUE;

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

	// read from memory to buffer
	static bool readBuffer(UINT_PTR address, void* buffer, SIZE_T size)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.readBuffer = TRUE;
		m.address = address;
		m.bufferAddress = buffer;
		m.size = size;

		callHook(&m);
		
		return true;
	}

	// write to memory from buffer
	static bool writeBuffer(UINT_PTR address, void* buffer, SIZE_T size)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.writeBuffer = TRUE;
		m.address = address;
		m.bufferAddress = buffer;
		m.size = size;

		callHook(&m);

		return true;
	}

	// simulate mouse click
	static void click() {
		mouseEvent(MOUSE_LEFT_BUTTON_DOWN);
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		mouseEvent(MOUSE_LEFT_BUTTON_UP);
	}

	// simulate mouse hold
	static void hold() {
		mouseEvent(MOUSE_LEFT_BUTTON_DOWN);
	}

	// simulate mouse movement
	static void moveTo(long x, long y) {
		mouseEvent(MOUSE_MOVE_ABSOLUTE | MOUSE_VIRTUAL_DESKTOP, x, y);
	}

	// simulate key press
	static void keyPress(USHORT keyCode) {
		keyboardEvent(keyCode, KEY_MAKE);
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		keyboardEvent(keyCode, KEY_BREAK);
	}

	// pattern scan
	uintptr_t patternScan(char* pattern, char* mask) {
		uintptr_t start = baseAddress;
		uintptr_t end = start + imageSize;

		uintptr_t currentChunk = start;
		const SIZE_T chunkSize = 4096;

		while (currentChunk < end)
		{
			byte buffer[chunkSize];
			readBuffer(currentChunk, buffer, chunkSize);

			uintptr_t InternalAddress = compare((char*)&buffer, chunkSize, pattern, mask);

			if (InternalAddress != 0)
			{
				uintptr_t offsetFromBuffer = InternalAddress - (uintptr_t)&buffer;
				return currentChunk + offsetFromBuffer;
			}
			else
			{
				currentChunk = currentChunk + chunkSize;
			}
		}

		return 0;
	}

	// get window handle
	HWND getHwnd(DWORD proc_id) {
		HWND curHwnd = NULL;
		do
		{
			curHwnd = FindWindowEx(NULL, curHwnd, NULL, NULL);
			DWORD dwProcID = 0;
			GetWindowThreadProcessId(curHwnd, &dwProcID);
			if (dwProcID == proc_id) {
				return curHwnd;
			}
		} while (curHwnd != NULL);

		return NULL;
	}
}