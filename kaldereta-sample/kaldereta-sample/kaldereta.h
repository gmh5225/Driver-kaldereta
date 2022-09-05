#pragma once

#include <Windows.h>
#include <string>
#include <memory>
#include <thread>
#include <system_error>
#include <TlHelp32.h>
#include <wow64apiset.h>
#include "kalderata_defs.h"

namespace kdt {
	static std::uint32_t procID;
	static ULONGLONG imageSize;
	static std::uintptr_t baseAddress;
	static HWND windowHandle;
	
	// hook win function to communicate with driver
	template<typename ... A>
	uint64_t callHook(const A ... args)
	{
		LoadLibrary("user32.dll");
		void* controlFunction = (void*)GetProcAddress(LoadLibrary("win32u.dll"), "NtTokenManagerGetAnalogExclusiveTokenEvent");
		const auto control = static_cast<uint64_t(__stdcall*)(A...)>(controlFunction);
		return control(args ...);
	}

	namespace {
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

		DWORD __stdcall LibraryLoader64(LPVOID Memory)
		{
			loaderdata* LoaderParams = (loaderdata*)Memory;

			PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;

			std::ptrdiff_t delta = (std::ptrdiff_t)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

			while (pIBR->VirtualAddress)
			{
				if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
				{
					int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					std::ptrdiff_t* list = (std::ptrdiff_t*)(pIBR + 1);

					for (int i = 0; i < count; i++)
					{
						if (list[i])
						{
							std::ptrdiff_t* ptr = (std::ptrdiff_t*)((LPBYTE)LoaderParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
							*ptr += delta;
						}
					}
				}

				pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
			}

			PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;

			// Resolve DLL imports
			while (pIID->Characteristics)
			{
				PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk);
				PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk);

				HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + pIID->Name);

				if (!hModule)
					return FALSE;

				while (OrigFirstThunk->u1.AddressOfData)
				{
					if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					{
						// Import by ordinal
						ULONGLONG Function = (ULONGLONG)LoaderParams->fnGetProcAddress(hModule,
							(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

						if (!Function)
							return FALSE;

						FirstThunk->u1.Function = Function;
					}
					else
					{
						// Import by name
						PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
						ULONGLONG Function = (ULONGLONG)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
						if (!Function)
							return FALSE;

						FirstThunk->u1.Function = Function;
					}
					OrigFirstThunk++;
					FirstThunk++;
				}
				pIID++;
			}

			if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
			{
				dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

				return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
			}
			return TRUE;
		}

		DWORD __stdcall LibraryLoader86(LPVOID Memory)
		{

			loaderdata* LoaderParams = (loaderdata*)Memory;

			PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;

			DWORD delta = (DWORD)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

			while (pIBR->VirtualAddress)
			{
				if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
				{
					int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					PWORD list = (PWORD)(pIBR + 1);

					for (int i = 0; i < count; i++)
					{
						if (list[i])
						{
							PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
							*ptr += delta;
						}
					}
				}

				pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
			}

			PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;

			// Resolve DLL imports
			while (pIID->Characteristics)
			{
				PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk);
				PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk);

				HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + pIID->Name);

				if (!hModule)
					return FALSE;

				while (OrigFirstThunk->u1.AddressOfData)
				{
					if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					{
						// Import by ordinal
						DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule,
							(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

						if (!Function)
							return FALSE;

						FirstThunk->u1.Function = Function;
					}
					else
					{
						// Import by name
						PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
						DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
						if (!Function)
							return FALSE;

						FirstThunk->u1.Function = Function;
					}
					OrigFirstThunk++;
					FirstThunk++;
				}
				pIID++;
			}

			if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
			{
				dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

				return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
			}
			return TRUE;
		}

		DWORD __stdcall stub() {
			return 0;
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
	T read(UINT_PTR dwAddress, char* Offset, BOOL isAddress = false)
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
	bool write(UINT_PTR dwAddress, char* Offset, T Value)
	{
		return write<T>(read<T>(dwAddress, Offset, false), Value);
	}

	// read from memory to buffer
	static bool readBuffer(UINT_PTR address, void* buffer, SIZE_T size)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.address = address;
		m.bufferAddress = buffer;
		m.size = size;
		m.readBuffer = TRUE;

		callHook(&m);
		
		return true;
	}

	// write to memory from buffer
	static bool writeBuffer(UINT_PTR address, void* buffer, SIZE_T size)
	{
		KALDERETA_MEMORY m = { 0 };

		m.pid = procID;
		m.address = address;
		m.bufferAddress = buffer;
		m.size = size;
		m.writeBuffer = TRUE;

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

	// manual map an image file
	bool manualMap(const char* dllPath) {
		loaderdata LoaderParams;

		BOOL is64 = FALSE;

		HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		IsWow64Process(hFile, &is64);

		std::cout << is64 << std::endl;

		DWORD FileSize = GetFileSize(hFile, NULL);
		PVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		ReadFile(hFile, FileBuffer, FileSize, NULL, NULL);

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, kdt::procID);

		uint64_t ExecutableImageTemp = NULL;
		kdt::virtualAlloc(ExecutableImageTemp, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		PVOID ExecutableImage = (PVOID)ExecutableImageTemp;

		kdt::writeBuffer(ExecutableImageTemp, FileBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);

		PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);

		for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
		{
			kdt::writeBuffer((UINT_PTR)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress),
				(PVOID)((LPBYTE)FileBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData);
		}

		uint64_t LoaderMemoryTemp = NULL;
		kdt::virtualAlloc(LoaderMemoryTemp, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		PVOID LoaderMemory = (PVOID)LoaderMemoryTemp;

		LoaderParams.ImageBase = ExecutableImage;
		LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);
		LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		LoaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		LoaderParams.fnLoadLibraryA = LoadLibraryA;
		LoaderParams.fnGetProcAddress = GetProcAddress;

		kdt::writeBuffer(LoaderMemoryTemp, &LoaderParams, sizeof(loaderdata));
		kdt::writeBuffer((UINT_PTR)((loaderdata*)LoaderMemory + 1), LibraryLoader86, (DWORD)stub - (DWORD)LibraryLoader86);

		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1), LoaderMemory, 0, NULL);

		printf("[-] Loader Address: %012X\n", LoaderMemory);
		printf("[-] Image Address: %012X\n", ExecutableImage);

		WaitForSingleObject(hThread, 30000);

		kdt::virtualFree((UINT_PTR)LoaderMemory, MEM_RELEASE);

		return true;
	}
}