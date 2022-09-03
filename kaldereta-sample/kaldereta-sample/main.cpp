#include <Windows.h>
#include <iostream>
#include "kaldereta.h"

int main() {
	printf("[-] Kalderate User-Mode Sample\n");

	std::string PROCESS_NAME = "test-app-x64.exe";

	printf("[-] Waiting for %s\n", PROCESS_NAME.c_str());

	while (!kdt::procID) {
		kdt::procID = kdt::getProcessId(PROCESS_NAME.c_str());
		Sleep(10);
	}

	Sleep(2000);

	printf("[-] Found %s\n", PROCESS_NAME.c_str());

	kdt::baseAddress = kdt::getBaseAddress(PROCESS_NAME.c_str());
	
	printf("[-] Process ID: %d\n", kdt::procID);
	printf("[-] Base Address: %012X\n", kdt::baseAddress);
	printf("[-] Image Size: %012X\n", kdt::imageSize);
	
	/*uint32_t old_protection;
	kdt::virtualProtect(0x4E36CFE020, PAGE_READWRITE, 0x40, old_protection);
	std::cout << old_protection << std::endl;*/

	// kdt::virtualAlloc
	// Note: address parameter could be IN or OUT
	/*uint64_t allocation_base = NULL;
	kdt::virtualAlloc(allocation_base, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	printf("[-] Allocation Base: %012X\n", allocation_base);*/

	/*kdt::virtualFree(allocation_base, MEM_RELEASE);*/

	/*char buffer[MAX_PATH];
	kdt::readBuffer(0xA38F5E6C0, buffer, MAX_PATH);
	std::cout << buffer << std::endl;*/

	/*char newBuffer[11];
	sprintf(newBuffer, "New String");
	kdt::writeBuffer(0xA38F5E6C0, newBuffer, 11);*/

	//kdt::click();

	//kdt::keyPress(0x41);

	//kdt::moveTo(500, 500);

	//x64 "C:\\Users\\steph\\Documents\\projects\\others\\ManualMap\\x64\\Release\\SampleDll.dll"

	if (!kdt::manualMap("C:\\Users\\steph\\Documents\\projects\\others\\ManualMap\\x64\\Release\\SampleDll.dll")) {
		printf("[-] Manual Map Failed");
	}

	for (;;);

	return 0;
}