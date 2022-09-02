#include <Windows.h>
#include <iostream>
#include "kaldereta.h"

int main() {
	printf("[-] Kalderate User-Mode Sample\n");

	std::string PROCESS_NAME = "test-app-x64.exe";

	kdt::procID = kdt::getProcID(PROCESS_NAME);

	printf("[-] Waiting for %s\n", PROCESS_NAME.c_str());

	while (!kdt::procID) {}

	printf("[-] Found %s\n", PROCESS_NAME.c_str());

	kdt::baseAddress = kdt::getBaseAddress(PROCESS_NAME.c_str());
	
	printf("[+] Base Address: %012X\n", kdt::baseAddress);
	printf("[+] Image Size: %012X\n", kdt::imageSize);
	
	/*kdt::virtualProtect(0xA38F5E6C0, PAGE_READWRITE, 0x40);*/

	/*kdt::allocateMemory(0x50, PAGE_READWRITE);*/

	/*char buffer[MAX_PATH];
	kdt::readString(0xA38F5E6C0, buffer, MAX_PATH);
	std::cout << buffer << std::endl;*/

	/*char newBuffer[11];
	sprintf(newBuffer, "New String");
	kdt::writeString(0xA38F5E6C0, newBuffer, 11);*/

	//kdt::click();

	kdt::moveTo(500, 500);

	for (;;);

	return 0;
}