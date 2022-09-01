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
	
	for (;;);

	return 0;
}