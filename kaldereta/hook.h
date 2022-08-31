#pragma once
#include "memory.h"

namespace hook
{
	bool callKernelFunc(void* kernelFunctionAddress);
	NTSTATUS hookHandler(PVOID calledParam);
}