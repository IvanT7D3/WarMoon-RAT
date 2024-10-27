#include <stdio.h>

//Paste here the shellcodes to encrypt with the xor key

//...

unsigned char EncryptedShellcode1[sizeof(ShellcodeSpawnNetcat) + 4];
unsigned char EncryptedShellcode2[sizeof(FallBackShell) + 4];

int i = 0;
int j = 0;
char XORKey = 'P';

int main()
{
	printf("unsigned char ShellcodeSpawnNetcat[] =\n");
	printf("\"");
	for (i; i < sizeof(ShellcodeSpawnNetcat) - 1; i++)
	{
		printf("\\x%02x", EncryptedShellcode1[i] = ShellcodeSpawnNetcat[i] ^ XORKey);
	}
	printf("\";");

	printf("\n\nunsigned char FallBackShell[] =\n");
	printf("\"");
	for (j; j < sizeof(FallBackShell) - 1; j++)
	{
		printf("\\x%02x", EncryptedShellcode2[j] = FallBackShell[j] ^ XORKey);
	}
	printf("\";");
	return 0;
}
