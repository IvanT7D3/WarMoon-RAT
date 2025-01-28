# WarMoon
WarMoon is an open-source RAT, with a few custom functionalities for both 64/32-bit Windows systems.

![Server-Image](https://github.com/IvanT7D3/WarMoon/blob/5d1aeaef5ea907dddfb6af3ff408900f74efa49c/img.png)

# Requirements

1. Install mingw-w64
```bash
sudo apt install mingw-w64
```

2. Clone the repository:
```bash
git clone https://github.com/IvanT7D3/WarMoon
```

## Versions
There are 2 versions of the Client software. 64 and 32 bit.

If you are compiling for a 64-bit system, go read the README file in the x64 folder for more info.

If you are compiling for a 32-bit system, go read the README file in the x86 folder for more info.

## Capabilities
- [x] Execute commands
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
- [ ] SSL/TLS
- [ ] Hidden VNC

Things that can be added to improve the whole project:

Add more functionalities.

Fix bugs.

## Demo
Here's a link if you want to watch a [Demo](https://www.youtube.com/watch?v=nErq4wlsF1g)

## License
This project can be freely modified and shared. Just don't damage systems, without having explicit permission from the owner of such systems.

## Credits
This project wouldn't have been possible without the many open-source projects that are already out there, and from which I took inspiration!

## Disclaimer
This project was created with the only purpose of learning.

Feel free to understand how it works, modify and play around with it.

This software should only be used on machines that you have explicit permission to attack. You are solely responsible for what you do with this code.

## Known Bugs
This section is one of the many reasons why you shouldn't use this, except for learning, playing around, and testing purposes on virtual machines.

This section tries to keep track of known bugs that were discovered.
I tried to fix as many as I could. If you find other bugs, feel free to let me know.

- If you use the server main shell to open a file that is greater than 18384 bytes in size, the client will crash. This can be avoided by increasing the size of the buffers, but I doubt that's the best solution.

- If you use wipembr on a Windows 7 machine, the client will crash (The MBR will still be wiped). The crash doesn't seem to happen on Windows 10 machines.

This project was tested mainly on Windows 7 Ultimate and Windows 10. If you have found any other bug and would like to report it, feel free to email me at: ituser905649056(at)protonmail.com
