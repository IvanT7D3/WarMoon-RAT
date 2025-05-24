#!/bin/bash

COff='\033[0m'
Error='\e[93m'
Success='\033[1;92m'

if [ -z "$1" ]; then
	echo -e "${Error}ERROR!${COff}"
	echo -e "${Error}You must give an argument : 'install' OR 'cert' OR 'compile' ${COff}"
	echo ""
	echo -e "${Error}install : Sets up OpenSSL and makes everything ready for static compilation${COff}"
	echo -e "${Error}! WARNING ! : The default installation directory will depend from the user that you are currently using. Specifically, it will use its \$HOME environment variable... This means that if you later try to use 'compile' using a user that doesn't have permission to access the folders where the folders of OpenSSL have been set up the first time, you will receive errors during compilation. Stick to 1 user only which will be used to execute everything inside of this project, or change the folder's owner using chown ${COff}"
	echo ""
	echo -e "${Error}cert : Generate a new key-pair${COff}"
	echo -e "${Error}You will then have to copy the contents of public.crt inside of the respective variable in the Client.c file"
	echo ""
	echo -e "${Error}compile : Compiles server and client (both versions)${COff}"
	exit 0
fi

if [ "$1" == "install" ]; then
	if dpkg -s "libssl-dev" &> /dev/null; then
		echo -e "${Success}libssl-dev is installed. Proceeding...${COff}"
	else
		echo -e "${Error}libssl-dev is NOT installed. Installing...${COff}"
		apt-get install libssl-dev -y
	fi

	echo -e "${Success}Starting...${COff}"

	if [ -d "$HOME/OpenSSL-Windows-Static-x64" ]; then
		echo -e "${Error}'$HOME/OpenSSL-Windows-Static-x64' (x64) already exists. You have (most likely) already executed the 'install' command. If for some reason you interrupted the installation process, remove everything that was installed, and try again!${COff}"
		exit 1
	fi

	if [ -d "$HOME/OpenSSL-Windows-Static-x86" ]; then
		echo -e "${Error}'$HOME/OpenSSL-Windows-Static-x86' (x86) already exists. You have (most likely) already executed the 'install' command. If for some reason you interrupted the installation process, remove everything that was installed, and try again!${COff}"
		exit 1
	fi

	echo -e "${Success}Compilation will use all available cores. Avoid stressing the machine${COff}"

	wget https://www.openssl.org/source/openssl-3.0.12.tar.gz
	tar -xvzf openssl-3.0.12.tar.gz
	rm openssl-3.0.12.tar.gz
	mkdir build-x64 && cd build-x64
	../openssl-3.0.12/Configure mingw64 no-shared --cross-compile-prefix=x86_64-w64-mingw32-
	make -j$(nproc)
	make install DESTDIR=$HOME/OpenSSL-Windows-Static-x64

	if [ -d "$HOME/OpenSSL-Windows-Static-x64" ]; then
		echo -e "${Success}'$HOME/OpenSSL-Windows-Static-x64' created.${COff}"
	fi

	echo -e "${Success}x64 Successful. Doing x86...${COff}"
	cd ..

	mkdir build-x86 && cd build-x86
	../openssl-3.0.12/Configure mingw no-shared --cross-compile-prefix=i686-w64-mingw32-
	make -j$(nproc)
	make install DESTDIR=$HOME/OpenSSL-Windows-Static-x86

	if [ -d "$HOME/OpenSSL-Windows-Static-x64" ]; then
		echo -e "${Success}'$HOME/OpenSSL-Windows-Static-x86' created.${COff}"
	fi

	echo -e "${Success}x86 Successful.${COff}"
	cd ..

	echo -e "${Success}Installation was successful!${COff}"
	exit 0

elif [ "$1" == "cert" ]; then
	openssl req -x509 -newkey rsa:4096 -keyout private.key -out public.crt -days 365 -nodes <<EOF







EOF
	echo ""
	echo -e "${Success}Generated. Remember to correctly copy the contents of public.crt inside of the variable 'ServerPublicCertPem' in the Client.c file.${COff}"
	exit 0

elif [ "$1" == "compile" ]; then
	echo -e "${Success}Verifying if I can compile...${COff}"

	if dpkg -s "libssl-dev" &> /dev/null; then
		echo -e "${Success}libssl-dev is installed. Proceeding...${COff}"
	else
		echo -e "${Error}libssl-dev is NOT installed. Installing...${COff}"
		apt-get install libssl-dev -y
	fi

	if [ ! -d "$HOME/OpenSSL-Windows-Static-x64" ]; then
		echo -e "${Error}The folder '$HOME/OpenSSL-Windows-Static-x64' doesn't exist!${COff}"
		exit 1
	fi

	if [ ! -d "$HOME/OpenSSL-Windows-Static-x86" ]; then
		echo -e "${Error}The folder '$HOME/OpenSSL-Windows-Static-x86' doesn't exist!${COff}"
		exit 1
	fi

	if ! command -v x86_64-w64-mingw32-gcc 2>&1 > /dev/null ; then
		echo -e "${Error}'x86_64-w64-mingw32-gcc' not found. Can't compile!${COff}"
		exit 1
	fi

	if ! command -v i686-w64-mingw32-gcc 2>&1 > /dev/null ; then
		echo -e "${Error}'i686-w64-mingw32-gcc' not found. Can't compile!${COff}"
		exit 1
	fi

	echo -e "${Success}OK ... Compiling x64 version.${COff}"

	x86_64-w64-mingw32-gcc -o Client-x64.exe x64/Client.c -Wl,--no-insert-timestamp -I$HOME/OpenSSL-Windows-Static-x64/usr/local/include -L$HOME/OpenSSL-Windows-Static-x64/usr/local/lib64 -lssl -lcrypto -lws2_32 -lcrypt32 -lwininet -lgdi32 -lntdll -static && gcc x64/Server.c -o ./Server-x64 -lssl -lcrypto

	echo -e "${Success}OK ... Compiling x86 version.${COff}"

	i686-w64-mingw32-gcc -o Client-x86.exe x86/Client.c -Wl,--no-insert-timestamp -I$HOME/OpenSSL-Windows-Static-x86/usr/local/include -L$HOME/OpenSSL-Windows-Static-x86/usr/local/lib -lssl -lcrypto -lws2_32 -lcrypt32 -lwininet -lgdi32 -lntdll -static && gcc x86/Server.c -o ./Server-x86 -lssl -lcrypto

	echo -e "${Success}Done.${COff}"

	echo ""
	echo -e "${Success}If for some reason you got an error like: $HOME/OpenSSL-Windows-Static-x86/usr/local/lib/libssl.a: error adding symbols: archive has no index; run ranlib to add one\n collect2: error: ld returned 1 exit status ${COff}"
	echo ""
	echo -e "${Success}Run these commands below and try again:${COff}"
	echo -e "${Success}ranlib $HOME/OpenSSL-Windows-Static-x86/usr/local/lib/libssl.a${COff}"
	echo -e "${Success}ranlib $HOME/OpenSSL-Windows-Static-x86/usr/local/lib/libcrypto.a${COff}"
	exit 0

else
	echo -e "${Error}Invalid argument. Use : 'install' OR 'cert' OR 'compile'${COff}"
	exit 1
fi
