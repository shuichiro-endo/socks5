@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DWIN32 /D_WIN32 client.cpp socks5server_i.c kernel32.lib user32.lib advapi32.lib rpcrt4.lib ole32.lib oleaut32.lib ws2_32.lib /link /OUT:client.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

del *.obj

