@ECHO OFF

midl socks5server.idl

cl.exe /nologo /Ox /MT /W0 /GS- /DWIN32 /D_WIN32 socks5server.cpp socks5server_s.c /link kernel32.lib user32.lib advapi32.lib rpcrt4.lib ws2_32.lib /OUT:socks5server.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

cl.exe /nologo /Ox /MT /W0 /GS- /DWIN32 /D_WIN32 client.cpp socks5server_c.c /link kernel32.lib user32.lib advapi32.lib rpcrt4.lib ws2_32.lib /OUT:client.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

rem del *.obj

