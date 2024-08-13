@ECHO OFF

midl socks5server.idl

cl.exe /nologo /Ox /MT /W0 /GS- /DWIN32 /D_WIN32 /DREGISTER_PROXY_DLL /LD /Fesocks5server_proxy.dll socks5server_p.c socks5server_i.c dlldata.c kernel32.lib user32.lib advapi32.lib rpcrt4.lib ole32.lib oleaut32.lib socks5server_proxy.def

cl.exe /nologo /Ox /MT /W0 /GS- /DWIN32 /D_WIN32 socks5server.cpp socks5server_i.obj kernel32.lib user32.lib advapi32.lib rpcrt4.lib ole32.lib oleaut32.lib ws2_32.lib /link /OUT:socks5server.exe /SUBSYSTEM:WINDOWS /MACHINE:x64

rem del *.obj

