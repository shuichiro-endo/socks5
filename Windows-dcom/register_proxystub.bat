@ECHO OFF

regsvr32.exe C:\socks5\server\socks5server_proxy.dll

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{1FDF77BA-5E52-4721-BE81-A3030E8C30E4}" /s
reg query "HKEY_CLASSES_ROOT\CLSID\{1FDF77BA-5E52-4721-BE81-A3030E8C30E4}" /s

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{1FDF77BA-5E52-4721-BE81-A3030E8C30E4}" /s
reg query "HKEY_CLASSES_ROOT\Interface\{1FDF77BA-5E52-4721-BE81-A3030E8C30E4}" /s
