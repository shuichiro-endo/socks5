@ECHO OFF

C:\socks5\server\socks5server.exe /RegServer

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\socks5server.exe" /s
reg query "HKEY_CLASSES_ROOT\AppID\socks5server.exe" /s

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{b1da36cc-d4e7-4f47-b7f8-8ee763fdc7e5}" /s
reg query "HKEY_CLASSES_ROOT\AppID\{b1da36cc-d4e7-4f47-b7f8-8ee763fdc7e5}" /s

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{70d2c8cf-f464-414a-84be-95fecc01c132}" /s
reg query "HKEY_CLASSES_ROOT\CLSID\{70d2c8cf-f464-414a-84be-95fecc01c132}" /s

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\AppID\socks5server.exe" /s
reg query "HKEY_CLASSES_ROOT\WOW6432Node\AppID\socks5server.exe" /s

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\AppID\{b1da36cc-d4e7-4f47-b7f8-8ee763fdc7e5}" /s
reg query "HKEY_CLASSES_ROOT\WOW6432Node\AppID\{b1da36cc-d4e7-4f47-b7f8-8ee763fdc7e5}" /s

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Socks5.Socks5Server.1" /s
reg query "HKEY_CLASSES_ROOT\Socks5.Socks5Server.1" /s

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\AppID\socks5server.exe" /s

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\AppID\{b1da36cc-d4e7-4f47-b7f8-8ee763fdc7e5}" /s

