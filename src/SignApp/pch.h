/*

winnt.h和ntstatus.h冲突：有重复的定义。
解决思路：先包含ntstatus.h，再定义WIN32_NO_STATUS，最后包含winnt.h。
*/

#pragma once

#include <ntstatus.h>

//#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WIN32_DCOM
#define STRICT
#define WIN32_NO_STATUS

#pragma warning(disable:28251)

// Windows 头文件
#include <Winsock2.h>
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <crtdbg.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <fltuser.h>
#include <locale.h>
#include <Lmserver.h>
#include <stdarg.h>
#include <wincrypt.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <aclapi.h>
#include <VersionHelpers.h>
#include <ShlDisp.h>
#include <Shlobj.h>
#include <Softpub.h>
#include <mscat.h>
//#include <SubAuth.h>
//#include <LsaLookup.h>
#include <WinUser.h>
#include <direct.h>
#include <sddl.h>
#include <ws2tcpip.h>
#include <fwpsu.h>
#include <atlbase.h>
#include <mbnapi.h>
#include <iostream>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <atlconv.h>
#define _WS2DEF_
#include <mstcpip.h>
#include <Intshcut.h>
#include <winternl.h>
//#include <SubAuth.h>
//#include <NTSecAPI.h>
//#include <netioapi.h>
#include <atlstr.h>
#include <comutil.h>
#include <dbt.h>
#include <comdef.h>
#include <winnls.h>
#include <shobjidl.h>
#include <objidl.h>
#include <shlguid.h>
#include <accctrl.h>
#include <azroles.h>
#include <winefs.h>
#include <shellapi.h>
#include <cryptuiapi.h>
#include <conio.h>
#include <signal.h>
#include <urlmon.h>
#include <certenroll.h>

//几个USB相关的头文件。
#include <initguid.h> //注意前后顺序。
#include <usbioctl.h>
#include <usbiodef.h>
//#include <usbctypes.h>
#include <intsafe.h>
#include <specstrings.h>
#include <usb.h>
#include <usbuser.h>

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Version.lib") 
//#pragma comment (lib,"Url.lib")
//#pragma comment(lib, "cmcfg32.lib")
//#pragma comment(lib, "duser.lib")
#pragma comment (lib, "cryptui.lib")
#pragma comment(lib, "Scarddlg.lib")

#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

#include <imagehlp.h>//和DbgHelp.h有重复的定义。
#pragma comment(lib, "imagehlp.lib")

#include <winscard.h>
#pragma comment(lib, "Winscard.lib")

#include <clusapi.h>
#pragma comment(lib, "ClusAPI.lib")

#include <authz.h>
#pragma comment (lib, "authz.lib")

#include <bcrypt.h>
#pragma comment (lib, "Bcrypt.lib")

#include <ncrypt.h>
#pragma comment (lib, "Ncrypt.lib")

#include <wintrust.h>
#pragma comment (lib, "wintrust.lib")

#include <Setupapi.h>
#pragma comment (lib,"Setupapi.lib")

#include <Shlwapi.h>
#pragma comment (lib,"Shlwapi.lib")

//#include <DbgHelp.h>
#pragma comment (lib,"DbgHelp.lib")

#include <psapi.h>
#pragma comment(lib, "Psapi.lib")

#include <Sfc.h>
#pragma comment(lib, "Sfc.lib")

//#include <winsock.h>
#pragma comment(lib, "Ws2_32.lib")

#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#include <Wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

#include <Userenv.h>
#pragma comment(lib, "Userenv.lib")

#include <Sensapi.h>
#pragma comment (lib,"Sensapi.lib")

#include <Wininet.h>
#pragma comment (lib,"Wininet.lib")

#include <string>
#include <list>
#include <regex>
#include <map>
#include <set>
#include <iostream>

using namespace std;


class pch
{

};
