// UserApp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Windows.h>
#include <stdio.h>


int main()
{
    __debugbreak();//DebugBreak();

    HANDLE HDevice = CreateFile(L"\\\\.\\VerifyUserAppSignature",
                                GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL,
                                OPEN_EXISTING,
                                0,
                                NULL);
    if (HDevice == INVALID_HANDLE_VALUE) {

        return GetLastError();
    }

    (void)getchar();

    CloseHandle(HDevice);

    return GetLastError();
}
