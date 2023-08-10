// SignApp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"


const wchar_t * SignatureFile = L"UserApp.sig";
const wchar_t * PrivateKeyFile = L"PrivateKey.bin";
const wchar_t * PublicKeyFile = L"PublicKey.bin";
const wchar_t * UserAppFile = L"UserApp.exe";

WCHAR g_ExePath[MAX_PATH]{};
WCHAR g_SignatureFileFullPath[MAX_PATH]{};
WCHAR g_PrivateKeyFileFullPath[MAX_PATH]{};
WCHAR g_PublicKeyFileFullPath[MAX_PATH]{};
WCHAR g_UserAppFileFullPath[MAX_PATH]{};


BOOL WINAPI CngHashData(_In_z_ LPCWSTR pszAlgId,
                        _In_reads_bytes_(DataSize) PUCHAR Data,
                        _In_ ULONG DataSize,
                        _Out_writes_bytes_all_(*HashSize) PUCHAR * Hash,
                        _In_ ULONG * HashSize
)
/*++

Hash需要由调用者调用HeapFree释放。

https://docs.microsoft.com/zh-cn/windows/win32/seccng/creating-a-hash-with-cng
--*/
{
    BCRYPT_ALG_HANDLE       hAlg = NULL;
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbData = 0, cbHashObject = 0;
    PBYTE                   pbHashObject = NULL;
    BOOL                    ret = FALSE;

    //open an algorithm handle
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg,
                                               BCRYPT_OBJECT_LENGTH,
                                               (PBYTE)&cbHashObject,
                                               sizeof(DWORD),
                                               &cbData,
                                               0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the length of the hash
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg,
                                               BCRYPT_HASH_LENGTH,
                                               (PBYTE)HashSize,
                                               sizeof(DWORD),
                                               &cbData,
                                               0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    *Hash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *HashSize);
    if (NULL == *Hash) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }


    //hash some data
    if (!NT_SUCCESS(status = BCryptHashData(hHash, Data, DataSize, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
        goto Cleanup;
    }

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, *Hash, *HashSize, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

    ret = TRUE;

Cleanup:

    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (hHash) {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject) {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }

    //if (*Hash) {
    //    HeapFree(GetProcessHeap(), 0, *Hash);
    //}

    return ret;
}


void WINAPI EcdsaSignHash(_In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                          _In_ ULONG PrivateKeyLen,
                          _In_reads_bytes_(DataSize) PUCHAR Data,
                          _In_ ULONG DataSize,
                          _Out_writes_bytes_all_(*SignSize) PUCHAR * Sign,
                          _In_ ULONG * SignSize
)
{
    PUCHAR Hash = nullptr;
    ULONG HashSize = 0;
    BOOL ret = CngHashData(BCRYPT_SHA512_ALGORITHM, Data, DataSize, &Hash, &HashSize);

    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE       hSignAlg = NULL;
    status = BCryptOpenAlgorithmProvider(&hSignAlg, BCRYPT_ECDSA_P521_ALGORITHM, NULL, 0);
    _ASSERTE(NT_SUCCESS(status));

    BCRYPT_KEY_HANDLE hPrivateKey = NULL;
    status = BCryptImportKeyPair(hSignAlg,
                                 NULL,
                                 BCRYPT_ECCPRIVATE_BLOB,
                                 &hPrivateKey,
                                 PrivateKey,
                                 PrivateKeyLen,
                                 BCRYPT_NO_KEY_VALIDATION);
    _ASSERTE(NT_SUCCESS(status));

    status = BCryptSignHash(hPrivateKey, NULL, Hash, HashSize, NULL, 0, SignSize, 0);
    _ASSERTE(NT_SUCCESS(status));

    *Sign = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *SignSize);
    _ASSERTE(*Sign);

    ULONG Result = 0;
    status = BCryptSignHash(hPrivateKey, NULL, Hash, HashSize, *Sign, *SignSize, &Result, 0);
    _ASSERTE(NT_SUCCESS(status));

    BCryptCloseAlgorithmProvider(hSignAlg, 0);
    BCryptDestroyKey(hPrivateKey);
}


void GetExePath(_Out_writes_(cchDest) STRSAFE_LPWSTR pszDest, _In_ size_t cchDest)
/*
获取安装路径的方式一。
*/
{
    TCHAR szPath[MAX_PATH] = {0};

    DWORD x = GetModuleFileName(NULL, szPath, MAX_PATH);

    TCHAR * module = PathFindFileName(szPath);

    int n = lstrlen(szPath) - lstrlen(module);

    szPath[n] = 0;

    StringCchCopy(pszDest, cchDest, szPath);
}


void CreateKeyFile(_In_ LPCWSTR KeyFileFullPath,
                   _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
                   _In_ DWORD nNumberOfBytesToWrite
)
{
    HANDLE hFile = CreateFile(KeyFileFullPath,
                              FILE_READ_DATA | FILE_WRITE_DATA,
                              FILE_SHARE_READ,
                              NULL,
                              CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    _ASSERTE(hFile != INVALID_HANDLE_VALUE);

    DWORD nBytesRead = 0;
    BOOL bResult = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &nBytesRead, NULL);
    if (bResult == 0) {
        printf("WriteFile LastError:%d", GetLastError());
    }

    CloseHandle(hFile);
}


void CreateKey()
{
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    LPCWSTR AlgId = BCRYPT_ECDSA_P521_ALGORITHM;
    LPCWSTR Implementation = nullptr;
    ULONG   Flags = 0;
    NTSTATUS NtStatus = BCryptOpenAlgorithmProvider(&hAlgorithm, AlgId, Implementation, Flags);
    if (STATUS_SUCCESS != NtStatus) {

        return;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    ULONG   Length = 521;
    NtStatus = BCryptGenerateKeyPair(hAlgorithm, &hKey, Length, 0);
    if (STATUS_SUCCESS != NtStatus) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return;
    }

    //NtStatus = BCryptSetProperty

    NtStatus = BCryptFinalizeKeyPair(hKey, 0);//这个还是很费时的。
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PrivateKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &PrivateKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    PBCRYPT_ECCKEY_BLOB PrivateKey = (PBCRYPT_ECCKEY_BLOB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PrivateKeyLen);
    _ASSERTE(PrivateKey);

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, (PUCHAR)PrivateKey, PrivateKeyLen, &PrivateKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    CreateKeyFile(g_PrivateKeyFileFullPath, PrivateKey, PrivateKeyLen);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PublicKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &PublicKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    PBCRYPT_ECCKEY_BLOB PublicKey = (PBCRYPT_ECCKEY_BLOB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PublicKeyLen);
    _ASSERTE(PublicKey);

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, (PUCHAR)PublicKey, PublicKeyLen, &PublicKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    CreateKeyFile(g_PublicKeyFileFullPath, PublicKey, PublicKeyLen);

    //////////////////////////////////////////////////////////////////////////////////////////////

    HeapFree(GetProcessHeap(), 0, PublicKey);
    HeapFree(GetProcessHeap(), 0, PrivateKey);

    NtStatus = BCryptDestroyKey(hKey);
    NtStatus = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
}


void SignaFile()
{
    HANDLE hFile = CreateFile(g_UserAppFileFullPath,
                              FILE_READ_DATA | FILE_WRITE_DATA,
                              FILE_SHARE_READ,
                              NULL,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    _ASSERTE(hFile != INVALID_HANDLE_VALUE);

    DWORD DataSize = GetFileSize(hFile, NULL);
    PUCHAR Data = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DataSize);
    _ASSERTE(Data);

    DWORD cbRead = 0;
    BOOL bResult = ReadFile(hFile, Data, DataSize, &cbRead, NULL);
    _ASSERTE(bResult);

    //////////////////////////////////////////////////////////////////////////////////////////////

    HANDLE hPrivateKeyFile = CreateFile(g_PrivateKeyFileFullPath,
                                        FILE_READ_DATA | FILE_WRITE_DATA,
                                        FILE_SHARE_READ,
                                        NULL,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        NULL);
    _ASSERTE(hPrivateKeyFile != INVALID_HANDLE_VALUE);

    ULONG PrivateKeyLen = GetFileSize(hPrivateKeyFile, NULL);
    PUCHAR PrivateKey = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PrivateKeyLen);
    _ASSERTE(PrivateKey);

    bResult = ReadFile(hPrivateKeyFile, PrivateKey, PrivateKeyLen, &cbRead, NULL);
    _ASSERTE(bResult);

    //////////////////////////////////////////////////////////////////////////////////////////////

    PUCHAR Sign = nullptr;
    ULONG SignSize = 0;

    EcdsaSignHash(PrivateKey, PrivateKeyLen, Data, DataSize, &Sign, &SignSize);

    CreateKeyFile(g_SignatureFileFullPath, Sign, SignSize);

    //////////////////////////////////////////////////////////////////////////////////////////////

    HeapFree(GetProcessHeap(), 0, PrivateKey);
    HeapFree(GetProcessHeap(), 0, Sign);
    HeapFree(GetProcessHeap(), 0, Data);
    CloseHandle(hPrivateKeyFile);
    CloseHandle(hFile);
}


int main()
{
    GetExePath(g_ExePath, _ARRAYSIZE(g_ExePath) - 1);

    lstrcpy(g_SignatureFileFullPath, g_ExePath);
    PathAppend(g_SignatureFileFullPath, SignatureFile);

    lstrcpy(g_PrivateKeyFileFullPath, g_ExePath);
    PathAppend(g_PrivateKeyFileFullPath, PrivateKeyFile);

    lstrcpy(g_PublicKeyFileFullPath, g_ExePath);
    PathAppend(g_PublicKeyFileFullPath, PublicKeyFile);

    lstrcpy(g_UserAppFileFullPath, g_ExePath);
    PathAppend(g_UserAppFileFullPath, UserAppFile);

    assert(PathFileExists(g_UserAppFileFullPath));

    if (!PathFileExists(g_PrivateKeyFileFullPath) || !PathFileExists(g_PublicKeyFileFullPath)) {
        CreateKey();
    }

    SignaFile();

    return 0;
}
