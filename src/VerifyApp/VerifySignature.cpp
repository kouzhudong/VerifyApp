#include "VerifySignature.h"

const UNICODE_STRING g_SignatureFile = RTL_CONSTANT_STRING(L"\\UserApp.sig");
const UNICODE_STRING g_PublicKeyFile = RTL_CONSTANT_STRING(L"\\PublicKey.bin");
const UNICODE_STRING g_UserAppFile = RTL_CONSTANT_STRING(L"\\UserApp.exe");

#pragma warning(disable:4996) //'ExAllocatePoolWithTag': ExAllocatePoolWithTag is deprecated, use ExAllocatePool2.


VOID FreeUnicodeString(_In_ PUNICODE_STRING String)
/*++
Routine Description:
    This routine frees a unicode string
Arguments:
    String - supplies the string to be freed
--*/
{
    PAGED_CODE();

    if (String->Buffer) {
        ExFreePoolWithTag(String->Buffer, TAG);
        String->Buffer = NULL;
    }

    String->Length = String->MaximumLength = 0;
    String->Buffer = NULL;
}


BOOL WINAPI CngHashData(_In_z_ LPCWSTR pszAlgId,
                        _In_reads_bytes_(DataSize) PUCHAR Data,
                        _In_ ULONG DataSize,
                        _Out_writes_bytes_all_(*HashSize) PUCHAR * Hash,
                        _In_ ULONG * HashSize
)
/*++

Hash需要由调用者调用ExFreePoolWithTag释放。

https://docs.microsoft.com/zh-cn/windows/win32/seccng/creating-a-hash-with-cng
--*/
{
    BCRYPT_ALG_HANDLE       hAlg = NULL;
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                Status = STATUS_UNSUCCESSFUL;
    DWORD                   cbData = 0, cbHashObject = 0;
    PBYTE                   pbHashObject = NULL;
    BOOL                    ret = FALSE;

    __try {
    //open an algorithm handle
        if (!NT_SUCCESS(Status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //calculate the size of the buffer to hold the hash object
        if (!NT_SUCCESS(Status = BCryptGetProperty(hAlg,
                                                   BCRYPT_OBJECT_LENGTH,
                                                   (PBYTE)&cbHashObject,
                                                   sizeof(DWORD),
                                                   &cbData,
                                                   0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //allocate the hash object on the heap
        pbHashObject = (PBYTE)ExAllocatePoolWithTag(NonPagedPool, cbHashObject, TAG); 
        if (NULL == pbHashObject) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //calculate the length of the hash
        if (!NT_SUCCESS(Status = BCryptGetProperty(hAlg,
                                                   BCRYPT_HASH_LENGTH,
                                                   (PBYTE)HashSize,
                                                   sizeof(DWORD),
                                                   &cbData,
                                                   0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //allocate the hash buffer on the heap
        *Hash = (PBYTE)ExAllocatePoolWithTag(NonPagedPool,  *HashSize, TAG); 
        if (NULL == *Hash) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //create a hash
        if (!NT_SUCCESS(Status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }


        //hash some data
        if (!NT_SUCCESS(Status = BCryptHashData(hHash, Data, DataSize, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //close the hash
        if (!NT_SUCCESS(Status = BCryptFinishHash(hHash, *Hash, *HashSize, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        ret = TRUE;
    } __finally {
        if (hAlg) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }

        if (hHash) {
            BCryptDestroyHash(hHash);
        }

        if (pbHashObject) {
            ExFreePoolWithTag(pbHashObject, TAG);
        }

        //if (*Hash) {
        //    ExFreePoolWithTag(*Hash, TAG); 
        //}
    }

    return ret;
}


BOOL WINAPI EcdsaVerifySignature(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                                 _In_ ULONG PublicKeyLen,
                                 _In_reads_bytes_(DataSize) PUCHAR Data,
                                 _In_ ULONG DataSize,
                                 _Out_writes_bytes_all_(SignSize) PUCHAR Sign,
                                 _In_ ULONG SignSize
)
{
    PUCHAR Hash = nullptr;
    ULONG HashSize = 0;
    BOOL IsVerify = FALSE;
    BOOL ret = CngHashData(BCRYPT_SHA512_ALGORITHM, Data, DataSize, &Hash, &HashSize);
    ASSERT(ret);

    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE       hSignAlg = NULL;
    status = BCryptOpenAlgorithmProvider(&hSignAlg, BCRYPT_ECDSA_P521_ALGORITHM, NULL, 0);
    ASSERT(NT_SUCCESS(status));

    BCRYPT_KEY_HANDLE hPublicKey = NULL;
    status = BCryptImportKeyPair(hSignAlg,
                                 NULL,
                                 BCRYPT_ECCPUBLIC_BLOB,
                                 &hPublicKey,
                                 PublicKey,
                                 PublicKeyLen,
                                 BCRYPT_NO_KEY_VALIDATION);
    ASSERT(NT_SUCCESS(status));

    status = BCryptVerifySignature(hPublicKey, NULL, Hash, HashSize, Sign, SignSize, 0);
    if (NT_SUCCESS(status)) {
        IsVerify = TRUE;
    }

    BCryptCloseAlgorithmProvider(hSignAlg, 0);
    BCryptDestroyKey(hPublicKey);

    return IsVerify;
}


void ReadFile(_In_ PUNICODE_STRING FileName, _Out_writes_bytes_(*Length) PVOID * Buffer, _In_ PULONG Length)
/*

过滤驱动中可以使用Flt函数。
*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    HANDLE FileHandle;
    PFILE_OBJECT  FileObject = nullptr;

    InitializeObjectAttributes(&ObjectAttributes, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwOpenFile(&FileHandle,
                        FILE_READ_DATA | SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    ASSERT(NT_SUCCESS(Status));

    Status = ObReferenceObjectByHandle(FileHandle,
                                       FILE_READ_ACCESS | SYNCHRONIZE,
                                       *IoFileObjectType,
                                       KernelMode,
                                       (PVOID *)&FileObject,
                                       NULL);
    ASSERT(NT_SUCCESS(Status));

    LARGE_INTEGER FileSize{};
    Status = FsRtlGetFileSize(FileObject, &FileSize);
    ASSERT(NT_SUCCESS(Status));

    if (FileSize.QuadPart > 1024 * 1024 * 1024) {

        ObDereferenceObject(FileObject);
        ZwClose(FileHandle);
        return;
    }

    *Length = FileSize.LowPart;
    *Buffer = (PVOID)ExAllocatePoolZero(NonPagedPool, FileSize.QuadPart, TAG);
    ASSERT(*Buffer);    

    LARGE_INTEGER ByteOffset{};
    Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, *Buffer, *Length, &ByteOffset, NULL);
    ASSERT(NT_SUCCESS(Status) || STATUS_END_OF_FILE == Status);

    ObDereferenceObject(FileObject);
    ZwClose(FileHandle);
}


void GetFileName(_In_ PUNICODE_STRING ExeDir, _In_ PCUNICODE_STRING FileName, _In_ PUNICODE_STRING FullFileName)
{
    FullFileName->MaximumLength = ExeDir->Length + FileName->Length + sizeof(WCHAR) + sizeof(WCHAR);//一个斜杠和空格

    FullFileName->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, FullFileName->MaximumLength, TAG);
    ASSERT(FullFileName->Buffer);
    FullFileName->Length = 0;

    RtlCopyUnicodeString(FullFileName, ExeDir);
    RtlAppendUnicodeStringToString(FullFileName, FileName);
}


BOOL GetExeDir(_Inout_ PUNICODE_STRING ImagePathName)
/*

*/
{
    PEPROCESS    eprocess;
    NTSTATUS     Status = STATUS_SUCCESS;
    KAPC_STATE   ApcState;
    BOOL ret = FALSE;
    PUNICODE_STRING temp = NULL;

    PAGED_CODE();

    Status = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &eprocess);
    ASSERT(NT_SUCCESS(Status));

    KeStackAttachProcess(eprocess, &ApcState);

    Status = SeLocateProcessImageName(eprocess, &temp);
    if (NT_SUCCESS(Status)) {
        ImagePathName->MaximumLength = temp->MaximumLength;
        ImagePathName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, ImagePathName->MaximumLength, TAG);
        if (NULL == ImagePathName->Buffer) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
        } else {
            RtlZeroMemory(ImagePathName->Buffer, ImagePathName->MaximumLength);
            RtlCopyUnicodeString(ImagePathName, temp);

            for (USHORT i = ImagePathName->Length / sizeof(WCHAR) - 1; i > 0; i--) {
                if (ImagePathName->Buffer[i] == L'/' || ImagePathName->Buffer[i] == L'\\') {
                    ImagePathName->Buffer[i] = 0;
                    ImagePathName->Length = i * sizeof(WCHAR);
                    break;
                }
            }

            ret = TRUE;
        }

        ExFreePool(temp);
    }

    KeUnstackDetachProcess(&ApcState);

    ObDereferenceObject(eprocess);

    return ret;
}


bool VerifyUserAppSignature()
{
    bool IsVerify = false;    
    
    UNICODE_STRING ExeDir{};
    UNICODE_STRING UserAppFileFullPath{};
    UNICODE_STRING SignatureFileFullPath{};
    UNICODE_STRING PublicKeyFileFullPath{};

    PUCHAR Data = nullptr;
    ULONG DataSize = 0;

    PUCHAR Sign = nullptr;
    ULONG SignSize = 0;

    PUCHAR PublicKey = nullptr;
    ULONG PublicKeyLen = 0;

    GetExeDir(&ExeDir);
    GetFileName(&ExeDir, &g_SignatureFile, &SignatureFileFullPath);
    GetFileName(&ExeDir, &g_PublicKeyFile, &PublicKeyFileFullPath);
    GetFileName(&ExeDir, &g_UserAppFile, &UserAppFileFullPath);

    ReadFile(&UserAppFileFullPath, (PVOID *)&Data, &DataSize);
    ReadFile(&SignatureFileFullPath, (PVOID *)&Sign, &SignSize);
    ReadFile(&PublicKeyFileFullPath, (PVOID *)&PublicKey, &PublicKeyLen);    

    IsVerify = EcdsaVerifySignature(PublicKey, PublicKeyLen, (PUCHAR)Data, DataSize, Sign, SignSize);

    if (Data) {
        ExFreePoolWithTag(Data, TAG);
    }

    if (Sign) {
        ExFreePoolWithTag(Sign, TAG);
    }

    if (PublicKey) {
        ExFreePoolWithTag(PublicKey, TAG);
    }

    FreeUnicodeString(&SignatureFileFullPath);
    FreeUnicodeString(&PublicKeyFileFullPath);
    FreeUnicodeString(&UserAppFileFullPath);
    FreeUnicodeString(&ExeDir);

    return IsVerify;
}
