#include "DriverEntry.h"
#include "VerifySignature.h"


#define VERIFY_DEVICE_NAME     L"\\Device\\VerifyUserAppSignature"
#define VERIFY_DOS_DEVICE_NAME L"\\DosDevices\\VerifyUserAppSignature"
UNICODE_STRING g_SymbolicLinkName = RTL_CONSTANT_STRING(VERIFY_DOS_DEVICE_NAME);
UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(VERIFY_DEVICE_NAME);


_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID Unload(_In_ struct _DRIVER_OBJECT * DriverObject)
{
    PDEVICE_OBJECT      deviceObject = DriverObject->DeviceObject;

    PAGED_CODE();

    IoDeleteSymbolicLink(&g_SymbolicLinkName);

    IoDeleteDevice(deviceObject);
}


_Use_decl_annotations_
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION  irpStack;
    NTSTATUS            status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    irpStack = IoGetCurrentIrpStackLocation(Irp);

    ASSERT(irpStack->FileObject != NULL);

    switch (irpStack->MajorFunction) {
    case IRP_MJ_CREATE:
        if (VerifyUserAppSignature()) {
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_UNSUCCESSFUL;
        }
        break;
    case IRP_MJ_CLOSE:

        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    // Save Status for return and complete Irp
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}


EXTERN_C DRIVER_INITIALIZE DriverEntry;
//#pragma INITCODE
//#pragma alloc_text(INIT, DriverEntry)
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
EXTERN_C NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PDEVICE_OBJECT      deviceObject;

    UNREFERENCED_PARAMETER(RegistryPath);

    if (!KD_DEBUGGER_NOT_PRESENT) {
        KdBreakPoint();//__debugbreak();
    }

    //if (*InitSafeBootMode) {
    //    return STATUS_ACCESS_DENIED;
    //}

    PAGED_CODE();

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "FILE:%s, LINE:%d, DATE:%s, TIME:%s.\r\n", __FILE__, __LINE__, __DATE__, __TIME__);

    DriverObject->DriverUnload = Unload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    Status = IoCreateDevice(DriverObject,
                            0,
                            &g_DeviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &deviceObject);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x", Status);
        return Status;
    }

    Status = IoCreateSymbolicLink(&g_SymbolicLinkName, &g_DeviceName);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x", Status);
        IoDeleteDevice(deviceObject);
    }

    return Status;
}
