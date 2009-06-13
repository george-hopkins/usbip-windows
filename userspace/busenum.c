/*++

Copyright (c) 1990-2000  Microsoft Corporation All Rights Reserved

Module Name:

    BUSENUM.C

Abstract:

    This module contains the entry points for a toaster bus driver.

Author:


Environment:

    kernel mode only

Revision History:

    Cleaned up sample 05/05/99
    Fixed the create_close and ioctl handler to fail the request 
    sent on the child stack - 3/15/04


--*/

#include "busenum.h"


//
// Global Debug Level
//

ULONG BusEnumDebugLevel = BUS_DEFAULT_DEBUG_OUTPUT_LEVEL;


GLOBALS Globals;


#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, Bus_DriverUnload)
#pragma alloc_text (PAGE, Bus_Create)
#pragma alloc_text (PAGE, Bus_Close)
#pragma alloc_text (PAGE, Bus_Cleanup)
#pragma alloc_text (PAGE, Bus_Read)
#pragma alloc_text (PAGE, Bus_Write)
#pragma alloc_text (PAGE, Bus_IoCtl)
#endif

NTSTATUS
DriverEntry (
    __in  PDRIVER_OBJECT  DriverObject,
    __in  PUNICODE_STRING RegistryPath
    )
/*++
Routine Description:

    Initialize the driver dispatch table.

Arguments:

    DriverObject - pointer to the driver object

    RegistryPath - pointer to a unicode string representing the path,
                   to driver-specific key in the registry.

Return Value:

  NT Status Code

--*/
{

    Bus_KdPrint_Def (BUS_DBG_SS_TRACE, ("Driver Entry \n"));

    //
    // Save the RegistryPath for WMI.
    //

    Globals.RegistryPath.MaximumLength = RegistryPath->Length +
                                          sizeof(UNICODE_NULL);
    Globals.RegistryPath.Length = RegistryPath->Length;
    Globals.RegistryPath.Buffer = ExAllocatePoolWithTag(
                                       PagedPool,
                                       Globals.RegistryPath.MaximumLength,
                                       BUSENUM_POOL_TAG
                                       );

    if (!Globals.RegistryPath.Buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }


    KdPrint(("ReistryPath %p\r\n", RegistryPath));
    RtlCopyUnicodeString(&Globals.RegistryPath, RegistryPath);

    //
    // Set entry points into the driver
    //
    DriverObject->MajorFunction [IRP_MJ_CREATE] = Bus_Close;
    DriverObject->MajorFunction [IRP_MJ_CLEANUP] = Bus_Cleanup;
    DriverObject->MajorFunction [IRP_MJ_CLOSE] = Bus_Create;
    DriverObject->MajorFunction [IRP_MJ_READ] = Bus_Read;
    DriverObject->MajorFunction [IRP_MJ_WRITE] = Bus_Write;
    DriverObject->MajorFunction [IRP_MJ_PNP] = Bus_PnP;
    DriverObject->MajorFunction [IRP_MJ_POWER] = Bus_Power;
    DriverObject->MajorFunction [IRP_MJ_DEVICE_CONTROL] = Bus_IoCtl;
    DriverObject->MajorFunction [IRP_MJ_INTERNAL_DEVICE_CONTROL] = Bus_Internal_IoCtl;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = Bus_SystemControl;
    DriverObject->DriverUnload = Bus_DriverUnload;
    DriverObject->DriverExtension->AddDevice = Bus_AddDevice;

    KdPrint(("load ok"));

    return STATUS_SUCCESS;
}

#include "code2name.c"

struct usbip_header_basic {
#define USBIP_CMD_SUBMIT	0x0001
#define USBIP_CMD_UNLINK	0x0002
#define USBIP_RET_SUBMIT	0x0003
#define USBIP_RET_UNLINK	0x0004
	unsigned int command;

	 /* sequencial number which identifies requests.
	  * incremented per connections */
	unsigned int seqnum;

	unsigned int devid;

#define USBIP_DIR_OUT	0
#define USBIP_DIR_IN	1
	unsigned int direction;
	unsigned int ep;     /* endpoint number */
};

/*
 * An additional header for a CMD_SUBMIT packet.
 */
struct usbip_header_cmd_submit {
	/* these values are basically the same as in a URB. */

	/* the same in a URB. */
	unsigned int transfer_flags;

	/* set the following data size (out),
	 * or expected reading data size (in) */
	int transfer_buffer_length;

	/* it is difficult for usbip to sync frames (reserved only?) */
	int start_frame;

	/* the number of iso descriptors that follows this header */
	int number_of_packets;

	/* the maximum time within which this request works in a host
	 * controller of a server side */
	int interval;

	/* set setup packet data for a CTRL request */
	unsigned char setup[8];
};

/*
 * An additional header for a RET_SUBMIT packet.
 */
struct usbip_header_ret_submit {
	int status;
	int actual_length; /* returned data length */
	int start_frame; /* ISO and INT */
	int number_of_packets;  /* ISO only */
	int error_count; /* ISO only */
};

/*
 * An additional header for a CMD_UNLINK packet.
 */
struct usbip_header_cmd_unlink {
	unsigned int seqnum; /* URB's seqnum which will be unlinked */
};


/*
 * An additional header for a RET_UNLINK packet.
 */
struct usbip_header_ret_unlink {
	int status;
};


/* the same as usb_iso_packet_descriptor but packed for pdu */
struct usbip_iso_packet_descriptor {
	unsigned int offset;
	unsigned int length;            /* expected length */
	unsigned int actual_length;
	unsigned int status;
};


/*
 * All usbip packets use a common header to keep code simple.
 */
struct usbip_header {
	struct usbip_header_basic base;

	union {
		struct usbip_header_cmd_submit	cmd_submit;
		struct usbip_header_ret_submit	ret_submit;
		struct usbip_header_cmd_unlink	cmd_unlink;
		struct usbip_header_ret_unlink	ret_unlink;
	} u;
};



int process_write_irp(PPDO_DEVICE_DATA pdodata, PIRP irp)
{
    KIRQL oldirql;
    PLIST_ENTRY le = NULL;
    ULONG len;
    PIO_STACK_LOCATION irpstack;
    struct usbip_header *h;
    PIRP ioctl_irp;
    char *buf;
    struct _URB_BULK_OR_INTERRUPT_TRANSFER * urb;
    NTSTATUS ioctl_status = STATUS_INVALID_PARAMETER;
    int found=0;

    irpstack = IoGetCurrentIrpStackLocation (irp);
    len = irpstack->Parameters.Write.Length;
    if(len<sizeof(*h)){
	    KdPrint(("write, small len %d\n", len));
	    return STATUS_INVALID_PARAMETER;
    }
    h = irp->AssociatedIrp.SystemBuffer;
    if(len!=h->u.ret_submit.actual_length+sizeof(*h)){
	    KdPrint(("write, error len %d\n", len));
	    return STATUS_INVALID_PARAMETER;
    }
    KeAcquireSpinLock(&pdodata->wait_q_lock, &oldirql);
    for (le = pdodata->wait_q.Flink;
         le != &pdodata->wait_q;
         le = le->Flink) {
        ioctl_irp = CONTAINING_RECORD (le, IRP, Tail.Overlay.ListEntry);
	if(ioctl_irp->Tail.Overlay.DriverContext[0]==(PVOID)h->base.seqnum){
		found=1;
                RemoveEntryList (&ioctl_irp->Tail.Overlay.ListEntry);
                InitializeListHead(&ioctl_irp->Tail.Overlay.ListEntry);
		break;
	}
    }
    KeReleaseSpinLock(&pdodata->wait_q_lock, oldirql);
    if(!found){
	    KdPrint(("can't found %d\n", h->base.seqnum));
	    return STATUS_INVALID_PARAMETER;
    }
    irp->IoStatus.Information = len;
    irpstack = IoGetCurrentIrpStackLocation(ioctl_irp);
    if(irpstack->Parameters.DeviceIoControl.IoControlCode
		    != IOCTL_INTERNAL_USB_SUBMIT_URB)
	    goto end;
    urb =  irpstack->Parameters.Others.Argument1;
    if(NULL == urb)
	    goto end;
    buf = (char *)h + sizeof(*h);
    urb->TransferBufferLength = min((unsigned long)h->u.ret_submit.actual_length,
		    urb->TransferBufferLength);
    RtlCopyMemory(urb->TransferBuffer, buf, urb->TransferBufferLength);
    ioctl_status=STATUS_SUCCESS;
end:
    ioctl_irp->IoStatus.Status = ioctl_status;
    IoCompleteRequest(ioctl_irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
Bus_Write (
    __in  PDEVICE_OBJECT  DeviceObject,
    __in  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  stackirp;
    NTSTATUS            status;
    PFDO_DEVICE_DATA    fdoData;
    PCOMMON_DEVICE_DATA     commonData;
    PPDO_DEVICE_DATA pdodata;

    PAGED_CODE ();

    KdPrint(("enter Write func\n"));
    commonData = (PCOMMON_DEVICE_DATA) DeviceObject->DeviceExtension;

    if (!commonData->IsFDO) {
        Irp->IoStatus.Status = status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
	KdPrint(("Write return not fd\n"));
        return status;
    }

    fdoData = (PFDO_DEVICE_DATA) DeviceObject->DeviceExtension;

    Bus_IncIoCount (fdoData);

    if (fdoData->DevicePnPState == Deleted){
        status = STATUS_NO_SUCH_DEVICE;
	goto END;
    }
    stackirp = IoGetCurrentIrpStackLocation(Irp);
    pdodata = stackirp->FileObject->FsContext;
    if(NULL==pdodata||pdodata->Present == FALSE){
	status = STATUS_INVALID_DEVICE_REQUEST;
	goto END;
    }
    Irp->IoStatus.Information = 0;
    status = process_write_irp(pdodata, Irp);
END:
    KdPrint(("Write return:%08lx\n", status));
    Irp->IoStatus.Status = status;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);
    Bus_DecIoCount (fdoData);
    return status;
}


int prepare_bulk_urb(struct _URB_BULK_OR_INTERRUPT_TRANSFER * req,
		char *buf, int len,  int *copied, unsigned long seqnum,
		unsigned int devid)
{
	struct usbip_header * h = (struct usbip_header * ) buf;
	*copied = 0;
	if(len< sizeof(*h)||NULL==buf)
		return STATUS_BUFFER_TOO_SMALL;
//FIXME
#define htonl RtlUlongByteSwap
	h->base.command   = htonl(USBIP_CMD_SUBMIT);
	h->base.seqnum    = htonl(seqnum);
        h->base.devid     = htonl(devid);
	h->base.direction = htonl(USBIP_DIR_IN);
	h->base.ep        = htonl(0x81);
	h->u.cmd_submit.transfer_flags = 0;
        h->u.cmd_submit.transfer_buffer_length = htonl(req->TransferBufferLength);
        h->u.cmd_submit.start_frame = 0;
        h->u.cmd_submit.number_of_packets = 0;
        h->u.cmd_submit.interval = 0;
	*copied=sizeof(*h);
	return STATUS_SUCCESS;
}

int set_read_irp_data(PIRP read_irp, PIRP ioctl_irp, unsigned long seq_num,
		unsigned int devid)
{
    PIO_STACK_LOCATION iostack_irp;
    char *buf;
    int len;
    PURB urb;
    iostack_irp = IoGetCurrentIrpStackLocation(read_irp);

    buf = read_irp->AssociatedIrp.SystemBuffer;
    len = iostack_irp->Parameters.Read.Length;

    iostack_irp = IoGetCurrentIrpStackLocation(ioctl_irp);

    if(iostack_irp->Parameters.DeviceIoControl.IoControlCode
		    != IOCTL_INTERNAL_USB_SUBMIT_URB){
	    read_irp->IoStatus.Information = 0;
	    return  STATUS_INVALID_DEVICE_REQUEST;
    }
    urb =  iostack_irp->Parameters.Others.Argument1;
    if(NULL == urb){
	    read_irp->IoStatus.Information = 0;
	    return  STATUS_INVALID_DEVICE_REQUEST;
    }
    switch (urb->UrbHeader.Function){
		case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
			KdPrint(("do transfer\r\n"));
			return prepare_bulk_urb((struct _URB_BULK_OR_INTERRUPT_TRANSFER *)urb, buf, len,
			&read_irp->IoStatus.Information, seq_num, devid);
		default:
			break;
     }
     read_irp->IoStatus.Information = 0;
     KdPrint(("Warning function:%x %d\n", urb->UrbHeader.Function,
				urb->UrbHeader.Length));
     return STATUS_INVALID_PARAMETER;
}

void add_wait_q(PPDO_DEVICE_DATA pdodata, PIRP Irp);

int process_read_irp(PPDO_DEVICE_DATA pdodata, PIRP read_irp)
{
    NTSTATUS status = STATUS_PENDING;
    KIRQL oldirql;
    PIRP ioctl_irp;
    PLIST_ENTRY le = NULL;
    unsigned long seq_num;
    KeAcquireSpinLock(&pdodata->q_lock, &oldirql);
    if (!IsListEmpty(&pdodata->ioctl_q)){
	seq_num=++(pdodata->seq_num);
	le = RemoveHeadList(&pdodata->ioctl_q);
    } else {
	    if(pdodata->pending_read_irp)
		    status = STATUS_INVALID_DEVICE_REQUEST;
	    else{
		IoMarkIrpPending(read_irp);
		pdodata->pending_read_irp = read_irp;
	    }
    }
    KeReleaseSpinLock(&pdodata->q_lock, oldirql);
    if(le){
	ioctl_irp = CONTAINING_RECORD(le, IRP, Tail.Overlay.ListEntry);
	KdPrint(("get a ioctl_irp %p\n", ioctl_irp));
	ioctl_irp->Tail.Overlay.DriverContext[0]=(PVOID)seq_num;
	status = set_read_irp_data(read_irp, ioctl_irp, seq_num, pdodata->devid);
       if(status == STATUS_SUCCESS)
		add_wait_q(pdodata, ioctl_irp);
       else{
	       ioctl_irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
               IoCompleteRequest (ioctl_irp, IO_NO_INCREMENT);
       }
    }
    return status;
}

NTSTATUS
Bus_Read (
    __in  PDEVICE_OBJECT  DeviceObject,
    __in  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  irpStack;
    NTSTATUS            status;
    PFDO_DEVICE_DATA    fdoData;
    PPDO_DEVICE_DATA	pdodata;
    PCOMMON_DEVICE_DATA     commonData;
    PIO_STACK_LOCATION stackirp;

    PAGED_CODE ();

    commonData = (PCOMMON_DEVICE_DATA) DeviceObject->DeviceExtension;

    if (!commonData->IsFDO) {
        Irp->IoStatus.Status = status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
        return status;
    }

    fdoData = (PFDO_DEVICE_DATA) DeviceObject->DeviceExtension;

    Bus_IncIoCount (fdoData);

    //
    // Check to see whether the bus is removed
    //

    if (fdoData->DevicePnPState == Deleted){
        status = STATUS_NO_SUCH_DEVICE;
	goto END;
    }
    stackirp = IoGetCurrentIrpStackLocation(Irp);
    pdodata = stackirp->FileObject->FsContext;
    if(NULL==pdodata||pdodata->Present == FALSE){
	status = STATUS_INVALID_DEVICE_REQUEST;
	goto END;
    }
    if(pdodata->pending_read_irp){
	status = STATUS_INVALID_PARAMETER;
	goto END;
    }
    status = process_read_irp(pdodata, Irp);
END:
    if(status != STATUS_PENDING){
	Irp->IoStatus.Status = status;
	IoCompleteRequest (Irp, IO_NO_INCREMENT);
    }
    Bus_DecIoCount (fdoData);
    return status;
}

NTSTATUS
Bus_Create (
    __in  PDEVICE_OBJECT  DeviceObject,
    __in  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  irpStack;
    NTSTATUS            status;
    PFDO_DEVICE_DATA    fdoData;
    PCOMMON_DEVICE_DATA     commonData;
    PIO_STACK_LOCATION iostackirp = NULL;

    PAGED_CODE ();

    commonData = (PCOMMON_DEVICE_DATA) DeviceObject->DeviceExtension;

    if (!commonData->IsFDO) {
        Irp->IoStatus.Status = status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
        return status;
    }

    fdoData = (PFDO_DEVICE_DATA) DeviceObject->DeviceExtension;

    Bus_IncIoCount (fdoData);

    //
    // Check to see whether the bus is removed
    //

    if (fdoData->DevicePnPState == Deleted) {
        Irp->IoStatus.Status = status = STATUS_NO_SUCH_DEVICE;
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
        return status;
    }
    status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = status;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);
    Bus_DecIoCount (fdoData);
    return status;
}

NTSTATUS
Bus_Cleanup (
    __in  PDEVICE_OBJECT  dev,
    __in  PIRP            irp
    )
{
    PIO_STACK_LOCATION  irpstack;
    NTSTATUS            status;
    PFDO_DEVICE_DATA    fdodata;
    PPDO_DEVICE_DATA	pdodata;
    PCOMMON_DEVICE_DATA     commondata;

    PAGED_CODE ();

    commondata = (PCOMMON_DEVICE_DATA) dev->DeviceExtension;
    //
    // We only allow create/close requests for the FDO.
    // That is the bus itself.
    //

    if (!commondata->IsFDO) {
        irp->IoStatus.Status = status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest (irp, IO_NO_INCREMENT);
        return status;
    }

    fdodata = (PFDO_DEVICE_DATA) dev->DeviceExtension;

    Bus_IncIoCount (fdodata);

    //
    // Check to see whether the bus is removed
    //

    if (fdodata->DevicePnPState == Deleted) {
        irp->IoStatus.Status = status = STATUS_NO_SUCH_DEVICE;
        IoCompleteRequest (irp, IO_NO_INCREMENT);
        return status;
    }
    irpstack = IoGetCurrentIrpStackLocation(irp);
    pdodata = irpstack->FileObject->FsContext;
    if(pdodata){
	    pdodata->fo=NULL;
	    irpstack->FileObject->FsContext=NULL;
    }
    status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = status;
    IoCompleteRequest (irp, IO_NO_INCREMENT);
    Bus_DecIoCount (fdodata);
    return status;
}

NTSTATUS
Bus_Close (
    __in  PDEVICE_OBJECT  DeviceObject,
    __in  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  irpStack;
    NTSTATUS            status;
    PFDO_DEVICE_DATA    fdoData;
    PCOMMON_DEVICE_DATA     commonData;

    PAGED_CODE ();

    commonData = (PCOMMON_DEVICE_DATA) DeviceObject->DeviceExtension;
    //
    // We only allow create/close requests for the FDO.
    // That is the bus itself.
    //

    if (!commonData->IsFDO) {
        Irp->IoStatus.Status = status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
        return status;
    }

    fdoData = (PFDO_DEVICE_DATA) DeviceObject->DeviceExtension;

    Bus_IncIoCount (fdoData);

    //
    // Check to see whether the bus is removed
    //

    if (fdoData->DevicePnPState == Deleted) {
        Irp->IoStatus.Status = status = STATUS_NO_SUCH_DEVICE;
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
        return status;
    }
    status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = status;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);
    Bus_DecIoCount (fdoData);
    return status;
}


/* mostly the same values as the Bochs USB Mouse device */
static const unsigned char qemu_mouse_dev_descriptor[] = {
	0x12,       /*  u8 bLength; */
	0x01,       /*  u8 bDescriptorType; Device */
	0x00, 0x01, /*  u16 bcdUSB; v1.0 */

	0x00,	    /*  u8  bDeviceClass; */
	0x00,	    /*  u8  bDeviceSubClass; */
	0x00,       /*  u8  bDeviceProtocol; [ low/full speeds only ] */
	0x08,       /*  u8  bMaxPacketSize0; 8 Bytes */

	0x28, 0x06, /*  u16 idVendor; */
 	0x10, 0x00, /*  u16 idProduct; */
	0x00, 0x00, /*  u16 bcdDevice */

	0x03,       /*  u8  iManufacturer; */
	0x02,       /*  u8  iProduct; */
	0x01,       /*  u8  iSerialNumber; */
	0x01        /*  u8  bNumConfigurations; */
};

static const unsigned char qemu_mouse_config_descriptor[] = {
	/* one configuration */
	0x09,       /*  u8  bLength; */
	0x02,       /*  u8  bDescriptorType; Configuration */
	0x22, 0x00, /*  u16 wTotalLength; */
	0x01,       /*  u8  bNumInterfaces; (1) */
	0x01,       /*  u8  bConfigurationValue; */
	0x04,       /*  u8  iConfiguration; */
	0xa0,       /*  u8  bmAttributes;
				 Bit 7: must be set,
				     6: Self-powered,
				     5: Remote wakeup,
				     4..0: resvd */
	50,         /*  u8  MaxPower; */

	/* USB 1.1:
	 * USB 2.0, single TT organization (mandatory):
	 *	one interface, protocol 0
	 *
	 * USB 2.0, multiple TT organization (optional):
	 *	two interfaces, protocols 1 (like single TT)
	 *	and 2 (multiple TT mode) ... config is
	 *	sometimes settable
	 *	NOT IMPLEMENTED
	 */

	/* one interface */
	0x09,       /*  u8  if_bLength; */
	0x04,       /*  u8  if_bDescriptorType; Interface */
	0x00,       /*  u8  if_bInterfaceNumber; */
	0x00,       /*  u8  if_bAlternateSetting; */
	0x01,       /*  u8  if_bNumEndpoints; */
	0x03,       /*  u8  if_bInterfaceClass; */
	0x01,       /*  u8  if_bInterfaceSubClass; */
	0x02,       /*  u8  if_bInterfaceProtocol; [usb1.1 or single tt] */
	0x07,       /*  u8  if_iInterface; */

        /* HID descriptor */
        0x09,        /*  u8  bLength; */
        0x21,        /*  u8 bDescriptorType; */
        0x01, 0x00,  /*  u16 HID_class */
        0x00,        /*  u8 country_code */
        0x01,        /*  u8 num_descriptors */
        0x22,        /*  u8 type; Report */
        52, 0,       /*  u16 len */

	/* one endpoint (status change endpoint) */
	0x07,       /*  u8  ep_bLength; */
	0x05,       /*  u8  ep_bDescriptorType; Endpoint */
	0x81,       /*  u8  ep_bEndpointAddress; IN Endpoint 1 */
 	0x03,       /*  u8  ep_bmAttributes; Interrupt */
 	0x04, 0x00, /*  u16 ep_wMaxPacketSize; */
	0x0a,       /*  u8  ep_bInterval; (255ms -- usb 2.0 spec) */
};

static const unsigned char qemu_mouse_hid_report_descriptor[] = {
    0x05, 0x01,		/* Usage Page (Generic Desktop) */
    0x09, 0x02,		/* Usage (Mouse) */
    0xa1, 0x01,		/* Collection (Application) */
    0x09, 0x01,		/*   Usage (Pointer) */
    0xa1, 0x00,		/*   Collection (Physical) */
    0x05, 0x09,		/*     Usage Page (Button) */
    0x19, 0x01,		/*     Usage Minimum (1) */
    0x29, 0x03,		/*     Usage Maximum (3) */
    0x15, 0x00,		/*     Logical Minimum (0) */
    0x25, 0x01,		/*     Logical Maximum (1) */
    0x95, 0x03,		/*     Report Count (3) */
    0x75, 0x01,		/*     Report Size (1) */
    0x81, 0x02,		/*     Input (Data, Variable, Absolute) */
    0x95, 0x01,		/*     Report Count (1) */
    0x75, 0x05,		/*     Report Size (5) */
    0x81, 0x01,		/*     Input (Constant) */
    0x05, 0x01,		/*     Usage Page (Generic Desktop) */
    0x09, 0x30,		/*     Usage (X) */
    0x09, 0x31,		/*     Usage (Y) */
    0x09, 0x38,		/*     Usage (Wheel) */
    0x15, 0x81,		/*     Logical Minimum (-0x7f) */
    0x25, 0x7f,		/*     Logical Maximum (0x7f) */
    0x75, 0x08,		/*     Report Size (8) */
    0x95, 0x03,		/*     Report Count (3) */
    0x81, 0x06,		/*     Input (Data, Variable, Relative) */
    0xc0,		/*   End Collection */
    0xc0,		/* End Collection */
};

void try_copy(struct _URB_CONTROL_DESCRIPTOR_REQUEST *req, unsigned const char *buf,
		unsigned int buf_len)
{
	unsigned int len;
	len=min(req->TransferBufferLength, buf_len);
	RtlCopyMemory(req->TransferBuffer, buf, len);
	req->TransferBufferLength = len;
}

int class_interface(struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST  *req)
{

	KdPrint(("flag:%d pbuf:%p len:%d RequestTypeReservedBits:%02x"
	"Request:%02x Value:%02x Index:%02x\r\n",
	req->TransferFlags, req->TransferBuffer,
	req->TransferBufferLength,
	req->RequestTypeReservedBits, req->Request,
	req->Value, req->Index));
	return  STATUS_SUCCESS;
}

int get_descriptor_from_interface(struct _URB_CONTROL_DESCRIPTOR_REQUEST * req)
{
	KdPrint(("pbuf:%p len:%d Index:%02x"
	"DescriptorType:%02x LanguageId:%02x\r\n",
	req->TransferBuffer,
	req->TransferBufferLength,
	req->Index,
	req->DescriptorType, 
	req->LanguageId));
	if(req->DescriptorType!=0x22){
		KdPrint(("unknow what for\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	try_copy(req, qemu_mouse_hid_report_descriptor,
					sizeof(qemu_mouse_hid_report_descriptor));
	return STATUS_SUCCESS;
}

int get_descriptor_from_device(struct _URB_CONTROL_DESCRIPTOR_REQUEST * req)
{
	switch(req->DescriptorType){
		case USB_DEVICE_DESCRIPTOR_TYPE:
			KdPrint(("get device descriptor\r\n"));
			try_copy(req, qemu_mouse_dev_descriptor, 
					sizeof(qemu_mouse_dev_descriptor));
			break;
		case USB_CONFIGURATION_DESCRIPTOR_TYPE:
			KdPrint(("get config descriptor\r\n"));
			try_copy(req, qemu_mouse_config_descriptor,
					sizeof(qemu_mouse_config_descriptor));
			break;
		case USB_STRING_DESCRIPTOR_TYPE:
			KdPrint(("Warning get string desc\r\n"));
			return STATUS_INSUFFICIENT_RESOURCES;
		default:
			return STATUS_INVALID_PARAMETER;
	}
	return STATUS_SUCCESS;
}

void proc_select_config(struct _URB_SELECT_CONFIGURATION * req)
{
	unsigned int i;
	KdPrint(("config handle:%d\n", req->ConfigurationHandle));
	KdPrint(("interface: len:%d num:%d class:%d subclass:%d"
		"protocol:%d handle:%d numerofpipes:%d",
		req->Interface.Length,
		req->Interface.InterfaceNumber,
		req->Interface.Class,
		req->Interface.SubClass,
		req->Interface.Protocol,
		req->Interface.InterfaceHandle,
		req->Interface.NumberOfPipes));
	req->Interface.Class=3;
	req->Interface.SubClass=1;
	req->Interface.Protocol=2;
	req->Interface.InterfaceHandle = (USBD_INTERFACE_HANDLE) 0x12345678;
	req->ConfigurationHandle=(USBD_CONFIGURATION_HANDLE) 0x12345678;
	for(i=0;i<req->Interface.NumberOfPipes;i++){
		KdPrint(("pipe %d:\n"
	    "MaximumTransferSize: %d\n"
	    "EndpointAddress: %d\n"
	    "Interval: %d\n"
	    "PipeType: %d\n"
	    "PiPeHandle: %d\n"
	    "MaximumTransferSize %d\n"
	    "PipeFlags %d\n", i,
	    req->Interface.Pipes[i].MaximumTransferSize,
	    req->Interface.Pipes[i].EndpointAddress,
	    req->Interface.Pipes[i].Interval,
	    req->Interface.Pipes[i].PipeType,
	    req->Interface.Pipes[i].PipeHandle,
	    req->Interface.Pipes[i].MaximumTransferSize,
	    req->Interface.Pipes[i].PipeFlags));

 	    req->Interface.Pipes[i].EndpointAddress=0x81;
	    req->Interface.Pipes[i].Interval=1;
	    req->Interface.Pipes[i].PipeType=UsbdPipeTypeInterrupt;
	    req->Interface.Pipes[i].PipeHandle=(USBD_PIPE_HANDLE) 0x12345678;
	}
}

int proc_urb(void *arg)
{
	PURB urb=(PURB) arg;
	if(urb==NULL){
		KdPrint(("null arg"));
		return STATUS_INVALID_PARAMETER;
	}
	switch (urb->UrbHeader.Function){
		case URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE:
			KdPrint(("get descriptor:%p %d\n",
			urb->UrbControlDescriptorRequest.TransferBuffer,
			urb->UrbControlDescriptorRequest.TransferBufferLength));
			return get_descriptor_from_device(arg);
			break;
		case URB_FUNCTION_SELECT_CONFIGURATION:
			KdPrint(("select configuration\n"));
			proc_select_config(arg);
			return STATUS_SUCCESS;
		case URB_FUNCTION_CLASS_INTERFACE:
			KdPrint(("class interface\r\n"));
			return class_interface(arg);
		case URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE:
			KdPrint(("get descriptor from interface\r\n"));
			return get_descriptor_from_interface(arg);
		case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
			KdPrint(("do transfer\r\n"));
			return STATUS_PENDING;
		default:
			break;
	}
	KdPrint(("Warning function:%x %d\n", urb->UrbHeader.Function,
				urb->UrbHeader.Length));
	return STATUS_INVALID_PARAMETER;
}

void add_wait_q(PPDO_DEVICE_DATA pdodata, PIRP Irp)
{
    KIRQL oldirql;

    KeAcquireSpinLock(&pdodata->wait_q_lock, &oldirql);
	InsertTailList(&pdodata->wait_q, &Irp->Tail.Overlay.ListEntry);
    KeReleaseSpinLock(&pdodata->wait_q_lock, oldirql);

    return;
}



int try_addq(PPDO_DEVICE_DATA pdodata, PIRP Irp)
{
    KIRQL oldirql;
    PIRP read_irp;
    NTSTATUS status=STATUS_PENDING;
    unsigned long seq_num;

    KeAcquireSpinLock(&pdodata->q_lock, &oldirql);
    read_irp=pdodata->pending_read_irp;
    pdodata->pending_read_irp=NULL;
    if(NULL==read_irp){
           IoMarkIrpPending(Irp);
	   InsertTailList(&pdodata->ioctl_q, &Irp->Tail.Overlay.ListEntry);\
    } else
	    seq_num = ++(pdodata->seq_num);
    KeReleaseSpinLock(&pdodata->q_lock, oldirql);
    if(NULL==read_irp)
	    return status;

    read_irp->IoStatus.Status = set_read_irp_data(read_irp, Irp, seq_num,
		    pdodata->devid);
    if(read_irp->IoStatus.Status == STATUS_SUCCESS){
	Irp->Tail.Overlay.DriverContext[0]=(PVOID)seq_num;
	add_wait_q(pdodata, Irp);
    }
    else
	status = STATUS_INVALID_PARAMETER;
    IoCompleteRequest(read_irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS
Bus_Internal_IoCtl (
    __in  PDEVICE_OBJECT  DeviceObject,
    __in  PIRP            Irp
    )
{
    PIO_STACK_LOCATION      irpStack;
    NTSTATUS                status;
    ULONG                   inlen;
    PPDO_DEVICE_DATA        pdoData;
    PVOID                   buffer;
    PCOMMON_DEVICE_DATA     commonData;

    PAGED_CODE ();

    commonData = (PCOMMON_DEVICE_DATA) DeviceObject->DeviceExtension;
    KdPrint(("Enter internal control %d\r\n", commonData->IsFDO));

    if (commonData->IsFDO) {
        Irp->IoStatus.Status = status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
        return status;
    }

    pdoData = (PPDO_DEVICE_DATA) DeviceObject->DeviceExtension;

    if (pdoData->Present==FALSE) {
        Irp->IoStatus.Status = status = STATUS_DEVICE_OFF_LINE;
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
        return status;
    }

    irpStack = IoGetCurrentIrpStackLocation (Irp);

    buffer = Irp->AssociatedIrp.SystemBuffer;
    inlen = irpStack->Parameters.DeviceIoControl.InputBufferLength;

    status = STATUS_INVALID_PARAMETER;

    KdPrint(("internal control:%d %s\r\n", irpStack->Parameters.DeviceIoControl.IoControlCode,code2name(irpStack->Parameters.DeviceIoControl.IoControlCode)));
    switch(irpStack->Parameters.DeviceIoControl.IoControlCode){
        case IOCTL_INTERNAL_USB_SUBMIT_URB:
		    status=proc_urb(irpStack->Parameters.Others.Argument1);
		    break;
	default:
		    KdPrint(("Unknown Ioctrl code\n"));
		    break;
    }
    Irp->IoStatus.Information = 0;

    if(status == STATUS_PENDING)
	 status = try_addq(pdoData,Irp);
    if(status!=STATUS_PENDING) {
	Irp->IoStatus.Status = status;
	IoCompleteRequest (Irp, IO_NO_INCREMENT);
    }
    return status;
}



NTSTATUS
Bus_IoCtl (
    __in  PDEVICE_OBJECT  DeviceObject,
    __in  PIRP            Irp
    )
/*++
Routine Description:

    Handle user mode PlugIn, UnPlug and device Eject requests.

Arguments:

   DeviceObject - pointer to a device object.

   Irp - pointer to an I/O Request Packet.

Return Value:

   NT status code

--*/
{
    PIO_STACK_LOCATION      irpStack;
    NTSTATUS                status;
    ULONG                   inlen;
    ULONG                   outlen;
    ULONG		    info = 0;
    PFDO_DEVICE_DATA        fdoData;
    PVOID                   buffer;
    PCOMMON_DEVICE_DATA     commonData;

    PAGED_CODE ();

    KdPrint(("Enter control\r\n"));

    commonData = (PCOMMON_DEVICE_DATA) DeviceObject->DeviceExtension;
    //
    // We only allow create/close requests for the FDO.
    // That is the bus itself.
    //
    if (!commonData->IsFDO) {
        Irp->IoStatus.Status = status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
        return status;
    }

    fdoData = (PFDO_DEVICE_DATA) DeviceObject->DeviceExtension;

    Bus_IncIoCount (fdoData);

    //
    // Check to see whether the bus is removed
    //

    if (fdoData->DevicePnPState == Deleted) {
        status = STATUS_NO_SUCH_DEVICE;
        goto END;
    }

    irpStack = IoGetCurrentIrpStackLocation (Irp);

    buffer = Irp->AssociatedIrp.SystemBuffer;
    inlen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outlen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    status = STATUS_INVALID_PARAMETER;

    switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_USBVBUS_PLUGIN_HARDWARE:
        if (sizeof(ioctl_usbvbus_plugin) == inlen ) {
            Bus_KdPrint(fdoData, BUS_DBG_IOCTL_TRACE, ("PlugIn called\n"));

            status= bus_plugin_dev((ioctl_usbvbus_plugin *)buffer, fdoData,
			    irpStack->FileObject);
        }
        break;

   case IOCTL_USBVBUS_GET_PORTS_STATUS:
        if (sizeof(ioctl_usbvbus_get_ports_status) == outlen ) {
            Bus_KdPrint(fdoData, BUS_DBG_IOCTL_TRACE, ("get ports status called\n"));

            status= bus_get_ports_status((ioctl_usbvbus_get_ports_status *)buffer, fdoData, &info);
        }
        break;

    case IOCTL_USBVBUS_UNPLUG_HARDWARE:

        if (sizeof (ioctl_usbvbus_unplug) == inlen){

            Bus_KdPrint(fdoData, BUS_DBG_IOCTL_TRACE, ("UnPlug called\n"));

            status= bus_unplug_dev(
                    (ioctl_usbvbus_unplug *)buffer, fdoData);

        }
        break;

    case IOCTL_USBVBUS_EJECT_HARDWARE:

        if ((sizeof (BUSENUM_EJECT_HARDWARE) == inlen) &&
            (((PBUSENUM_EJECT_HARDWARE)buffer)->Size == inlen)) {

            Bus_KdPrint(fdoData, BUS_DBG_IOCTL_TRACE, ("Eject called\n"));

            status= Bus_EjectDevice((PBUSENUM_EJECT_HARDWARE)buffer, fdoData);

        }
        break;

    default:
        break; // default status is STATUS_INVALID_PARAMETER
    }

    Irp->IoStatus.Information = info;
END:
    Irp->IoStatus.Status = status;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);
    Bus_DecIoCount (fdoData);
    return status;
}


VOID
Bus_DriverUnload (
    __in PDRIVER_OBJECT DriverObject
    )
/*++
Routine Description:
    Clean up everything we did in driver entry.

Arguments:

   DriverObject - pointer to this driverObject.


Return Value:

--*/
{
    PAGED_CODE ();

    Bus_KdPrint_Def (BUS_DBG_SS_TRACE, ("Unload\n"));

    //
    // All the device objects should be gone.
    //

    ASSERT (NULL == DriverObject->DeviceObject);

    //
    // Here we free all the resources allocated in the DriverEntry
    //

    if (Globals.RegistryPath.Buffer)
        ExFreePool(Globals.RegistryPath.Buffer);

    return;
}

VOID
Bus_IncIoCount (
    __in  PFDO_DEVICE_DATA   FdoData
    )

/*++

Routine Description:

    This routine increments the number of requests the device receives


Arguments:

    FdoData - pointer to the FDO device extension.

Return Value:

    VOID

--*/

{

    LONG            result;


    result = InterlockedIncrement(&FdoData->OutstandingIO);

    ASSERT(result > 0);
    //
    // Need to clear StopEvent (when OutstandingIO bumps from 1 to 2)
    //
    if (result == 2) {
        //
        // We need to clear the event
        //
        KeClearEvent(&FdoData->StopEvent);
    }

    return;
}

VOID
Bus_DecIoCount(
    __in  PFDO_DEVICE_DATA  FdoData
    )

/*++

Routine Description:

    This routine decrements as it complete the request it receives

Arguments:

    FdoData - pointer to the FDO device extension.

Return Value:

    VOID

--*/
{

    LONG            result;

    result = InterlockedDecrement(&FdoData->OutstandingIO);

    ASSERT(result >= 0);

    if (result == 1) {
        //
        // Set the stop event. Note that when this happens
        // (i.e. a transition from 2 to 1), the type of requests we
        // want to be processed are already held instead of being
        // passed away, so that we can't "miss" a request that
        // will appear between the decrement and the moment when
        // the value is actually used.
        //

        KeSetEvent (&FdoData->StopEvent, IO_NO_INCREMENT, FALSE);

    }

    if (result == 0) {

        //
        // The count is 1-biased, so it can be zero only if an
        // extra decrement is done when a remove Irp is received
        //

        ASSERT(FdoData->DevicePnPState == Deleted);

        //
        // Set the remove event, so the device object can be deleted
        //

        KeSetEvent (&FdoData->RemoveEvent, IO_NO_INCREMENT, FALSE);

    }

    return;
}


