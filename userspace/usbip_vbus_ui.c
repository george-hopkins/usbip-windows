#define INITGUID
#include <basetyps.h>
#include <stdlib.h>
#include <wtypes.h>
#include <setupapi.h>
#include <initguid.h>
#include <stdio.h>
#include <string.h>
#include <winioctl.h>
#include <ctype.h>
#include "public.h"
#include "usbip.h"

static char * usbip_vbus_dev_node_name(char *buf, int buf_len)
{
	HDEVINFO dev_info;
	SP_DEVICE_INTERFACE_DATA dev_interface_data;
	PSP_DEVICE_INTERFACE_DETAIL_DATA dev_interface_detail = NULL;
	unsigned long len;
	char *ret=NULL;

	dev_info = SetupDiGetClassDevs(
		(LPGUID) &GUID_DEVINTERFACE_BUSENUM_TOASTER, /* ClassGuid */
		NULL,	/* Enumerator */
	        NULL,	/* hwndParent */
		DIGCF_PRESENT|DIGCF_DEVICEINTERFACE /* Flags */
	);

	if (INVALID_HANDLE_VALUE == dev_info) {
		err("SetupDiGetClassDevs failed: %ld\n", GetLastError());
		return NULL;
	}

	dev_interface_data.cbSize = sizeof (dev_interface_data);

	if (!SetupDiEnumDeviceInterfaces(
		dev_info, /* DeviceInfoSet */
		NULL, /* DeviceInfoData */
		(LPGUID)
		&GUID_DEVINTERFACE_BUSENUM_TOASTER, /* InterfaceClassGuid */
		0, /* MemberIndex */
		&dev_interface_data /* DeviceInterfaceData */
	)) {
		if (ERROR_NO_MORE_ITEMS == GetLastError())
			err("usbvbus interface is not registered\n");
		else
			err("unknown error when get interface_data\n");
		goto end;
	}
	SetupDiGetDeviceInterfaceDetail(
		dev_info, /* DeviceInfoSet */
		&dev_interface_data, /* DeviceInterfaceData */
		NULL,	/* DeviceInterfaceDetailData */
		0,	/* DeviceInterfaceDetailDataSize */
		&len,	/* RequiredSize */
		NULL	/* DeviceInfoData */);

	if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
		err("Error in SetupDiGetDeviceInterfaceDetail%ld\n",
		       GetLastError());
		goto end;
	}

	dev_interface_detail = malloc(len);
	if(NULL == dev_interface_detail){
		err("can't malloc %lu size memoery", len);
		goto end;
	}
	dev_interface_detail->cbSize = sizeof (*dev_interface_detail);

	if (!SetupDiGetDeviceInterfaceDetail(
		dev_info, /* DeviceInfoSet */
		&dev_interface_data, /* DeviceInterfaceData */
		dev_interface_detail,	/* DeviceInterfaceDetailData */
		len,	/* DeviceInterfaceDetailDataSize */
		&len,	/* RequiredSize */
		NULL	/* DeviceInfoData */)){
		err("Error in SetupDiGetDeviceInterfaceDetail\n");
		goto end;
	}
	len=snprintf(buf, buf_len, "%s", dev_interface_detail->DevicePath);
	if(len>=buf_len)
		goto end;
	ret = buf;
end:
	if(dev_interface_detail)
		free(dev_interface_detail);
	SetupDiDestroyDeviceInfoList(dev_info);
	return ret;
}

HANDLE usbip_vbus_open(void)
{
	char buf[256];
	if(NULL==usbip_vbus_dev_node_name(buf, sizeof(buf)))
		return INVALID_HANDLE_VALUE;
	return	CreateFile(buf,
			GENERIC_READ|GENERIC_WRITE,
			  0,
			  NULL,
			  OPEN_EXISTING,
			  FILE_FLAG_OVERLAPPED,
			  NULL);
}

int usbip_vbus_get_ports_status(HANDLE fd, char *buf, int l)
{
	int ret;
	unsigned long len;
	ioctl_usbvbus_get_ports_status * st=(ioctl_usbvbus_get_ports_status *)buf;

	if(l!=sizeof(*st))
		return -1;

	ret = DeviceIoControl(fd, IOCTL_USBVBUS_GET_PORTS_STATUS,
				NULL, 0, st, sizeof(*st), &len, NULL);
	if(ret&&len==sizeof(*st))
		return 0;
	else
		return -1;
}

int usbip_vbus_get_free_port(HANDLE fd)
{
	int i;
	char buf[128];
	if(usbip_vbus_get_ports_status(fd, buf, sizeof(buf)))
		return -1;
	for(i=1;i<sizeof(buf);i++){
		if(!buf[i])
			return i;
	}
	return -1;
}

int usbip_vbus_detach_device(HANDLE fd, int port)
{
	int ret;
	ioctl_usbvbus_unplug  unplug;
	unsigned long unused;

	unplug.addr = port;
	ret = DeviceIoControl(fd, IOCTL_USBVBUS_UNPLUG_HARDWARE,
				&unplug, sizeof(unplug), NULL, 0, &unused, NULL);
	if(ret)
		return 0;
	return -1;
}

int usbip_vbus_attach_device(HANDLE fd, int port, struct usb_device *udev,
		struct usb_interface *uinf0)
{
	int ret;
	ioctl_usbvbus_plugin  plugin;
	unsigned long unused;

	plugin.devid  = ((udev->busnum << 16)|udev->devnum);
	plugin.vendor = udev->idVendor;
	plugin.product = udev->idProduct;
	plugin.version = udev->bcdDevice;
	plugin.int0_class = uinf0->bInterfaceClass;
	plugin.int0_subclass = uinf0->bInterfaceSubClass;
	plugin.int0_protocol = uinf0->bInterfaceProtocol;
	plugin.addr = port;

	info("call me\n");
	ret = DeviceIoControl(fd, IOCTL_USBVBUS_PLUGIN_HARDWARE,
				&plugin, sizeof(plugin), NULL, 0, &unused, NULL);
	info("finishied attach\n");
	if(ret)
		return 0;
	return -1;
}

static void usbip_dump_header(struct usbip_header *pdu)
{
	dbg("BASE: cmd %u seq %u devid %u dir %u ep %u\n",
			pdu->base.command,
			pdu->base.seqnum,
			pdu->base.devid,
			pdu->base.direction,
			pdu->base.ep);

	switch(pdu->base.command) {
		case USBIP_CMD_SUBMIT:
			dbg("CMD_SUBMIT: x_flags %u x_len %u sf %u #p %u iv %u\n",
					pdu->u.cmd_submit.transfer_flags,
					pdu->u.cmd_submit.transfer_buffer_length,
					pdu->u.cmd_submit.start_frame,
					pdu->u.cmd_submit.number_of_packets,
					pdu->u.cmd_submit.interval);
					break;
		case USBIP_CMD_UNLINK:
			dbg("CMD_UNLINK: seq %u\n", pdu->u.cmd_unlink.seqnum);
			break;
		case USBIP_RET_SUBMIT:
			dbg("RET_SUBMIT: st %d al %u sf %d ec %d\n",
					pdu->u.ret_submit.status,
					pdu->u.ret_submit.actual_length,
					pdu->u.ret_submit.start_frame,
					pdu->u.ret_submit.error_count);
			break;
		case USBIP_RET_UNLINK:
			dbg("RET_UNLINK: status %d\n", pdu->u.ret_unlink.status);
			break;
		default:
			/* NOT REACHED */
			dbg("UNKNOWN\n");
	}
}

struct fd_info {
	SOCKET sock;
	HANDLE dev;
};

static void correct_endian_basic(struct usbip_header_basic *base, int send)
{
	if (send) {
		base->command	= htonl(base->command);
		base->seqnum	= htonl(base->seqnum);
		base->devid	= htonl(base->devid);
		base->direction	= htonl(base->direction);
		base->ep	= htonl(base->ep);
	} else {
		base->command	= ntohl(base->command);
		base->seqnum	= ntohl(base->seqnum);
		base->devid	= ntohl(base->devid);
		base->direction	= ntohl(base->direction);
		base->ep	= ntohl(base->ep);
	}
}

static void correct_endian_ret_submit(struct usbip_header_ret_submit *pdu)
{
	pdu->status	= ntohl(pdu->status);
	pdu->actual_length = ntohl(pdu->actual_length);
	pdu->start_frame = ntohl(pdu->start_frame);
	pdu->error_count = ntohl(pdu->error_count);
}

void usbip_header_correct_endian(struct usbip_header *pdu, int send)
{
	unsigned int cmd = 0;

	if (send)
		cmd = pdu->base.command;

	correct_endian_basic(&pdu->base, send);

	if (!send)
		cmd = pdu->base.command;

	switch (cmd) {
		case USBIP_RET_SUBMIT:
			correct_endian_ret_submit(&pdu->u.ret_submit);
			break;
		default:
			/* NOTREACHED */
			err("unknown command in pdu header: %d", cmd);
			//BUG();
	}
}

DWORD WINAPI sock_thread(LPVOID p)
{
	struct fd_info * fdi=p;
	int ret, len;
	unsigned long out=0;
	char *buf;
	struct usbip_header u;
	HANDLE ev;
	OVERLAPPED ov;
	ev=CreateEvent(NULL, FALSE, FALSE, NULL);
	ov.Offset=ov.OffsetHigh=0;
	ov.hEvent=ev;

	do {
		ret=recv(fdi->sock, (char *)&u, sizeof(u), 0);
		if(ret!=sizeof(u)){
			err("strange recv %d\n",ret);
			break;
		}
		usbip_header_correct_endian(&u, 0);
		//FIXME
		len = sizeof(u)+u.u.ret_submit.actual_length;
		buf=malloc(len);
		if(NULL==buf){
			err("malloc\n");
			break;
		}
//		usbip_dump_header(&u);
		memcpy(buf, &u, sizeof(u));
		ret=recv(fdi->sock, buf+sizeof(u),
				u.u.ret_submit.actual_length,0);
		if(ret!=u.u.ret_submit.actual_length){
			err("recv from sock failed\n");
			free(buf);
			break;
		}
		ret=WriteFile(fdi->dev, buf, len, &out, &ov);
		if(!ret||out!=len){
			err("last error:%ld\n",GetLastError());
			err("out:%ld ret:%d len:%d\n",out,ret,len);
			err("write dev failed");
			break;
		}
		free(buf);
	} while(1);
	CloseHandle(fdi->dev);
	ExitThread(0);
}

DWORD WINAPI dev_thread(LPVOID p)
{
	struct fd_info *fdi=p;
	struct usbip_header u;
	int ret;
	unsigned long len;
	HANDLE ev;
	OVERLAPPED ov;
	long x;
	ev=CreateEvent(NULL, FALSE, FALSE, NULL);
	ov.Offset=ov.OffsetHigh=0;
	ov.hEvent=ev;
	do {
		len=0;
		ret=ReadFile(fdi->dev, &u, sizeof(u), &len, &ov);
		if(!ret &&  (x=GetLastError())!=ERROR_IO_PENDING){
			err("read:%d x:%ld\n",ret, x);
			break;
		}
		if(!ret)
			WaitForSingleObject(ev, INFINITE);
		ret = GetOverlappedResult(fdi->dev,
			    &ov, &len, FALSE);
		if(!ret||len!=sizeof(u)){
			err("read dev ret:%d len:%ld\n",ret, len);
			break;
		}
		len=send(fdi->sock, (char *)&u, sizeof(u), 0);
		if(len!=sizeof(u)){
			err("send sock len:%ld\n", len);
			break;
		}
	} while(1);
	closesocket(fdi->sock);
	ExitThread(0);
}

void usbip_vbus_forward(SOCKET sockfd, HANDLE devfd)
{
	struct fd_info fdi;
	HANDLE t[2];
	fdi.sock=sockfd;
	fdi.dev=devfd;

	t[0]=CreateThread(NULL,0,dev_thread, &fdi, 0, NULL);
	if(t[0]==NULL)
		return;
	t[1]=CreateThread(NULL,0,sock_thread, &fdi, 0, NULL);
	if(NULL==t[0]){
		TerminateThread(t[0], 0);
		return;
	}
	WaitForMultipleObjects(2, t, TRUE, INFINITE);
}
