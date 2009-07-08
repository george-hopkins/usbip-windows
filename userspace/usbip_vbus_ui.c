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

#define BIG_SIZE 10000000
static char *dev_read_buf;
static char *sock_read_buf;

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
	plugin.speed = udev->speed;
	plugin.inum = udev->bNumInterfaces;
	plugin.int0_class = uinf0->bInterfaceClass;
	plugin.int0_subclass = uinf0->bInterfaceSubClass;
	plugin.int0_protocol = uinf0->bInterfaceProtocol;
	plugin.addr = port;

	ret = DeviceIoControl(fd, IOCTL_USBVBUS_PLUGIN_HARDWARE,
				&plugin, sizeof(plugin), NULL, 0, &unused, NULL);
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

int usbip_header_correct_endian(struct usbip_header *pdu, int send)
{
	unsigned int cmd = 0;

	if (send)
		cmd = pdu->base.command;

	correct_endian_basic(&pdu->base, send);

	if (!send)
		cmd = pdu->base.command;

	switch (cmd) {
		case USBIP_RESET_DEV:
			break;
		case USBIP_RET_SUBMIT:
			correct_endian_ret_submit(&pdu->u.ret_submit);
			break;
		default:
			/* NOTREACHED */
			err("unknown command in pdu header: %d", cmd);
			return -1;
			//BUG();
	}
	return 0;
}

#define OUT_Q_LEN 256
static long out_q_seqnum_array[OUT_Q_LEN];

int record_out(long num)
{
	int i;
	for(i=0;i<OUT_Q_LEN;i++){
		if(out_q_seqnum_array[i])
			continue;
		out_q_seqnum_array[i]=num;
		return 1;
	}
	return 0;
}

int check_out(unsigned long num)
{
	int i;
	for(i=0;i<OUT_Q_LEN;i++){
		if(out_q_seqnum_array[i]!=num)
			continue;
		out_q_seqnum_array[i]=0;
		return 1;
	}
	return 0;
}

void fix_iso_desc_endian(char *buf, int num)
{
	struct usbip_iso_packet_descriptor * ip_desc;
	int i;
	int all=0;
	ip_desc = (struct usbip_iso_packet_descriptor *) buf;
	for(i=0;i<num;i++){
		ip_desc->offset = ntohl(ip_desc->offset);
		ip_desc->status = ntohl(ip_desc->status);
		ip_desc->length = ntohl(ip_desc->length);
		ip_desc->actual_length = ntohl(ip_desc->actual_length);
		all+=ip_desc->actual_length;
		ip_desc++;
	}
}

#ifdef DEBUG
void dbg_file(char *fmt, ...)
{
	static FILE *fp=NULL;
	va_list ap;
	if(fp==NULL){
		fp=fopen("debug.log", "w");
	}
	if(NULL==fp)
		return;
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	fflush(fp);
	return;
}
#else
void dbg_file(char *fmt, ...)
{
	return;
}
#endif

int write_to_dev(char * buf, int buf_len, int len, SOCKET sockfd,
		HANDLE devfd, OVERLAPPED *ov)
{
	int ret;
	unsigned long out=0, in_len, iso_len;
	struct usbip_header * u = (struct usbip_header *)buf;

	if(len!=sizeof(*u)){
		err("read from sock ret %d not equal a usbip_header\n", len);
		return -1;
	}
	if(usbip_header_correct_endian(u, 0)<0)
		return -1;
	dbg_file("recv seq %d\n", u->base.seqnum);
	//	usbip_dump_header(&u);
	if(check_out(htonl(u->base.seqnum)))
		in_len=0;
	else
		in_len=u->u.ret_submit.actual_length;

	iso_len = u->u.ret_submit.number_of_packets
			* sizeof(struct usbip_iso_packet_descriptor);

	if(in_len==0&&iso_len==0){
		ret=WriteFile(devfd, (char *)u, sizeof(*u), &out, ov);
		if(!ret||out!=sizeof(*u)){
			err("last error:%ld\n",GetLastError());
			err("out:%ld ret:%d\n",out,ret);
			err("write dev failed");
			return -1;
		}
		return 0;
	}
	len = sizeof(*u) + in_len + iso_len;
	if(len>buf_len){
		err("too big len %d", len);
		return -1;
	}
	ret=usbip_recv(sockfd, buf+sizeof(*u),
		in_len+iso_len);
	if(ret != in_len + iso_len){
		err("recv from sock failed %d %ld\n",
				ret,
				in_len + iso_len);
		return -1;
	}
	if(iso_len)
		fix_iso_desc_endian(sock_read_buf+sizeof(*u)+in_len,
					u->u.ret_submit.number_of_packets);
	ret=WriteFile(devfd, buf, len, &out, ov);
	if(!ret||out!=len){
		err("last error:%ld\n",GetLastError());
		err("out:%ld ret:%d len:%d\n",out,ret,len);
		err("write dev failed");
		return -1;
	}
	return 0;
}

int sock_read_async(SOCKET sockfd, HANDLE devfd, OVERLAPPED *ov_sock,
		OVERLAPPED *ov_dev)
{
	int ret, x;
	unsigned long len;
	do {
		ret = ReadFile((HANDLE)sockfd,  sock_read_buf,
			sizeof(struct usbip_header), &len, ov_sock);
		if(!ret &&  (x=GetLastError())!=ERROR_IO_PENDING) {
			err("read:%d x:%d\n",ret, x);
			return -1;
		}
		if(!ret)
			return 0;
		ret = write_to_dev(sock_read_buf, BIG_SIZE, len,
				sockfd, devfd, ov_dev);
		if(ret<0)
			return -1;
	}while(1);
}

int sock_read_completed(SOCKET sockfd, HANDLE devfd, OVERLAPPED *ov_sock,
		OVERLAPPED *ov_dev)
{

	int ret;
	unsigned long len;
	ret = GetOverlappedResult((HANDLE)sockfd, ov_sock, &len, FALSE);
	if(!ret){
		err("get overlapping failed: %ld", GetLastError());
		return -1;
	}
	ret = write_to_dev(sock_read_buf, BIG_SIZE, len, sockfd, devfd, ov_dev);
	if(ret<0)
		return -1;
	return sock_read_async(sockfd, devfd, ov_sock, ov_dev);
}

int write_to_sock(char *buf, int len, SOCKET sockfd)
{
	struct usbip_header *u;
	int ret;
	unsigned long out_len, iso_len;

	u=(struct usbip_header *)buf;

	if(len<sizeof(*u)){
		err("read dev len: %d\n", len);
		return -1;
	}
	if(!u->base.direction)
		out_len=ntohl(u->u.cmd_submit.transfer_buffer_length);
	else
		out_len=0;
	if(u->u.cmd_submit.number_of_packets)
		iso_len=sizeof(struct usbip_iso_packet_descriptor)*
			ntohl(u->u.cmd_submit.number_of_packets);
	else
		iso_len=0;
	if(len!= sizeof(*u) + out_len + iso_len){
		err("read dev ret:%d len:%d out_len:%ld"
				    "iso_len: %ld\n",
			ret, len, out_len, iso_len);
		return -1;
	}
	if(!u->base.direction&&!record_out(u->base.seqnum)){
		err("out q full");
		return -1;
	}
	dbg_file("send seq:%d\n", ntohl(u->base.seqnum));
	ret=usbip_send(sockfd, buf, len);
	if(ret!=len){
		err("send sock len:%d, ret:%d\n", len, ret);
		return -1;
	}
	return 0;
}

int dev_read_async(HANDLE devfd, SOCKET sockfd, OVERLAPPED *ov)
{
	int ret, x;
	unsigned long len;

	do {
		len=0;
		ret = ReadFile(devfd, dev_read_buf, BIG_SIZE, &len, ov);
		if(!ret &&  (x=GetLastError())!=ERROR_IO_PENDING) {
			err("read:%d x:%d\n",ret, x);
			return -1;
		}
		if(!ret)
			return 0;
		ret = write_to_sock(dev_read_buf, len, sockfd);
		if(ret<0)
			return -1;
	} while(1);
}

int dev_read_completed(HANDLE devfd, SOCKET sockfd, OVERLAPPED *ov)
{
	int ret;
	unsigned long len;
	ret = GetOverlappedResult(devfd, ov, &len, FALSE);
	if(!ret){
		err("get overlapping failed: %ld", GetLastError());
		return -1;
	}
	ret = write_to_sock(dev_read_buf, len, sockfd);
	if(ret<0)
		return -1;
	return dev_read_async(devfd, sockfd, ov);
}

void usbip_vbus_forward(SOCKET sockfd, HANDLE devfd)
{
	HANDLE ev[3];
	OVERLAPPED ov[3];
	int ret;
	int i;

	dev_read_buf = malloc(BIG_SIZE);
	sock_read_buf = malloc(BIG_SIZE);

	if(dev_read_buf == NULL||sock_read_buf==NULL){
		err("faint.can't malloc");
		return;
	}

	for(i=0;i<3;i++){
		ev[i]=CreateEvent(NULL, FALSE, FALSE, NULL);
		if(NULL==ev[i]){
			err("can't new event");
			return;
		}
		ov[i].Offset=ov[i].OffsetHigh=0;
		ov[i].hEvent=ev[i];
	}
	dev_read_async(devfd, sockfd, &ov[0]);
	sock_read_async(sockfd, devfd, &ov[1], &ov[2]);

	do {
		dbg_file("wait\n");
		ret =  WaitForMultipleObjects(2, ev, FALSE, INFINITE);
		dbg_file("wait out %d\n", ret);

		switch (ret){
		case WAIT_OBJECT_0:
			if(dev_read_completed(devfd, sockfd, &ov[0]))
				return;
			break;
		case WAIT_OBJECT_0 + 1:
			if(sock_read_completed(sockfd, devfd, &ov[1], &ov[2]))
				return;
			break;
		default:
			err("unknown ret %d\n",ret);
			return;
		}
	} while(1);
	/* FIXME free resouce */
}
