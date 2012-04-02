/*
 *
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#include "usbip.h"
#include "usbip_network.h"
#include "usbip_osspecific.h"

#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <winioctl.h>

int attach_devices_all(char *host)
{
	return 0;
}


#ifdef __GNUC__
#define INITGUID
#endif
#include "usbip.h"
#include "windows/usbip_windows_kernel_api.h"

#define BIG_SIZE 1000000
static char *dev_read_buf;
static char *sock_read_buf;

static char * usbip_vbus_dev_node_name(char *buf, unsigned long buf_len)
{
	HDEVINFO dev_info;
	SP_DEVICE_INTERFACE_DATA dev_interface_data;
	PSP_DEVICE_INTERFACE_DETAIL_DATA dev_interface_detail = NULL;
	unsigned long len;
	char *ret=NULL;

	dev_info = SetupDiGetClassDevs(
		(LPGUID) &GUID_DEVINTERFACE_BUSENUM_USBIP, /* ClassGuid */
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
		&GUID_DEVINTERFACE_BUSENUM_USBIP, /* InterfaceClassGuid */
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
	len=_snprintf(buf, buf_len, "%s", dev_interface_detail->DevicePath);
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

#ifdef DEBUG
static void usbip_dump_header(struct usbip_header *pdu)
{
	dbg_file("BASE: cmd %u seq %u devid %u dir %u ep %u\n",
			pdu->base.command,
			pdu->base.seqnum,
			pdu->base.devid,
			pdu->base.direction,
			pdu->base.ep);

	switch(pdu->base.command) {
		case USBIP_CMD_SUBMIT:
			dbg_file("CMD_SUBMIT: x_flags %u x_len %u sf %u #p %u iv %u\n",
					pdu->u.cmd_submit.transfer_flags,
					pdu->u.cmd_submit.transfer_buffer_length,
					pdu->u.cmd_submit.start_frame,
					pdu->u.cmd_submit.number_of_packets,
					pdu->u.cmd_submit.interval);
					break;
		case USBIP_CMD_UNLINK:
			dbg_file("CMD_UNLINK: seq %u\n", pdu->u.cmd_unlink.seqnum);
			break;
		case USBIP_RET_SUBMIT:
			dbg_file("RET_SUBMIT: st %d al %u sf %d #p %d ec %d\n",
					pdu->u.ret_submit.status,
					pdu->u.ret_submit.actual_length,
					pdu->u.ret_submit.start_frame,
					pdu->u.cmd_submit.number_of_packets,
					pdu->u.ret_submit.error_count);
			break;
		case USBIP_RET_UNLINK:
			dbg_file("RET_UNLINK: status %d\n", pdu->u.ret_unlink.status);
			break;
		default:
			/* NOT REACHED */
			dbg_file("UNKNOWN\n");
	}
}
#endif

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
	pdu->number_of_packets = ntohl(pdu->number_of_packets);
	pdu->error_count = ntohl(pdu->error_count);
}

static void correct_endian_cmd_submit(struct usbip_header_cmd_submit *pdu)
{
	pdu->transfer_flags	= ntohl(pdu->transfer_flags);
	pdu->transfer_buffer_length = ntohl(pdu->transfer_buffer_length);
	pdu->start_frame = ntohl(pdu->start_frame);
	pdu->number_of_packets = ntohl(pdu->number_of_packets);
	pdu->interval = ntohl(pdu->interval);
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
		case USBIP_CMD_SUBMIT:
			correct_endian_cmd_submit(&pdu->u.cmd_submit);
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
		err("read from sock ret %d not equal a usbip_header", len);
#ifdef DEBUG
		usbip_dump_buffer(buf,len);
#endif
		return -1;
	}
	if(usbip_header_correct_endian(u, 0)<0)
		return -1;
	dbg_file("recv seq %d\n", u->base.seqnum);
	if ((u->base.seqnum%100)==0)
		fprintf(stderr,"Receive sequence:    %d\r", u->base.seqnum);

#ifdef DEBUG
	usbip_dump_header(u);
#endif

	if(check_out(htonl(u->base.seqnum)))
		in_len=0;
	else
		in_len=u->u.ret_submit.actual_length;

	iso_len = u->u.ret_submit.number_of_packets
			* sizeof(struct usbip_iso_packet_descriptor);

	if(in_len==0&&iso_len==0){
		ret=WriteFile(devfd, (char *)u, sizeof(*u), &out, ov);
		if(!ret||out!=sizeof(*u)){
			err("last error:%ld",GetLastError());
			err("out:%ld ret:%d",out,ret);
			err("write dev failed");
			return -1;
		}
		return 0;
	}
	len = sizeof(*u) + in_len + iso_len;
	if(len>buf_len){
		err("too big len %d %ld %ld", len, in_len,iso_len);
		return -1;
	}
	ret=usbip_recv(sockfd, buf+sizeof(*u),
		in_len+iso_len);
	if(ret != in_len + iso_len){
		err("recv from sock failed %d %ld",
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
	int ret, err=0;
	unsigned long len;
	do {
		ret = ReadFile((HANDLE)sockfd,  sock_read_buf,
			sizeof(struct usbip_header), &len, ov_sock);
		if (!ret)
			err=GetLastError();

		if(err==ERROR_IO_PENDING)
			return 0;

		if(err) {
			err("read:%d err:%d\n",ret, err);
			return -1;
		}

		if (len!=sizeof(struct usbip_header))
		{
			err=GetLastError();
			err("incomplete header %d %d\n",ret,err);
		}

		dbg_file("Bytes read from socket synchronously: %d\n",len);
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
	dbg_file("Bytes read from socket asynchronously: %d\n",len);
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
		err("read dev len:%d out_len:%ld"
				    "iso_len: %ld\n",
			len, out_len, iso_len);
		return -1;
	}
	if(!u->base.direction&&!record_out(u->base.seqnum)){
		err("out q full");
		return -1;
	}
	dbg_file("send seq:%d\r", ntohl(u->base.seqnum));
//	fprintf(stderr,"Send sequence: %d\n",  ntohl(u->base.seqnum));



	ret=usbip_send(sockfd, buf, len);
	if(ret!=len){
		err("send sock len:%d, ret:%d\n", len, ret);
		return -1;
	}
	#ifdef DEBUG
	{
		struct usbip_header cu;
		memcpy(&cu,u,sizeof(struct usbip_header));
		usbip_header_correct_endian(&cu,0);
		usbip_dump_header(&cu);
	}
	#endif
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

volatile int signalflag=0;

void __cdecl signalhandler(int signal)
{
	signalflag=1;
	return;
}

void usbip_vbus_forward(SOCKET sockfd, HANDLE devfd)
{
	HANDLE ev[3];
	OVERLAPPED ov[3];
	int ret;
	int i;
	int err=0;

	dev_read_buf = malloc(BIG_SIZE);
	sock_read_buf = malloc(BIG_SIZE);

	if(dev_read_buf == NULL||sock_read_buf==NULL){
		err("cannot allocate buffers");
		return;
	}

	for(i=0;i<3;i++){
		ev[i]=CreateEvent(NULL, FALSE, FALSE, NULL);
		if(NULL==ev[i]){
			err("cannot create new events");
			return;
		}
		ov[i].Offset=ov[i].OffsetHigh=0;
		ov[i].hEvent=ev[i];
	}

	signal(SIGINT,signalhandler);

	dev_read_async(devfd, sockfd, &ov[0]);
	sock_read_async(sockfd, devfd, &ov[1], &ov[2]);

	do {
		dbg_file("wait\n");
		ret =  WaitForMultipleObjects(2, ev, FALSE, 100);
//		dbg_file("wait out %d\n", ret);

		switch (ret) {
		case WAIT_TIMEOUT:
			// do nothing just give CTRL-C a chance to be detected
			break;
		case WAIT_OBJECT_0:
			err=dev_read_completed(devfd, sockfd, &ov[0]);
			break;
		case WAIT_OBJECT_0 + 1:
			err=sock_read_completed(sockfd, devfd, &ov[1], &ov[2]);
			break;
		default:
			err("unknown ret %d\n",ret);
			err=ret;
			break;
		}
	} while(err==0&&!signalflag);
	
	info("\n");
	if (signalflag)
	{
		info("CTRL-C received\n");
	}
	free(dev_read_buf);
	free(sock_read_buf);
	return;
}


static int import_device(int sockfd, struct usb_device *udev,
		struct usb_interface *uinf0,
		HANDLE *devfd)
{
	HANDLE fd;
	int port, ret;

	fd = usbip_vbus_open();
	if (INVALID_HANDLE_VALUE == fd) {
		err("open vbus driver");
		return -1;
	}

	port = usbip_vbus_get_free_port(fd);
	if (port <= 0) {
		err("no free port");
		CloseHandle(fd);
		return -1;
	}

	dbg("call from attch here\n");
	ret = usbip_vbus_attach_device(fd, port, udev, uinf0);
	dbg("return from attch here\n");

	if (ret < 0) {
		err("import device");
		CloseHandle(fd);
		return -1;
	}
	dbg("devfd:%p\n",devfd);
	*devfd=fd;

	return port;
}

static int query_import_device(int sockfd, char *busid,
		struct usb_interface *uinf0, HANDLE * fd)
{
	int ret;
	struct op_import_request request;
	struct op_import_reply   reply;
	uint16_t code = OP_REP_IMPORT;

	memset(&request, 0, sizeof(request));
	memset(&reply, 0, sizeof(reply));

	/* send a request */
	ret = usbip_send_op_common(sockfd, OP_REQ_IMPORT, 0);
	if (ret < 0) {
		err("send op_common");
		return -1;
	}

	strncpy(request.busid, busid, sizeof(request.busid));
	request.busid[sizeof(request.busid)-1]=0;

	PACK_OP_IMPORT_REQUEST(0, &request);

	ret = usbip_send(sockfd, (void *) &request, sizeof(request));
	if (ret < 0) {
		err("send op_import_request");
		return -1;
	}

	/* recieve a reply */
	ret = usbip_recv_op_common(sockfd, &code);
	if (ret < 0) {
		err("recv op_common");
		return -1;
	}

	ret = usbip_recv(sockfd, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		err("recv op_import_reply");
		return -1;
	}

	PACK_OP_IMPORT_REPLY(0, &reply);

	/* check the reply */
	if (strncmp(reply.udev.busid, busid, sizeof(reply.udev.busid))) {
		err("recv different busid %s", reply.udev.busid);
		return -1;
	}

	/* import a device */
	return import_device(sockfd, &reply.udev, uinf0, fd);
}

static int query_interface0(SOCKET sockfd, char * busid, struct usb_interface * uinf0)
{
	int ret;
	struct op_devlist_reply rep;
	uint16_t code = OP_REP_DEVLIST;
	uint32_t i,j;
	char product_name[100];
	char class_name[100];
	struct usb_device udev;
	struct usb_interface uinf;
	int found=0;

	memset(&rep, 0, sizeof(rep));

	ret = usbip_send_op_common(sockfd, OP_REQ_DEVLIST, 0);
	if (ret < 0) {
		err("send op_common");
		return -1;
	}

	ret = usbip_recv_op_common(sockfd, &code);
	if (ret < 0) {
		err("recv op_common");
		return -1;
	}

	ret = usbip_recv(sockfd, (void *) &rep, sizeof(rep));
	if (ret < 0) {
		err("recv op_devlist");
		return -1;
	}

	PACK_OP_DEVLIST_REPLY(0, &rep);
	dbg("exportable %d devices", rep.ndev);

	for (i=0; i < rep.ndev; i++) {

		memset(&udev, 0, sizeof(udev));

		ret = usbip_recv(sockfd, (void *) &udev, sizeof(udev));
		if (ret < 0) {
			err("recv usb_device[%d]", i);
			return -1;
		}
		pack_usb_device(0, &udev);
		usbip_names_get_product(product_name, sizeof(product_name),
				udev.idVendor, udev.idProduct);
		usbip_names_get_class(class_name, sizeof(class_name), udev.bDeviceClass,
				udev.bDeviceSubClass, udev.bDeviceProtocol);

		dbg("%8s: %s", udev.busid, product_name);
		dbg("%8s: %s", " ", udev.path);
		dbg("%8s: %s", " ", class_name);

		for (j=0; j < udev.bNumInterfaces; j++) {

			ret = usbip_recv(sockfd, (void *) &uinf, sizeof(uinf));
			if (ret < 0) {
				err("recv usb_interface[%d]", j);
				return -1;
			}

			pack_usb_interface(0, &uinf);
			if(!strcmp(udev.busid, busid)&&j==0){
				memcpy(uinf0, &uinf, sizeof(uinf));
				found=1;
			}
			usbip_names_get_class(class_name, sizeof(class_name),
					uinf.bInterfaceClass,
					uinf.bInterfaceSubClass,
					uinf.bInterfaceProtocol);

			dbg("%8s: %2d - %s", " ", j, class_name);
		}

		dbg(" ");
	}
	if(found)
		return 0;
	return -1;
}

int attach_device(char * host, char * busid)
{
	SOCKET sockfd;
	int rhport;
	HANDLE devfd=INVALID_HANDLE_VALUE;
	struct usb_interface uinf;

	sockfd = tcp_connect(host, USBIP_PORT_STRING);
	if (INVALID_SOCKET == sockfd) {
		err("tcp connect");
		return 0;
	}
	if(query_interface0(sockfd, busid, &uinf)){
		err("cannot find device");
		return 0;
	}
	closesocket(sockfd);
	sockfd = tcp_connect(host, USBIP_PORT_STRING);
	if (INVALID_SOCKET == sockfd) {
		err("tcp connect");
		return 0;
	}
	rhport = query_import_device(sockfd, busid, &uinf, &devfd);
	if (rhport < 0) {
		err("query");
		return 0;
	}
	info("new usb device attached to usbvbus port %d\n", rhport);
	usbip_vbus_forward(sockfd, devfd);
	
	dbg("closing connection to device");
	CloseHandle(devfd);

	dbg("detaching device");
	usbip_vbus_detach_device(devfd,rhport);

	dbg("closing connection to peer");
	closesocket(sockfd);

	dbg("done");
	return 1;
}

int detach_port(char *port)
{
	signed char addr=atoi(port);
	HANDLE fd;
	int ret;

	fd = usbip_vbus_open();
	if (INVALID_HANDLE_VALUE == fd) {
		err("open vbus driver");
		return -1;
	}
	ret = usbip_vbus_detach_device(fd, addr);
	CloseHandle(fd);
	return ret;
}

int show_port_status(void)
{
	HANDLE fd;
	int i;
	char buf[128];

	fd = usbip_vbus_open();
	if (INVALID_HANDLE_VALUE == fd) {
		err("open vbus driver");
		return -1;
	}
	if(usbip_vbus_get_ports_status(fd, buf, sizeof(buf))){
		err("get port status");
		return -1;
	}
	info("max used port:%d\n", buf[0]);
	for(i=1; i<=buf[0]; i++){
		if(buf[i])
			info("port %d: used\n", i);
		else
			info("port %d: idle\n", i);
	}
	CloseHandle(fd);
	return 0;
}

int init_socket()
{
    WSADATA wsaData;
    int err;

    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0) {
        err("WSAStartup failed with error: %d\n", err);
        return -1;
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        err("Could not find a usable version of Winsock.dll\n");
        WSACleanup();
        return -1;
    }
	return 0;
}

int cleanup_socket()
{
	WSACleanup();
	return 0;
}