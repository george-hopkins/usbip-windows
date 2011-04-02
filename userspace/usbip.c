/*
	$Id$
*/
#include "usbip.h"
#include "getopt.h"
#define _GNU_SOURCE

static const char version[] = "usbip for windows ($Id$)";

int usbip_use_debug=0;
int usbip_use_syslog=0;
int usbip_use_stderr=1;

static const struct option longopts[] = {
	{"attach",	no_argument,	NULL, 'a'},
	{"attachall",	no_argument,	NULL, 'x'},
	{"detach",	no_argument,	NULL, 'd'},
	{"port",	no_argument,	NULL, 'p'},
	{"list",	no_argument,	NULL, 'l'},
	{"version",	no_argument,	NULL, 'v'},
	{"help",	no_argument,	NULL, 'h'},
	{"debug",	no_argument,	NULL, 'D'},
	{"syslog",	no_argument,	NULL, 'S'},
	{NULL,		0,		NULL,  0}
};

enum {
	CMD_ATTACH = 1,
	CMD_ATTACHALL,
	CMD_DETACH,
	CMD_PORT,
	CMD_LIST,
	CMD_HELP,
	CMD_VERSION
};

unsigned int parse_opt(int argc, char *argv[])
{
	int cmd = 0;

	for (;;) {
		int c;
		int index = 0;
		c = getopt_long(argc, argv, "adplvhDSx", longopts, &index);

		if (c == -1)
			break;

		switch(c) {
			case 'a':
				if (!cmd)
					cmd = CMD_ATTACH;
				else
					cmd = CMD_HELP;
				break;
			case 'd':
				if (!cmd)
					cmd = CMD_DETACH;
				else
					cmd = CMD_HELP;
				break;
			case 'p':
				if (!cmd)
					cmd = CMD_PORT;
				else
					cmd = CMD_HELP;
				break;
			case 'l':
				if (!cmd)
					cmd = CMD_LIST;
				else
					cmd = CMD_HELP;
				break;
			case 'v':
				if (!cmd)
					cmd = CMD_VERSION;
				else
					cmd = CMD_HELP;
				break;
			case 'x':
				if(!cmd)
					cmd = CMD_ATTACHALL;
				else
					cmd = CMD_HELP;
				break;
			case 'h':
				cmd = CMD_HELP;
				break;
			case 'D':
				usbip_use_debug = 1;
				break;
			case 'S':
				usbip_use_syslog = 1;
				break;
			case '?':
				break;
			default:
				err("getopt");
		}
	}
	if(!cmd)
		cmd = CMD_HELP;
	return cmd;
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

static void attach_device(char * host, char * busid)
{
	SOCKET sockfd;
	int rhport;
	HANDLE devfd=INVALID_HANDLE_VALUE;
	struct usb_interface uinf;

	sockfd = tcp_connect(host, USBIP_PORT_STRING);
	if (INVALID_SOCKET == sockfd) {
		err("tcp connect");
		return;
	}
	if(query_interface0(sockfd, busid, &uinf)){
		err("cannot find device");
		return;
	}
	closesocket(sockfd);
	sockfd = tcp_connect(host, USBIP_PORT_STRING);
	if (INVALID_SOCKET == sockfd) {
		err("tcp connect");
		return;
	}
	rhport = query_import_device(sockfd, busid, &uinf, &devfd);
	if (rhport < 0) {
		err("query");
		return;
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
	return;
}

const char help_message[] = "\
Usage: %s [options]				\n\
	-a, --attach [host] [bus_id]		\n\
		Attach a remote USB device.	\n\
						\n\
	-x, --attachall [host]		\n\
		Attach all remote USB devices on the specific host.	\n\
						\n\
	-d, --detach [ports]			\n\
		Detach an imported USB device.	\n\
						\n\
	-l, --list [hosts]			\n\
		List exported USB devices.	\n\
						\n\
	-p, --port				\n\
		List virtual USB port status. 	\n\
						\n\
	-D, --debug				\n\
		Print debugging information.	\n\
						\n\
	-v, --version				\n\
		Show version.			\n\
						\n\
	-h, --help 				\n\
		Print this help.		\n";

static void show_help(char *name)
{
	printf(help_message, name);
}

static int detach_port(char *port)
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

static int show_port_status(void)
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

static int query_exported_devices(SOCKET sockfd)
{
	int ret;
	struct op_devlist_reply rep;
	uint16_t code = OP_REP_DEVLIST;
	uint32_t i,j;
	char product_name[100];
	char class_name[100];
	struct usb_device udev;

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

		info("%8s: %s", udev.busid, product_name);
		info("%8s: %s", " ", udev.path);
		info("%8s: %s", " ", class_name);

		for (j=0; j < udev.bNumInterfaces; j++) {
			struct usb_interface uinf;

			ret = usbip_recv(sockfd, (void *) &uinf, sizeof(uinf));
			if (ret < 0) {
				err("recv usb_interface[%d]", j);
				return -1;
			}

			pack_usb_interface(0, &uinf);
			usbip_names_get_class(class_name, sizeof(class_name),
					uinf.bInterfaceClass,
					uinf.bInterfaceSubClass,
					uinf.bInterfaceProtocol);

			info("%8s: %2d - %s", " ", j, class_name);
		}

		info(" ");
	}
	return rep.ndev;
}

static void show_exported_devices(char *host)
{
	int ret;
	SOCKET sockfd;

	sockfd = tcp_connect(host, USBIP_PORT_STRING);
	if (INVALID_SOCKET == sockfd){
		info("- %s failed", host);
		return;
	}
	info("- %s", host);

	ret = query_exported_devices(sockfd);
	if (ret < 0) {
		err("query");
	}
	closesocket(sockfd);
}

static void attach_devices_all(char *host)
{
	return;
}

int
main(int argc, char *argv[])
{
	int cmd;
	info("%s\n",version);

	if(init_winsock()){
		err("can't init winsock");
		return 0;
	}
	cmd = parse_opt(argc, argv);

	switch(cmd) {
		case CMD_ATTACH:
			if (optind == argc - 2)
				attach_device(argv[optind], argv[optind+1]);
			else
				show_help(argv[0]);
			break;
		case CMD_DETACH:
			while (optind < argc)
				detach_port(argv[optind++]);
			break;
		case CMD_PORT:
			show_port_status();
			break;
		case CMD_LIST:
			while (optind < argc)
				show_exported_devices(argv[optind++]);
			break;
		case CMD_ATTACHALL:
			while(optind < argc)
				attach_devices_all(argv[optind++]);
			break;
		case CMD_VERSION:
			printf("%s\n", version);
			break;
		case CMD_HELP:
			show_help(argv[0]);
			break;
		default:
			show_help(argv[0]);
	}
	return 0;
}
