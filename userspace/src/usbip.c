/*
 *
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#include "usbip.h"
#include "usbip_network.h"
#include "usbip_osspecific.h"
#include <getopt.h>

static const char version[] = PACKAGE_STRING;


int show_exported_devices(char *host);


const char help_message[] = "\
Usage: usbip [options]				\n\
	-a, --attach [host] [bus_id]		\n\
		Attach a remote USB device.	\n\
						\n"
#ifdef __linux__
"	-x, --attachall [host]		\n\
		Attach all remote USB devices on the specific host.	\n\
						\n"
#endif
"	-d, --detach [ports]			\n\
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

static void show_help(void)
{
	printf("%s", help_message);
}

static const struct option longopts[] = {
	{"attach",	no_argument,	NULL, 'a'},
#ifdef __linux__
	{"attachall",	no_argument,	NULL, 'x'},
#endif
	{"detach",	no_argument,	NULL, 'd'},
	{"port",	no_argument,	NULL, 'p'},
	{"list",	no_argument,	NULL, 'l'},
	{"version",	no_argument,	NULL, 'v'},
	{"help",	no_argument,	NULL, 'h'},
	{"debug",	no_argument,	NULL, 'D'},
	{"syslog",	no_argument,	NULL, 'S'},
	{NULL,		0,		NULL,  0}
};

int main(int argc, char *argv[])
{
	int ret;

	enum {
		cmd_attach = 1,
		cmd_attachall,
		cmd_detach,
		cmd_port,
		cmd_list,
		cmd_help,
		cmd_version
	} cmd = 0;

	usbip_use_stderr = 1;

#ifdef __linux__
	if (geteuid() != 0)
		notice("running non-root?");
#endif

	if (init_socket())
		return EXIT_FAILURE;

 	ret = usbip_names_init(USBIDS_FILE);
 	if (ret)
 		notice("failed to open %s", USBIDS_FILE);

	for (;;) {
		int c;
		int index = 0;

		c = getopt_long(argc, argv, "adplvhDSx", longopts, &index);

		if (c == -1)
			break;

		switch(c) {
			case 'a':
				if (!cmd)
					cmd = cmd_attach;
				else
					cmd = cmd_help;
				break;
			case 'd':
				if (!cmd)
					cmd = cmd_detach;
				else
					cmd = cmd_help;
				break;
			case 'p':
				if (!cmd)
					cmd = cmd_port;
				else cmd = cmd_help;
				break;
			case 'l':
				if (!cmd)
					cmd = cmd_list;
				else
					cmd = cmd_help;
				break;
			case 'v':
				if (!cmd)
					cmd = cmd_version;
				else
					cmd = cmd_help;
				break;
#ifdef __linux__
			case 'x':
				if(!cmd)
					cmd = cmd_attachall;
				else
					cmd = cmd_help;
				break;
#endif
			case 'h':
				cmd = cmd_help;
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

	ret = 0;
	switch(cmd) {
		case cmd_attach:
			if (optind == argc - 2)
				ret = attach_device(argv[optind], argv[optind+1]);
			else
				show_help();
			break;
		case cmd_detach:
			while (optind < argc)
				ret = detach_port(argv[optind++]);
			break;
		case cmd_port:
			ret = show_port_status();
			break;
		case cmd_list:
			while (optind < argc)
				ret = show_exported_devices(argv[optind++]);
			break;
		case cmd_attachall:
			while(optind < argc)
				ret = attach_devices_all(argv[optind++]);
			break;
		case cmd_version:
			printf("%s\n", version);
			break;
		case cmd_help:
			show_help();
			break;
		default:
			show_help();
	}


	usbip_names_free();
	
	cleanup_socket();

	exit((ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
}

static int query_exported_devices(int sockfd)
{
	int ret;
	unsigned int i;
	int j;
	struct op_devlist_reply rep;
	uint16_t code = OP_REP_DEVLIST;

	memset(&rep, '\0', sizeof(rep));

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
		char product_name[100];
		char class_name[100];
		struct usb_device udev;

		memset(&udev, '\0', sizeof(udev));

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
			usbip_names_get_class(class_name, sizeof(class_name), uinf.bInterfaceClass,
					uinf.bInterfaceSubClass, uinf.bInterfaceProtocol);

			info("%8s: %2d - %s", " ", j, class_name);
		}

		info(" ");
	}

	return rep.ndev;
}

int show_exported_devices(char *host)
{
	int ret;
	int sockfd;

	sockfd = tcp_connect(host, USBIP_PORT_STRING);
	if (sockfd < 0) {
		err("- %s failed", host);
		return -1;
	}

	info("- %s", host);

	ret = query_exported_devices(sockfd);
	if (ret < 0) {
		err("query");
		return -1;
	}

	closesocket(sockfd);
	return 0;
}

