/*
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#ifndef _USBIP_PROTOCOL_H
#define _USBIP_PROTOCOL_H

#include <stdint.h>

#define USBIP_VERSION 0x000106

/* -------------------------------------------------- */
/* Define Protocol Format                             */
/* -------------------------------------------------- */


/* ---------------------------------------------------------------------- */
/* Common header for all the kinds of PDUs. */
struct op_common {
	uint16_t version;

#define OP_REQUEST	(0x80 << 8)
#define OP_REPLY	(0x00 << 8)
	uint16_t code;

	/* add more error code */
#define ST_OK	0x00
#define ST_NA	0x01
	uint32_t status; /* op_code status (for reply) */

} __attribute__((packed));

#define PACK_OP_COMMON(pack, op_common)  do {\
	pack_uint16_t(pack, &(op_common)->version);\
	pack_uint16_t(pack, &(op_common)->code   );\
	pack_uint32_t(pack, &(op_common)->status );\
} while (0)

/* ---------------------------------------------------------------------- */
/* Dummy Code */
#define OP_UNSPEC	0x00
#define OP_REQ_UNSPEC	OP_UNSPEC
#define OP_REP_UNSPEC	OP_UNSPEC

/* ---------------------------------------------------------------------- */
/* Retrieve USB device information. (still not used) */
#define OP_DEVINFO	0x02
#define OP_REQ_DEVINFO	(OP_REQUEST | OP_DEVINFO)
#define OP_REP_DEVINFO	(OP_REPLY   | OP_DEVINFO)

#define USBIP_BUS_ID_SIZE 32
#define USBIP_DEV_PATH_MAX 256

struct op_devinfo_request {
	char busid[USBIP_BUS_ID_SIZE];
} __attribute__((packed));

enum usb_device_speed {
	USB_SPEED_UNKNOWN = 0,                  /* enumerating */
	USB_SPEED_LOW, USB_SPEED_FULL,          /* usb 1.1 */
	USB_SPEED_HIGH,                         /* usb 2.0 */
	USB_SPEED_VARIABLE                      /* wireless (usb 2.5) */
};

struct usb_device {
	char path[USBIP_DEV_PATH_MAX];
	char busid[USBIP_BUS_ID_SIZE];
	uint32_t busnum;
	uint32_t devnum;
	uint32_t speed;

	uint16_t idVendor;
	uint16_t idProduct;
	uint16_t bcdDevice;

	uint8_t bDeviceClass;
	uint8_t bDeviceSubClass;
	uint8_t bDeviceProtocol;
	uint8_t bConfigurationValue;
	uint8_t bNumConfigurations;
	uint8_t bNumInterfaces;
} __attribute__((packed));

struct usb_interface {
	uint8_t bInterfaceClass;
	uint8_t bInterfaceSubClass;
	uint8_t bInterfaceProtocol;
	uint8_t padding;	/* alignment */
} __attribute__((packed));

struct op_devinfo_reply {
	struct usb_device udev;
	struct usb_interface uinf[];
} __attribute__((packed));


/* ---------------------------------------------------------------------- */
/* Import a remote USB device. */
#define OP_IMPORT	0x03
#define OP_REQ_IMPORT	(OP_REQUEST | OP_IMPORT)
#define OP_REP_IMPORT   (OP_REPLY   | OP_IMPORT)

struct op_import_request {
	char busid[USBIP_BUS_ID_SIZE];
} __attribute__((packed));

struct op_import_reply {
	struct usb_device udev;
//	struct usb_interface uinf[];
} __attribute__((packed));

#define PACK_OP_IMPORT_REQUEST(pack, request)  do {\
} while (0)

#define PACK_OP_IMPORT_REPLY(pack, reply)  do {\
	pack_usb_device(pack, &(reply)->udev);\
} while (0)



/* ---------------------------------------------------------------------- */
/* Export a USB device to a remote host. */
#define OP_EXPORT	0x06
#define OP_REQ_EXPORT	(OP_REQUEST | OP_EXPORT)
#define OP_REP_EXPORT	(OP_REPLY   | OP_EXPORT)

struct op_export_request {
	struct usb_device udev;
} __attribute__((packed));

struct op_export_reply {
	int returncode;
} __attribute__((packed));


#define PACK_OP_EXPORT_REQUEST(pack, request)  do {\
	pack_usb_device(pack, &(request)->udev);\
} while (0)

#define PACK_OP_EXPORT_REPLY(pack, reply)  do {\
} while (0)

/* ---------------------------------------------------------------------- */
/* un-Export a USB device from a remote host. */
#define OP_UNEXPORT	0x07
#define OP_REQ_UNEXPORT	(OP_REQUEST | OP_UNEXPORT)
#define OP_REP_UNEXPORT	(OP_REPLY   | OP_UNEXPORT)

struct op_unexport_request {
	struct usb_device udev;
} __attribute__((packed));

struct op_unexport_reply {
	int returncode;
} __attribute__((packed));

#define PACK_OP_UNEXPORT_REQUEST(pack, request)  do {\
	pack_usb_device(pack, &(request)->udev);\
} while (0)

#define PACK_OP_UNEXPORT_REPLY(pack, reply)  do {\
} while (0)



/* ---------------------------------------------------------------------- */
/* Negotiate IPSec encryption key. (still not used) */
#define OP_CRYPKEY	0x04
#define OP_REQ_CRYPKEY	(OP_REQUEST | OP_CRYPKEY)
#define OP_REP_CRYPKEY	(OP_REPLY   | OP_CRYPKEY)

struct op_crypkey_request {
	/* 128bit key */
	uint32_t key[4];
} __attribute__((packed));

struct op_crypkey_reply {
	uint32_t __reserved;
} __attribute__((packed));


/* ---------------------------------------------------------------------- */
/* Retrieve the list of exported USB devices. */
#define OP_DEVLIST	0x05
#define OP_REQ_DEVLIST	(OP_REQUEST | OP_DEVLIST)
#define OP_REP_DEVLIST	(OP_REPLY   | OP_DEVLIST)

struct op_devlist_request {
} __attribute__((packed));

struct op_devlist_reply {
	uint32_t ndev;
	/* followed by reply_extra[] */
} __attribute__((packed));

struct op_devlist_reply_extra {
	struct usb_device    udev;
	struct usb_interface uinf[];
} __attribute__((packed));

#define PACK_OP_DEVLIST_REQUEST(pack, request)  do {\
} while (0)

#define PACK_OP_DEVLIST_REPLY(pack, reply)  do {\
	pack_uint32_t(pack, &(reply)->ndev);\
} while (0)

/*
 * A basic header followed by other additional headers.
 */
struct usbip_header_basic {
#define USBIP_CMD_SUBMIT	0x0001
#define USBIP_CMD_UNLINK	0x0002
#define USBIP_RET_SUBMIT	0x0003
#define USBIP_RET_UNLINK	0x0004
#define USBIP_RESET_DEV		0xFFFF
	unsigned int command;

	 /* sequencial number which identifies requests.
	  * incremented per connections */
	unsigned int seqnum;

	/* devid is used to specify a remote USB device uniquely instead
	 * of busnum and devnum in Linux. In the case of Linux stub_driver,
	 * this value is ((busnum << 16) | devnum) */
	unsigned int devid;  

#define USBIP_DIR_OUT	0
#define USBIP_DIR_IN 	1
	unsigned int direction;
	unsigned int ep;     /* endpoint number */
} __attribute__ ((packed));

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
}__attribute__ ((packed));

/*
 * An additional header for a RET_SUBMIT packet.
 */
struct usbip_header_ret_submit {
	int status;
	int actual_length; /* returned data length */
	int start_frame; /* ISO and INT */
	int number_of_packets;  /* ISO only */
	int error_count; /* ISO only */
}__attribute__ ((packed));

/*
 * An additional header for a CMD_UNLINK packet.
 */
struct usbip_header_cmd_unlink {
	unsigned int seqnum; /* URB's seqnum which will be unlinked */
}__attribute__ ((packed));


/*
 * An additional header for a RET_UNLINK packet.
 */
struct usbip_header_ret_unlink {
	int status;
}__attribute__ ((packed));


/* the same as usb_iso_packet_descriptor but packed for pdu */
struct usbip_iso_packet_descriptor {
	unsigned int offset;
	unsigned int length;            /* expected length */
	unsigned int actual_length;
	unsigned int status;
}__attribute__ ((packed));


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
}__attribute__ ((packed));




/* -------------------------------------------------- */
/* Declare Prototype Function                         */
/* -------------------------------------------------- */

void pack_uint32_t(int pack, uint32_t *num);
void pack_uint16_t(int pack, uint16_t *num);
void pack_usb_device(int pack, struct usb_device *udev);
void pack_usb_interface(int pack, struct usb_interface *uinf);

#define USBIP_PORT 3240
#define USBIP_PORT_STRING "3240"

#endif
