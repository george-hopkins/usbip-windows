/*
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#ifndef _USBIP_COMMON_H
#define _USBIP_COMMON_H

#ifdef __GNUC__
#define PACKED __attribute__((__packed__))
#else
#pragma pack(push,1)
#define PACKED /* */
#endif


#ifndef USBIDS_FILE
#define USBIDS_FILE "/usr/share/hwdata/usb.ids"
#endif

#ifndef VHCI_STATE_PATH
#define VHCI_STATE_PATH "/var/run/vhci_hcd"
#endif

enum usb_device_speed {
	USB_SPEED_UNKNOWN = 0,                  /* enumerating */
	USB_SPEED_LOW, USB_SPEED_FULL,          /* usb 1.1 */
	USB_SPEED_HIGH,                         /* usb 2.0 */
	USB_SPEED_VARIABLE                      /* wireless (usb 2.5) */
};

/* FIXME: how to sync with drivers/usbip_common.h ? */
enum usbip_device_status{
	/* sdev is available. */
	SDEV_ST_AVAILABLE = 0x01,
	/* sdev is now used. */
	SDEV_ST_USED,
	/* sdev is unusable because of a fatal error. */
	SDEV_ST_ERROR,

	/* vdev does not connect a remote device. */
	VDEV_ST_NULL,
	/* vdev is used, but the USB address is not assigned yet */
	VDEV_ST_NOTASSIGNED,
	VDEV_ST_USED,
	VDEV_ST_ERROR
};

extern int usbip_use_syslog;
extern int usbip_use_stderr;
extern int usbip_use_debug ;


#define err(fmt, ...)	do { \
	if (usbip_use_syslog) { \
		syslog(LOG_ERR, "usbip err: %13s:%4d (%-12s) " fmt "\n", \
		__FILE__, __LINE__, __FUNCTION__,  ##__VA_ARGS__); \
	} \
	if (usbip_use_stderr) { \
		fprintf(stderr, "usbip err: %13s:%4d (%-12s) " fmt "\n", \
		__FILE__, __LINE__, __FUNCTION__,  ##__VA_ARGS__); \
	} \
} while (0)

#define notice(fmt, ...)	do { \
	if (usbip_use_syslog) { \
		syslog(LOG_DEBUG, "usbip: " fmt, ##__VA_ARGS__); \
	} \
	if (usbip_use_stderr) { \
		fprintf(stderr, "usbip: " fmt "\n", ##__VA_ARGS__); \
	} \
} while (0)

#define info(fmt, ...)	do { \
	if (usbip_use_syslog) { \
		syslog(LOG_DEBUG, fmt, ##__VA_ARGS__); \
	} \
	if (usbip_use_stderr) { \
		fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
	} \
} while (0)

#define dbg(fmt, ...)	do { \
	if (usbip_use_debug) { \
		if (usbip_use_syslog) { \
			syslog(LOG_DEBUG, "usbip dbg: %13s:%4d (%-12s) " fmt, \
				__FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
		} \
		if (usbip_use_stderr) { \
			fprintf(stderr, "usbip dbg: %13s:%4d (%-12s) " fmt "\n", \
				__FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
		} \
	} \
} while (0)

#define BUG()	do { err("sorry, it's a bug"); abort(); } while (0)


struct usb_interface {
	uint8_t bInterfaceClass;
	uint8_t bInterfaceSubClass;
	uint8_t bInterfaceProtocol;
	uint8_t padding;	/* alignment */
} PACKED;



struct usb_device {
	char path[SYSFS_PATH_MAX];
	char busid[SYSFS_BUS_ID_SIZE];

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
} PACKED;

/*
 * USB/IP request headers.
 * Currently, we define 4 request types:
 *
 *  - CMD_SUBMIT transfers a USB request, corresponding to usb_submit_urb().
 *    (client to server)
 *  - RET_RETURN transfers the result of CMD_SUBMIT.
 *    (server to client)
 *  - CMD_UNLINK transfers an unlink request of a pending USB request.
 *    (client to server)
 *  - RET_UNLINK transfers the result of CMD_UNLINK.
 *    (server to client)
 *
 * Note: The below request formats are based on the USB subsystem of Linux. Its
 * details will be defined when other implementations come.
 *
 *
 */


typedef uint32_t __u32;
typedef int32_t __s32;

/*
 * A basic header followed by other additional headers.
 */
struct usbip_header_basic {
#define USBIP_CMD_SUBMIT	0x0001
#define USBIP_CMD_UNLINK	0x0002
#define USBIP_RET_SUBMIT	0x0003
#define USBIP_RET_UNLINK	0x0004
	__u32 command;

	 /* sequential number which identifies requests.
	  * incremented per connections */
	__u32 seqnum;

	/* devid is used to specify a remote USB device uniquely instead
	 * of busnum and devnum in Linux. In the case of Linux stub_driver,
	 * this value is ((busnum << 16) | devnum) */
	__u32 devid;

#define USBIP_DIR_OUT	0
#define USBIP_DIR_IN	1
	__u32 direction;
	__u32 ep;     /* endpoint number */
} PACKED;

/*
 * An additional header for a CMD_SUBMIT packet.
 */
struct usbip_header_cmd_submit {
	/* these values are basically the same as in a URB. */

	/* the same in a URB. */
	__u32 transfer_flags;

	/* set the following data size (out),
	 * or expected reading data size (in) */
	__s32 transfer_buffer_length;

	/* it is difficult for usbip to sync frames (reserved only?) */
	__s32 start_frame;

	/* the number of iso descriptors that follows this header */
	__s32 number_of_packets;

	/* the maximum time within which this request works in a host
	 * controller of a server side */
	__s32 interval;

	/* set setup packet data for a CTRL request */
	unsigned char setup[8];
} PACKED;

/*
 * An additional header for a RET_SUBMIT packet.
 */
struct usbip_header_ret_submit {
	__s32 status;
	__s32 actual_length;		/* returned data length */
	__s32 start_frame;		/* ISO and INT */
	__s32 number_of_packets;	/* ISO only */
	__s32 error_count;		/* ISO only */
} PACKED;

/*
 * An additional header for a CMD_UNLINK packet.
 */
struct usbip_header_cmd_unlink {
	__u32 seqnum;			/* URB's seqnum that will be unlinked */
} PACKED;

/*
 * An additional header for a RET_UNLINK packet.
 */
struct usbip_header_ret_unlink {
	__s32 status;
} PACKED;

/* the same as usb_iso_packet_descriptor but packed for pdu */
struct usbip_iso_packet_descriptor {
	__u32 offset;
	__u32 length;			/* expected length */
	__u32 actual_length;
	__u32 status;
} PACKED;

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
} PACKED;


#define to_string(s)	#s

void dump_usb_interface(struct usb_interface *);
void dump_usb_device(struct usb_device *);
int read_usb_device(struct sysfs_device *sdev, struct usb_device *udev);
int read_attr_value(struct sysfs_device *dev, const char *name, const char *format);
int read_usb_interface(struct usb_device *udev, int i, struct usb_interface *uinf);

const char *usbip_speed_string(int num);
const char *usbip_status_string(int32_t status);

int usbip_names_init(char *);
void usbip_names_free(void);
void usbip_names_get_product(char *buff, size_t size, uint16_t vendor, uint16_t product);
void usbip_names_get_class(char *buff, size_t size, uint8_t class, uint8_t subclass, uint8_t protocol);

#ifdef __GNUC__
#else
#pragma pack(pop)
#endif

#endif
