#include <stdio.h>
extern int usbip_use_stderr;
extern int usbip_use_debug;

#define err(fmt, args...)	do { \
	if (usbip_use_stderr) { \
		fprintf(stderr, "usbip err: %13s:%4d (%-12s) " fmt "\n", \
			__FILE__, __LINE__, __FUNCTION__,  ##args); \
	} \
} while (0)

#define notice(fmt, args...)	do { \
	if (usbip_use_stderr) { \
		fprintf(stderr, "usbip: " fmt "\n",  ##args); \
	} \
} while (0)

#define info(fmt, args...)	do { \
	if (usbip_use_stderr) { \
		fprintf(stderr, fmt "\n",  ##args); \
	} \
} while (0)

#define dbg(fmt, args...)	do { \
	if (usbip_use_debug) { \
		if (usbip_use_stderr) { \
			fprintf(stderr, "usbip dbg: %13s:%4d (%-12s) " fmt "\n", \
				__FILE__, __LINE__, __FUNCTION__,  ##args); \
		} \
	} \
} while (0)
