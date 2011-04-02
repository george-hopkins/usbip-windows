extern int usbip_use_stderr;
extern int usbip_use_debug;

#ifdef _MSC_VER 

#ifdef DEBUG
#define err(fmt, ...)	do { \
	if (usbip_use_stderr) { \
		fprintf(stderr, "usbip err: %13s:%4d (%-12s) " fmt "\n", \
			__FILE__, __LINE__, __FUNCTION__,  __VA_ARGS__); \
	} \
} while (0)
#else
#define err(fmt, ...)	do { \
	if (usbip_use_stderr) { \
		fprintf(stderr, "*** ERROR: " fmt "\n", \
			__VA_ARGS__); \
	} \
} while (0)
#endif

#define notice(fmt, ...)	do { \
	if (usbip_use_stderr) { \
		fprintf(stderr, "usbip: " fmt "\n",  __VA_ARGS__); \
	} \
} while (0)

#define info(fmt, ...)	do { \
	if (usbip_use_stderr) { \
		fprintf(stderr, fmt "\n",  __VA_ARGS__); \
	} \
} while (0)

#define dbg(fmt, ...)	do { \
	if (usbip_use_debug) { \
		if (usbip_use_stderr) { \
			fprintf(stderr, "usbip dbg: %13s:%4d (%-12s) " fmt "\n", \
				__FILE__, __LINE__, __FUNCTION__,  __VA_ARGS__); \
		} \
	} \
} while (0)

extern void dbg_file(char *fmt, ...);

#else

#ifdef DEBUG
#define err(fmt, args...)	do { \
		fprintf(stderr, "usbip err: %13s:%4d (%-12s) " fmt "\n", \
			__FILE__, __LINE__, __FUNCTION__,  ##args); \
} while (0)
#else
#define err(fmt, args...)	do { \
		fprintf(stderr, "*** ERROR: " fmt "\n", \
			##args); \
} while (0)
#endif

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

extern void dbg_file(char *fmt, ...);

#endif
