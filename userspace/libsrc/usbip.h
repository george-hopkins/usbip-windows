/*
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#ifndef _USBIP_H
#define _USBIP_H

#include "../config.h"

#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>

#define UNUSED(x) (void)(x)

#ifdef __linux__

#include <unistd.h>
#include <strings.h>
#include <syslog.h>

#include <netdb.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sysfs/libsysfs.h>

#include <netinet/tcp.h>

#define closesocket close

#else

#define USBIDS_FILE "usb.ids"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <signal.h>

typedef unsigned int u_int16_t;
typedef unsigned char u_int8_t;
typedef signed int ssize_t;

#define SYSFS_PATH_MAX		256
#define SYSFS_BUS_ID_SIZE	32

#define snprintf _snprintf
#define syslog(...) /* ... */

#endif

#include "usbip_common.h"
#include "stub_driver.h"
#include "vhci_driver.h"
#ifdef DMALLOC
#include <dmalloc.h>
#endif

#endif
