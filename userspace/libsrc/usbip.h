/*
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#ifndef _USBIP_H
#define _USBIP_H

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#define UNUSED(x) (void)(x)

#ifndef __linux__

#define _CRT_SECURE_NO_WARNINGS

#define USBIDS_FILE "usb.ids"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <signal.h>

typedef unsigned int u_int16_t;
typedef unsigned char u_int8_t;
typedef signed int ssize_t;

#define SYSFS_PATH_MAX		256
#define SYSFS_BUS_ID_SIZE	32

#ifndef _UCRT
#define snprintf _snprintf
#endif
#define syslog(...) /* ... */

#endif /* !__linux__ */

#include "usbip_common.h"
#ifdef __linux__
#include "stub_driver.h"
#include "vhci_driver.h"
#endif
#ifdef DMALLOC
#include <dmalloc.h>
#endif

#endif
