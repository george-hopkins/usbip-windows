/*
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#ifndef _USBIP_H
#define _USBIP_H

#ifdef _DEBUG
	#define DEBUG
#endif

#define _CRT_SECURE_NO_WARNINGS
#define WINVER 0x0501
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <winioctl.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>

//#include <basetyps.h>
//#include <wtypes.h>

#ifdef _MSC_VER 
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Setupapi.lib")
typedef size_t ssize_t;
#endif

#include "win_stub.h"
#include "usbip_protocol.h"
#include "usbip_network.h"
#include "usbip_common.h"
#include "usbip_vbus_ui.h"

#endif
