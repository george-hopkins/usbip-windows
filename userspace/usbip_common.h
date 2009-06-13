/*
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#ifndef _USBIP_COMMON_H
#define _USBIP_COMMON_H

#include <sys/types.h>

#define to_string(s)	#s

void dump_usb_interface(struct usb_interface *);
void dump_usb_device(struct usb_device *);
int read_usb_interface(struct usb_device *udev, int i, struct usb_interface *uinf);

const char *usbip_speed_string(int num);

void usbip_names_get_product(char *buff, size_t size, uint16_t vendor, uint16_t product);
void usbip_names_get_class(char *buff, size_t size, uint8_t class, uint8_t subclass, uint8_t protocol);

#endif
