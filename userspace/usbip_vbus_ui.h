#ifndef _USBIP_VBUS_UI_H
#define _USBIP_VBUS_UI_H
/* char * usbip_vbus_dev_node_name(char *buf, int buf_len); */
HANDLE usbip_vbus_open(void);
int usbip_vbus_get_free_port(HANDLE fd);
int usbip_vbus_get_ports_status(HANDLE fd, char *buf, int len);
int usbip_vbus_attach_device(HANDLE fd, int port,
		struct usb_device *udev, struct usb_interface * uinf0);
int usbip_vbus_detach_device(HANDLE fd, int port);
void usbip_vbus_forward(SOCKET sockfd, HANDLE devfd);

#endif
