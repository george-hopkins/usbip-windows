#ifndef _USBIP_OS_H
#define _USBIP_OS_H

int attach_devices_all(char *host);
int show_port_status(void);
int detach_port(char *port);
int attach_device(char *host, char *busid);
int init_socket();
int cleanup_socket();

#endif