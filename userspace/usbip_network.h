/*
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#ifndef _USBIP_NETWORK_H
#define _USBIP_NETWORK_H

ssize_t usbip_recv(int sockfd, void *buff, size_t bufflen);
ssize_t usbip_send(int sockfd, void *buff, size_t bufflen);
int usbip_send_op_common(int sockfd, uint32_t code, uint32_t status);
int usbip_recv_op_common(int sockfd, uint16_t *code);
int usbip_set_reuseaddr(int sockfd);
int usbip_set_nodelay(int sockfd);
int usbip_set_keepalive(int sockfd);

SOCKET tcp_connect(char *hostname, char *service);

int init_winsock(void);

#endif
