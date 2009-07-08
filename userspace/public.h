//
// Define an Interface Guid for bus enumerator class.
// This GUID is used to register (IoRegisterDeviceInterface) 
// an instance of an interface so that enumerator application 
// can send an ioctl to the bus driver.
//

DEFINE_GUID (GUID_DEVINTERFACE_BUSENUM_TOASTER,
        0xD35F7840, 0x6A0C, 0x11d2, 0xB8, 0x41, 0x00, 0xC0, 0x4F, 0xAD, 0x51, 0x71);


//
// Define a Setup Class GUID for Toaster Class. This is same
// as the TOASTSER CLASS guid in the INF files.
//

DEFINE_GUID (GUID_DEVCLASS_TOASTER,
        0xB85B7C50, 0x6A01, 0x11d2, 0xB8, 0x41, 0x00, 0xC0, 0x4F, 0xAD, 0x51, 0x71);
//{B85B7C50-6A01-11d2-B841-00C04FAD5171}

//
// Define a WMI GUID to get busenum info.
//

DEFINE_GUID (TOASTER_BUS_WMI_STD_DATA_GUID, 
        0x0006A660, 0x8F12, 0x11d2, 0xB8, 0x54, 0x00, 0xC0, 0x4F, 0xAD, 0x51, 0x71);
//{0006A660-8F12-11d2-B854-00C04FAD5171}

//
// Define a WMI GUID to get toaster device info.
//

DEFINE_GUID (TOASTER_WMI_STD_DATA_GUID, 
        0xBBA21300L, 0x6DD3, 0x11d2, 0xB8, 0x44, 0x00, 0xC0, 0x4F, 0xAD, 0x51, 0x71);

//
// Define a WMI GUID to represent device arrival notification WMIEvent class.
//

DEFINE_GUID (TOASTER_NOTIFY_DEVICE_ARRIVAL_EVENT, 
        0x1cdaff1, 0xc901, 0x45b4, 0xb3, 0x59, 0xb5, 0x54, 0x27, 0x25, 0xe2, 0x9c);
// {01CDAFF1-C901-45b4-B359-B5542725E29C}


//
// GUID definition are required to be outside of header inclusion pragma to avoid
// error during precompiled headers.
//

#ifndef __PUBLIC_H
#define __PUBLIC_H

#define USBVBUS_IOCTL(_index_) \
    CTL_CODE (FILE_DEVICE_BUS_EXTENDER, _index_, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_USBVBUS_PLUGIN_HARDWARE               USBVBUS_IOCTL (0x0)
#define IOCTL_USBVBUS_UNPLUG_HARDWARE               USBVBUS_IOCTL (0x1)
#define IOCTL_USBVBUS_EJECT_HARDWARE                USBVBUS_IOCTL (0x2)
#define IOCTL_USBVBUS_GET_PORTS_STATUS              USBVBUS_IOCTL (0x3)

#define COMPATIBLE_IDS_SAMPLE L"USB\\Class_00&SubClass_00&Prot_00\0USB\\Class_00&SubClass_00\0USB\\Class_00\0"

#define BUSENUM_COMPATIBLE_IDS_LENGTH sizeof(COMPATIBLE_IDS_SAMPLE)

typedef struct _ioctl_usbvbus_plugin
{
	unsigned int devid;
	/* 4 bytes */
	unsigned short vendor;
	unsigned short product;
	/* 8 bytes */
	unsigned short version;
	unsigned char speed;
	unsigned char inum;
	/* 12 bytes */
	unsigned char int0_class;
	unsigned char int0_subclass;
	unsigned char int0_protocol;
	signed char addr;  /* then it can not be bigger then 127 */
	/* 16 bytes */
} ioctl_usbvbus_plugin;

typedef struct _ioctl_usbvbus_get_ports_status
{
	union {
		signed char max_used_port; /* then it can not be bigger than 127 */
		unsigned char port_status[128];
		/* 128 bytes */
	};
} ioctl_usbvbus_get_ports_status;

typedef struct _ioctl_usbvbus_unplug
{
	signed char addr;
	char unused[3];

} ioctl_usbvbus_unplug;

typedef struct _BUSENUM_EJECT_HARDWARE
{
    //
    // sizeof (struct _EJECT_HARDWARE)
    //

    ULONG Size;                                    

    //
    // Serial number of the device to be ejected
    //

    ULONG   SerialNo;
    
    ULONG Reserved[2];    

} BUSENUM_EJECT_HARDWARE, *PBUSENUM_EJECT_HARDWARE;

#endif
