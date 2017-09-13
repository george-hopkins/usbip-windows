//
// This guid is used in IoCreateDeviceSecure call to create PDOs. The idea is to
// allow the administrators to control access to the child device, in case the
// device gets enumerated as a raw device - no function driver, by modifying the 
// registry. If a function driver is loaded for the device, the system will override
// the security descriptor specified in the call to IoCreateDeviceSecure with the 
// one specifyied for the setup class of the child device.
//

DEFINE_GUID(GUID_SD_BUSENUM_PDO, 
        0x9d3039dd, 0xcca5, 0x4b4d, 0xb3, 0x3d, 0xe2, 0xdd, 0xc8, 0xa8, 0xc5, 0x2e);
// {9D3039DD-CCA5-4b4d-B33D-E2DDC8A8C52E}

//
// GUID definition are required to be outside of header inclusion pragma to avoid
// error during precompiled headers.
//

#ifndef __DRIVER_H
#define __DRIVER_H

//
// Define Interface reference/dereference routines for
//  Interfaces exported by IRP_MN_QUERY_INTERFACE
//

typedef VOID (*PINTERFACE_REFERENCE)(PVOID Context);
typedef VOID (*PINTERFACE_DEREFERENCE)(PVOID Context);

typedef
BOOLEAN
(*PUSBIP_GET_CRISPINESS_LEVEL)(
                           __in   PVOID Context,
                           __out  PUCHAR Level
                               );

typedef
BOOLEAN
(*PUSBIP_SET_CRISPINESS_LEVEL)(
                           __in   PVOID Context,
                           __out  UCHAR Level
                               );

typedef
BOOLEAN
(*PUSBIP_IS_CHILD_PROTECTED)(
                             __in PVOID Context
                             );

//
// Interface for getting and setting power level etc.,
//

#ifndef  STATUS_CONTINUE_COMPLETION //required to build driver in Win2K and XP build environment
//
// This value should be returned from completion routines to continue
// completing the IRP upwards. Otherwise, STATUS_MORE_PROCESSING_REQUIRED
// should be returned.
//
#define STATUS_CONTINUE_COMPLETION      STATUS_SUCCESS

#endif

#endif
