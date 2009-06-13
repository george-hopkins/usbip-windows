.PHONY: clean all
CC:=i586-mingw32msvc-gcc
LD:=i586-mingw32msvc-ld
STRIP:=i586-mingw32msvc-strip
ALL_TARGET:=usbip.exe #driver.sys
all:$(ALL_TARGET)
source:=busenum.c buspdo.c pnp.c power.c Wmi.c
usbip_source:=usbip.c usbip_network.c usbip_common.c usbip_vbus_ui.c
usbip_include:=public.h usbip_protocol.h usbip_network.h \
	usbip_common.h usbip_vbus_ui.h
usbip.exe:$(usbip_source) $(usbip_include)
	$(CC) -Wall -o $@ $(usbip_source) -lsetupapi -lws2_32
driver.sys:$(source) busenum.h driver.h public.h
	$(CC) -D__USE_DIRECT__ -DDBG -Wall -Wl,-subsystem,native -Wl,-entry,_DriverEntry@8 -shared -nostartfiles -nostdlib -o $@ $(source) -lntoskrnl
#	$(LD) entry.o functions.o -mdll --subsystem,native --image-base=0x10000 --file-alignment=0x1000 --section-alignment=0x1000 --entry=_DriverEntry -nostartfiles -nostdlib -L/usr/i586-mingw32msvc/lib/ -lntoskrnl -o $@
#	$(STRIP) $@
clean:
	rm -f $(ALL_TARGET)
cscope:
	cscope -b -I/usr/i586-mingw32msvc/include -I/usr/i586-mingw32msvc/include/ddk
