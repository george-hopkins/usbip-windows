devcon remove "root\busenum"
build
if exist objchk_wxp_x86\i386\busenum.sys copy objchk_wxp_x86\i386\busenum.sys .
if exist objchk_wxp_x86\i386\busenum.sys devcon install bus.inf "root\busenum"
