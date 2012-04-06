rem batch file to build complete drivers: output will be put in output directory

rem build 32-bit version in XP environment
rem build 64-bit version in Windows Server 2003 environment

set OCD=%CD%

set TYPE=chk

IF "%BASEDIR%"=="" (
set BASEDIR=D:\WinDDK\7600.16385.1
CALL D:\WinDDK\7600.16385.1\bin\setenv.bat D:\WinDDK\7600.16385.1 %TYPE%     WLH
cd /d %OCD%
)

cmd /C "set DDKBUILDENV=&& %BASEDIR%\bin\setenv.bat %BASEDIR% %TYPE%     WLH && cd /d %OCD% && build"
cmd /C "set DDKBUILDENV=&& %BASEDIR%\bin\setenv.bat %BASEDIR% %TYPE% x64 WLH && cd /d %OCD% && build"

rem copy files to output folder
rem del /Q output
mkdir output
copy USBIPEnum.inf output
copy obj%TYPE%_wlh_x86\i386\USBIPEnum.sys output\USBIPEnum_x86.sys
copy obj%TYPE%_wlh_amd64\amd64\USBIPEnum.sys output\USBIPEnum_x64.sys

rem sign files and create catalog file
signtool sign /f USBIP_TestCert.pfx /t http://timestamp.verisign.com/scripts/timestamp.dll output\USBIPEnum_x86.sys
signtool sign /f USBIP_TestCert.pfx /t http://timestamp.verisign.com/scripts/timestamp.dll output\USBIPEnum_x64.sys

inf2cat /driver:output /os:XP_x86,XP_x64,Server2003_X86,Server2003_X64,Vista_X86,Vista_X64,Server2008_X86,Server2008_X64,7_X86,7_X64,Server2008R2_X64,8_X64,8_X86

signtool sign /f USBIP_TestCert.pfx /t http://timestamp.verisign.com/scripts/timestamp.dll output\USBIPEnum.cat

