
rem bcdedit /set testsigning on

rem certutil -enterprise -addstore Root USBIP_TestCert.cer
rem certutil -enterprise -addstore TrustedPublisher USBIP_TestCert.cer

cd output

..\devcon install USBIPEnum.inf "root\USBIPEnum"

cd ..
