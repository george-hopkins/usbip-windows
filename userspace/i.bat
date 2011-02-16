
rem bcdedit /set testsigning on

certutil -enterprise -addstore Root USBIP_TestCert.cer
certutil -enterprise -addstore TrustedPublisher USBIP_TestCert.cer

cd output

devcon install USBIPEnum.inf "root\USPIPEnum"
