import serial
 
#连接串口
serial = serial.Serial('/dev/serial/by-id/usb-STMicroelectronics_STLINK-V3_003800493137511733333639-if01',115200,timeout=2)
if serial.isOpen():
	print ('串口已打开')
 
	data = b'Beking\r\n'    #发送的数据
	serial.write(data)      #串口写数据
	print ('You Send Data:',data)
 
	while True:
		data = serial.read(20)    #串口读20位数据
		if data != b'':
			break
	print ('receive data is :',data) 
	
else:
	print ('串口未打开')
 
 
 
#关闭串口
serial.close()
 
if serial.isOpen():
	print ('串口未关闭')
else:
	print ('串口已关闭')