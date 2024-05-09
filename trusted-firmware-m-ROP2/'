import serial
import serial.tools.list_ports
import time


def scan_all_ports():
    COM_lst = []
    ports_list  = serial.tools.list_ports.comports()
    if len(ports_list) <= 0:
        print("无串口设备。")
    else:
        print("可用串口设备如下：")
        for comport in ports_list:
            COM_num = list(comport)[0]
            print(COM_num, "   |   ", list(comport)[1])
            COM_lst.append(COM_num)
    return COM_lst



def open_port(COM_num):
    # 打开串口
    # 完整的打开串口的方式
    ser = serial.Serial(port=COM_num,
                        baudrate=115200,
                        bytesize=serial.EIGHTBITS,
                        parity=serial.PARITY_NONE,
                        stopbits=serial.STOPBITS_ONE,
                        timeout=1,
                        xonxoff=False,
                        rtscts=False,
                        dsrdtr=False,
                        write_timeout=0.001,
                        inter_byte_timeout=None,
                        exclusive=None)
    if ser.isOpen():                        # 判断串口是否成功打开
        print("打开串口成功 port open success:", ser.name)
    else:
        print("打开串口失败 port open failure")

    return ser



def close_port(ser):
    if ser.isOpen():
        ser.close()
        return True
    else:
        pass




def main_task(ser):
    flag_A_ack = False
    last_time = 0
    while(True):
        if(time.time_ns() - last_time > 1000*1e6):

            if flag_A_ack == True:
                print("ERROR:上一次的命令尚未完成")
                assert 0

            num_bytes = ser.write("C".encode('utf-8'))
            last_time = time.time_ns()
            flag_A_ack = True

        if flag_A_ack:
            rxdata = ser.read(6) # 返回的是bytes对象,bytes只是一个8bit数字为一个单位元素的数组
            rxdata_str = rxdata.decode('utf-8')
            if rxdata:
                print(len(rxdata_str))
                assert len(rxdata_str) == 6
                flag_A_ack = False # 收到数据并验证后清除flag
                for each in rxdata:
                    assert each == 123
                    print(each," ",end="")
                print("连接成功")
            else:
                # 若由于延迟，此次没有接收到数据，会在下一个while循环中继续尝试接收
                print("连接失败")
                pass



if __name__ == "__main__":

    COM_lst = scan_all_ports()
    ser = open_port(COM_lst[0])
    #ser = open_port(COM3)
    main_task(ser)

input("EOF")
