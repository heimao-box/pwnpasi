# pwnpasi
pwnpasi 是一款专为CTF PWN方向栈溢出入门基础题目开发设计的自动化工具，旨在帮助新手小白快速识别和利用32位和64位程序中的栈溢出漏洞与格式化字符串漏洞。该工具能够自动判断溢出字符数，自动识别格式化字符串漏洞，自动识别程序调用的动态链接库，并生成相应的ROP链以利用漏洞。支持多种利用方式，包括调用system后门函数、写入shellcode、puts函数ROP、write函数ROP以及syscall ROP，格式化字符串利用，可自动识别并绕过PIE防护与canary防护。此外，工具还具备本地和远程利用功能，并集成了LibcSearcher库，用于在没有提供libc地址的情况下自动搜索合适的libc版本



## 栈溢出漏洞演示：

https://github.com/user-attachments/assets/5b5abcdb-1011-4ed4-be6e-5b819eb3a3ab

## 格式化字符串漏洞演示



https://github.com/user-attachments/assets/9bf09335-605a-4896-aacf-ea938b800ba0

## 绕过canary防护演示：



https://github.com/user-attachments/assets/a3d8037d-227a-4f01-a554-750df58e7b67

canary FUZZ需要的时间较久，需要耐心等一下



## 绕过PIE防护演示



https://github.com/user-attachments/assets/2a3b1e49-e372-43d7-b2f1-43b153ea7ec6


## 安装依赖
确保已安装Python 3.x，安装所需依赖库：

```
pip3 install pwntools LibcSearcher ropper
```

安装所需工具：

```
apt install checksec objdump strings libc-bin
```

## 运行工具
通过命令行运行工具。示例命令：

```
python pwnsipa.py -l level3_x64
```

使用ldd工具可查看程序调用的动态链接库

```
ldd [文件名]
```

![](https://cdn.nlark.com/yuque/0/2025/png/27444040/1740375618886-31437dd2-55a3-4063-bc27-96492cc4c109.png)

指定造成溢出的字符数与动态链接库：

```
python pwnsipa.py -l level3_x64 -libc /lib/i386-linux-gnu/libc.so.6 -f 112
```

远程连接：

```
python pwnsipa.py -l level3_x64 -libc /lib/i386-linux-gnu/libc.so.6 -ip 192.168.0.1 -p 33333
```

## 未来计划
完善64位程序的寄存器调用功能

增加多交互程序的FUZZ功能

增加更多栈溢出与格式化字符串漏洞的利用方式和支持的架构

提升工具的自动化程度和用户友好性

## 关于可能的报错
进行FUZZ的程序名不要有特殊符合，如(_/*&^%$#@)之类的，如果有的话就重命名一下程序

报错也有可能是需要的工具和依赖没有安装完全，可以依照上面提供安装的工具检查一下

## 最后
此工具是针对的是ctf pwn方向，现在只能做一些入门基础题，目标人群为完全不会pwn的小白以及会pwn基础的师傅，之后会逐渐增加新的功能，最终目标就是能做中等类型的题目

此工具也为我下一个项目做技术积累

pwnpasi反馈/交流群: 256806296，欢迎各位师傅反馈工具问题，也可以提出想要增加的功能，有想要加入这个项目一起开发的师傅，非常欢迎
