## 项目说明 -- SM3 Rho环路攻击

✅Project: forge a signature to pretend that you are Satoshi



## 运行说明

**开发环境**：Windows WSL（Ubuntu18.04）

**默认执行环境**：Linux

**运行方式：**

- linux：`$: ./a.out`  



## 文件说明

- main.cpp	主要函数，通过产生随机数字，作为字符串string计算hash值，然后通过Pollard_Rho方法，找到碰撞原像，碰撞的bit长度通过全局变量定义
- Makefile     O2优化，因为初始是随机数的原因，也比较看运气，一般不会超过20s



## 运行截图：