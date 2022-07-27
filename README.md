## 项目说明 -- ECDSA签名伪造

✅Project: forge a signature to pretend that you are Satoshi



## 运行说明

**开发环境**：Windows WSL（Ubuntu18.04）Python3

**默认执行环境**：Python3

**库依赖：**

```python
import math
import secrets
from hashlib import sha256
# 一般都有
```

**运行方式：**

- `$: python3 ecdsa.py`  



## 伪造原理

**基础知识：**

​		ECDSA签名算法 https://www.cnblogs.com/Kalafinaian/p/7392505.html

**流程简介：**

- 确定参数：在有限域 $\mathbb{F}^*p$上，选取椭圆曲线$(secp256k1):y^2 = x^3+Ax+B,A=0,B=7$，选取基点G，确定G的阶N，这些数据都是公开的。

- 生成公私钥对：生成128bit随机数d，$sk=d$，然后计算 $vk=dG$

- 签名$Sig_d(m)$ :  选取随机数k，计算$R=k*G=(r_x，r_y)$，然后计算$e=hash(hash(m))$，$s=k^{-1}(e+r_xd)modn$，输出$signature = (r_x,s)$

- 使用公钥P、消息m或消息的hash值e，验证签名$signature = (r_x,s)$：$s^{-1}(eG+r_xP)=R'=(r'_x,r'_y)$，如果$r'_x=r_x$则验证通过。

  我们可以计算$e^{-1}=(k^{-1}(e+r_xd))^{-1}=(e+r_xd)^{-1}k$

  则$s^{-1}(eG+r_xP)=(e+r_xd)^{-1}k(eG+r_xdG)=IkG=R$

  利用这个数学原理，我们就可以进行伪造

**伪造过程：**

- 从验证中可以看到，我们只需要让$s^{-1}(eG+r_xP) =R $ 即可，构造 $R=uG+vP=(r_x',r'_y)$

  只需：

  ![image-20220727142731920](./picture/image-20220727142731920.png)

  解得：

  ![image-20220727142745358](./picture/image-20220727142745358.png)

  

  因此我们输出$sig =(r_x',s')$，皆可以通过对P的验证，当然我们只能提供 $e'$，没办法提供原像，所以这个伪造应用范围也有限。



## 运行截图：

