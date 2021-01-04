# 2101_XiongMao

> 首发 语雀笔记
> https://www.yuque.com/co0kie/on3irt/zwon3w#IiGTr

# 手动杀毒

- 程序启动时，会判断路径

- - 将自己复制至C:\Windows\System32\drivers\spo0lsv.exe
  - 并创建副本进程，退出自身进程
  - ![image.png](https://cdn.nlark.com/yuque/0/2020/png/2556867/1609416736460-db524f5a-3b4b-41d9-8e7d-98ac0de049f7.png)

- 感染EXE文件

- - 遍历文件夹，将EXE感染为熊猫，并且无法打开
  - ![image.png](https://cdn.nlark.com/yuque/0/2020/png/2556867/1609423243348-de3703e7-e293-430e-98fe-acbd5b2edffc.png)
  - 对比原文件
  - EXE末尾标志
  - [0x00][WhBoy][文件名][文件后缀][0x02][文件大小][0x01]
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609464051730-0fcce1b7-3093-49c3-bdbe-c91d15d9d1c0.png)

- 感染htm/html文件

- - 对htm/html进行填充iframe框架
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609571265271-9faecff8-081b-48b6-a641-d9a77e9c6280.png)

- 创建文件

- - 创建Desktop_.ini文件
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609570068576-821e1035-2bb6-489c-82d7-eb8bd61e1a8e.png)
  - 创建根目录自动启动文件
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609571125261-05d8fefe-ab0a-4467-9185-8c934f92f29b.png)

- 创建启动项

- - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609571005165-68f0d71f-1b11-4539-86b5-3a22b21e1b09.png)

- 查看字符串

- - 猜测感染文件类型
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609512470088-bec4810a-1730-415b-86d7-6b62064f64a7.png)

- 对局域网攻击
- ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609571829456-9f26b4a8-7b45-4510-8103-fd474064209e.png)
- END

------

# 逆向分析

## 准备工作

- 查壳
- 脱壳

- - 找OEP
  - 通过特征码定位入口点jmp
  - FF 63 0C 50 55 FF 53 14 AB
  - ![image.png](https://cdn.nlark.com/yuque/0/2020/png/2556867/1609331711349-496f103f-68e0-4d6f-a080-36052173cba5.png)
  - DUMP
  - ![image.png](https://cdn.nlark.com/yuque/0/2020/png/2556867/1609331790419-39e9a58f-1cda-4d26-9a30-1300d8d84d43.png)

- 查新壳

- - 得出Delphi 6.0-7.0
  - ![image.png](https://cdn.nlark.com/yuque/0/2020/png/2556867/1609332170799-4f90ab52-18bd-4860-af29-f23d6b38d229.png)

- END

------

## 静态分析

- 主函数

- - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609574192357-3f823d8f-3129-4436-acbb-27fc8d0f51a9.png)

- 遍历磁盘线程回调函数

- - 遍历盘符，交给Fun_409348处理
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609577021588-51c40cc8-63cc-4aa3-8aea-b2c75a279529.png)

- 遍历文件函数

- - 排除白名单
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609577370094-898e5667-44e6-4994-b186-4ec3d1d63cf9.png)
  - 写入Desktop_.ini文件
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609578071402-989493b2-e928-4939-b45c-daa1828fb47b.png)
  - 感染名单
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609580491319-4d90802e-082f-4e9d-a03e-60b52e09ad79.png)
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609580708693-7473d516-ee92-4846-a7f3-5145f7eab772.png)
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609580995961-845ef9b7-9f52-480f-8af8-50b1d2d9ccca.png)

- 感染EXE文件

- - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609583755049-8a5ac49b-18da-4e04-ac31-8c26f978d060.png)

- 感染Html文件

- - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609584722484-dbed6c3e-e0aa-4070-9c4e-f3edc91d684d.png)

- 感染Setup.exe文件

- - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609591890524-e61c0cd7-2488-4062-821e-555b18117250.png)

- 感染autorun.inf文件

- - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609592117861-14cdafcb-b0ea-471b-822b-813c1736d7e1.png)

- 网络传播

- - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609592677398-6e7113e0-f06a-40fe-8f54-bb896e65a069.png)
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609592780834-459a6e6e-25aa-4c84-aefe-af1593f3fc52.png)

- 注册表编辑

- - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609593709265-255b5103-767e-42c7-aad8-7b70c5b8ea05.png)

- 自我保护、网络操作

- - 关闭共享
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609594177167-4dd0607a-be35-4dea-a37b-7de9bf0138da.png)
  - 关闭杀毒软件
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609594051857-18810524-01c4-4047-92ea-6e0250f9ef58.png)
  - 下载文件
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609719839603-350c842e-e011-4e19-8105-f689f49fc990.png)
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609720341479-4f75cb64-cd6a-4d87-9d7a-61606d1dbdd7.png)
  - 后门通道
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609720739988-05788739-5201-48bd-979c-033d87c58898.png)

- END

------

## 动态分析

- 病毒启动

- - 复制自身
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609573866509-4505ecce-1bee-40ee-8feb-c500717597bf.png)
  - 创建新进程
  - ![image.png](https://cdn.nlark.com/yuque/0/2021/png/2556867/1609572887789-fa344899-40ac-49c2-b13f-d6f01a105d58.png)

- END

------

