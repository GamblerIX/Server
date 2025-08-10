# 鸣潮服务端一键运行工具（运行版）

## 项目介绍

这是一个用于运行和管理wicked-waifus-rs服务端发行版的Python项目。

> 使用教程详见Server/docs目录下的使用指南.md。

## 一键运行脚本

> 请确保您已按照使用指南正确完成了所有配置步骤。

```
cd D:\WuWaPS\Server
pip install -r py/requirements.txt
python main.py
```

## 📁 项目结构

```
Server/
	   ├── docs/         # 配置文档
       ├── release/      # 发行版目录
       ├── logs/         # 日志目录
       ├── py/           # 脚本目录
       └── README.md     # 说明文档
```

## 🎮 项目功能

- **1** - 运行服务端
- **2** - 停止服务端
- **3** - 完全卸载项目
- **4** - 监控服务端状态
- **5** - 调试运行 (分窗口显示)
- **6** - 环境检查
- **7** - 退出主菜单

## 🌐 服务端口

- 10001 - configserver
- 5500 - loginserver
- 10003 - gateway
- 7777 - kcpport
- 10004 - gameserver
- 10002 - hotpatch


## 🗄️ 数据库配置

```
host = "127.0.0.1:5432"
user_name = "users"
password = "password"
db_name = "users"
```

## 🛡️ 防卡死特性

- 智能资源监控
- 僵死进程检测

## 📋 运行最低要求

- **硬件配置**：
    - CPU：2核+
    - 内存：4GB+

- **操作系统**:
    - Windows 10+
    - Windows Server 2019+

## 🔗 项目地址

- **一键运行脚本**: https://github.com/GamblerIX/Server
- **服务端源码**: https://git.xeondev.com/wickedwaifus/wicked-waifus-rs

## 叠甲

> 本项目采用MIT协议开源，您可以在遵守协议且仅为学习和研究使用的前提下自由使用、修改和分发本项目的代码。