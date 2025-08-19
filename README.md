# Linux权限维持工具 / Linux Persistence Tool

[English](#english) | [中文](#chinese)

---

## English

# Linux Persistence Tool

A comprehensive Linux persistence tool written in Go language, containing various persistence techniques for security research and penetration testing purposes only.

## ⚠️ Disclaimer

**This tool is for authorized security testing and educational purposes only. Do not use for illegal activities. Users are responsible for their actions.**

## Features

### 1. Reverse Shell
- Continuously attempts to connect to specified host and port
- Automatic reconnection mechanism
- Default connection: 192.168.1.100:4444

### 2. SSH Backdoor
- Starts simplified SSH service on specified port
- Simulates SSH protocol handshake
- Default listening port: 2222

### 3. Hidden Files
- Creates hidden script files
- File names disguised as system processes
- Includes reverse shell functionality

### 4. Cron Backdoor
- Adds crontab scheduled tasks
- Attempts reverse shell every 5 minutes
- Silent operation

### 5. Setuid Backdoor
- Creates binary files with root privileges
- Compiles C code and sets setuid bit
- Disguised as system file names

### 6. PAM Backdoor
- Creates PAM authentication modules
- Universal password: backdoor123
- Integrated into system authentication process

### 7. Kernel Module Backdoor
- Creates and loads kernel modules
- Runs at kernel level
- Harder to detect

### 8. ICMP Backdoor
- Listens for ICMP packets
- Triggered by specific payload
- Uses raw sockets

### 9. DNS Backdoor
- Disguised as DNS query traffic
- Periodically sends query requests
- Covert communication channel

### 10. VIM Backdoor
- Exploits VIM's Python extension
- Background shell listener
- Process disguise

### 11. Strace Backdoor
- Records SSH and su command inputs
- Captures user passwords
- Log file storage

### 12. Port Reuse Backdoor
- Uses iptables for port reuse
- Triggered by specific strings
- SSH traffic reuse

## Compilation and Usage

### Compilation
```bash
go build -o linux-persistence main.go
```

### Usage
```bash
# Recommended to run with root privileges for best results
sudo ./linux-persistence
```

## Configuration Options

You can modify the configuration struct in `main.go` to customize settings:

```go
var config = Config{
    ReverseShellHost: "192.168.1.100",  // Reverse shell target host
    ReverseShellPort: 4444,             // Reverse shell target port
    BackdoorPort:     6666,             // VIM backdoor listening port
    HiddenProcess:    "systemd-resolved", // Hidden process name
    SSHBackdoorPort:  2222,             // SSH backdoor port
}
```

## Usage Instructions

### 1. Prepare Listener
Start netcat listener on attacker machine:
```bash
nc -lvp 4444
```

### 2. Run Tool
Run on target machine:
```bash
sudo ./linux-persistence
```

### 3. Use SSH Backdoor
```bash
ssh -p 2222 root@target_ip
```

### 4. Port Reuse
Activate port reuse:
```bash
echo 'backdoor' | socat - tcp:target_ip:80
```

Deactivate port reuse:
```bash
echo 'close' | socat - tcp:target_ip:80
```

### 5. ICMP Backdoor
Send ICMP packet containing "backdoor" to trigger

## Detection and Protection

### Detection Methods
1. Monitor network connections: `netstat -an`
2. Check process list: `ps aux`
3. Check scheduled tasks: `crontab -l`
4. Check system file integrity
5. Monitor kernel modules: `lsmod`
6. Check PAM configuration
7. Analyze network traffic

### Protection Recommendations
1. Regular system integrity checks
2. Monitor abnormal network connections
3. Restrict root privilege usage
4. Deploy HIDS/NIDS
5. Regular system patch updates
6. Restrict compilation tool access
7. Monitor kernel module loading

## Technical Details

### Hiding Techniques
- Process name disguise
- File hiding (starting with .)
- Network traffic disguise
- Kernel-level hiding

### Persistence Techniques
- Scheduled tasks
- System service disguise
- Kernel modules
- PAM modules

### Communication Techniques
- TCP reverse shell
- ICMP covert channels
- DNS tunneling
- Port reuse

## Dependencies

Running this tool requires the following dependencies:
- GCC compiler (for compiling C code)
- Linux kernel development headers (for kernel modules)
- PAM development library (for PAM modules)
- iptables (for port reuse)
- netcat or socat (for network connections)

## Legal Notice

This tool is only for:
1. Authorized penetration testing
2. Security research and education
3. Red team exercises
4. Security awareness training

**Do not use for any unauthorized activities!**

## Contributing

Welcome to submit issues and improvement suggestions. Please ensure all contributions comply with ethical usage guidelines.

## License

This project is for educational and authorized testing purposes only. Users must comply with local laws and regulations.

---

## Chinese

# Linux权限维持工具

这是一个用Go语言编写的Linux权限维持工具，包含多种权限维持技术，仅供安全研究和渗透测试使用。

## ⚠️ 免责声明

**此工具仅供授权的安全测试和教育目的使用。请勿用于非法活动。使用者应对其行为负责。**

## 功能特性

### 1. 反弹Shell
- 持续尝试连接指定的主机和端口
- 自动重连机制
- 默认连接 192.168.1.100:4444

### 2. SSH后门
- 在指定端口启动简化的SSH服务
- 模拟SSH协议握手
- 默认监听端口 2222

### 3. 隐藏文件
- 创建隐藏的脚本文件
- 文件名伪装成系统进程
- 包含反弹shell功能

### 4. 定时任务后门
- 添加crontab定时任务
- 每5分钟尝试反弹shell
- 静默运行

### 5. Setuid后门
- 创建具有root权限的二进制文件
- 编译C代码并设置setuid位
- 伪装成系统文件名

### 6. PAM后门
- 创建PAM认证模块
- 万能密码：backdoor123
- 集成到系统认证流程

### 7. 内核模块后门
- 创建并加载内核模块
- 在内核级别运行
- 更难被检测

### 8. ICMP后门
- 监听ICMP数据包
- 通过特定payload触发
- 使用原始套接字

### 9. DNS后门
- 伪装成DNS查询流量
- 定期发送查询请求
- 隐蔽的通信通道

### 10. VIM后门
- 利用VIM的Python扩展
- 后台运行shell监听
- 进程伪装

### 11. Strace后门
- 记录SSH和su命令的输入
- 获取用户密码
- 日志文件存储

### 12. 端口复用后门
- 使用iptables实现端口复用
- 通过特定字符串触发
- SSH流量复用

## 编译和运行

### 编译
```bash
go build -o linux-persistence main.go
```

### 运行
```bash
# 建议以root权限运行以获得最佳效果
sudo ./linux-persistence
```

## 配置选项

可以修改`main.go`中的配置结构体来自定义设置：

```go
var config = Config{
    ReverseShellHost: "192.168.1.100",  // 反弹shell目标主机
    ReverseShellPort: 4444,             // 反弹shell目标端口
    BackdoorPort:     6666,             // VIM后门监听端口
    HiddenProcess:    "systemd-resolved", // 隐藏进程名称
    SSHBackdoorPort:  2222,             // SSH后门端口
}
```

## 使用方法

### 1. 准备监听器
在攻击者机器上启动netcat监听：
```bash
nc -lvp 4444
```

### 2. 运行工具
在目标机器上运行：
```bash
sudo ./linux-persistence
```

### 3. 使用SSH后门
```bash
ssh -p 2222 root@target_ip
```

### 4. 端口复用
激活端口复用：
```bash
echo 'backdoor' | socat - tcp:target_ip:80
```

关闭端口复用：
```bash
echo 'close' | socat - tcp:target_ip:80
```

### 5. ICMP后门
发送包含"backdoor"的ICMP包来触发

## 检测和防护

### 检测方法
1. 监控网络连接：`netstat -an`
2. 检查进程列表：`ps aux`
3. 检查定时任务：`crontab -l`
4. 检查系统文件完整性
5. 监控内核模块：`lsmod`
6. 检查PAM配置
7. 分析网络流量

### 防护建议
1. 定期检查系统完整性
2. 监控异常网络连接
3. 限制root权限使用
4. 部署HIDS/NIDS
5. 定期更新系统补丁
6. 限制编译工具访问
7. 监控内核模块加载

## 技术细节

### 隐藏技术
- 进程名伪装
- 文件隐藏（以.开头）
- 网络流量伪装
- 内核级隐藏

### 持久化技术
- 定时任务
- 系统服务伪装
- 内核模块
- PAM模块

### 通信技术
- TCP反弹shell
- ICMP隐蔽通道
- DNS隧道
- 端口复用

## 依赖项

运行此工具需要以下依赖：
- GCC编译器（用于编译C代码）
- Linux内核开发头文件（用于内核模块）
- PAM开发库（用于PAM模块）
- iptables（用于端口复用）
- netcat或socat（用于网络连接）

## 法律声明

此工具仅用于：
1. 授权的渗透测试
2. 安全研究和教育
3. 红队演练
4. 安全意识培训

**请勿用于任何未经授权的活动！**

## 贡献

欢迎提交问题和改进建议。请确保所有贡献都符合道德使用准则。

## 许可证

本项目仅供教育和授权测试使用。使用者须遵守当地法律法规。
