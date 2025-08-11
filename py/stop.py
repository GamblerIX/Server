#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
鸣潮服务端一键停止脚本

功能：
- 停止所有正在运行的服务端进程
- 清理端口占用
- 显示停止状态
"""

import os
import sys
import psutil
import time
from pathlib import Path
from datetime import datetime

class WuWaStop:
    """鸣潮服务端停止类"""
    
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.logs_dir = self.project_root / "logs"
        
        # 确保日志目录存在
        self.logs_dir.mkdir(exist_ok=True)
        
        # 服务端配置
        self.servers = {
            "config-server": {
                "name": "wicked-waifus-config-server",
                "port": 10001
            },
            "hotpatch-server": {
                "name": "wicked-waifus-hotpatch-server",
                "port": 10002
            },
            "login-server": {
                "name": "wicked-waifus-login-server",
                "port": 5500
            },
            "gateway-server": {
                "name": "wicked-waifus-gateway-server",
                "port": 10003
            },
            "game-server": {
                "name": "wicked-waifus-game-server",
                "port": 10004
            }
        }
        
        # 停止顺序（与启动顺序相反）
        self.stop_order = [
            "game-server",
            "gateway-server",
            "login-server",
            "hotpatch-server",
            "config-server"
        ]
        
    def log_message(self, message, log_type="INFO"):
        """记录日志消息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{log_type}] {message}"
        
        # 输出到控制台
        print(log_entry)
        
        # 写入日志文件
        log_file = self.logs_dir / "stop.log"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
            
    def find_processes_by_name(self, process_name):
        """根据进程名查找进程"""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    # 检查进程名
                    if process_name.lower() in proc.info['name'].lower():
                        processes.append(proc)
                    # 检查命令行参数
                    elif proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline']).lower()
                        if process_name.lower() in cmdline:
                            processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.log_message(f"查找进程时发生错误: {e}", "ERROR")
        return processes
        
    def find_processes_by_port(self, port):
        """根据端口查找进程"""
        processes = []
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                    try:
                        process = psutil.Process(conn.pid)
                        processes.append(process)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except (psutil.AccessDenied, AttributeError):
            self.log_message(f"无法检查端口{port}的占用情况", "WARNING")
        return processes
        
    def find_processes_by_name_fast(self, process_name):
        """快速根据进程名查找进程（3秒超时）"""
        processes = []
        start_time = time.time()
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                # 检查超时
                if time.time() - start_time > 1.5:  # 1.5秒超时
                    break
                try:
                    # 只检查进程名，不检查命令行参数（更快）
                    if process_name.lower() in proc.info['name'].lower():
                        processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.log_message(f"快速查找进程时发生错误: {e}", "ERROR")
        return processes
        
    def find_processes_by_port_fast(self, port):
        """快速根据端口查找进程（1.5秒超时）"""
        processes = []
        start_time = time.time()
        try:
            for conn in psutil.net_connections():
                # 检查超时
                if time.time() - start_time > 1.5:  # 1.5秒超时
                    break
                if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                    try:
                        process = psutil.Process(conn.pid)
                        processes.append(process)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except (psutil.AccessDenied, AttributeError):
            pass  # 静默处理，避免过多警告
        return processes
        
    def stop_process(self, process, server_name):
        """停止单个进程"""
        try:
            self.log_message(f"停止进程: {server_name} (PID: {process.pid})")
            
            # 尝试优雅停止
            process.terminate()
            
            # 等待进程结束
            try:
                process.wait(timeout=3)  # 减少等待时间到3秒
                self.log_message(f"[成功] {server_name} 已优雅停止")
                return True
            except psutil.TimeoutExpired:
                # 强制杀死进程
                self.log_message(f"强制停止 {server_name}...", "WARNING")
                process.kill()
                process.wait()
                self.log_message(f"[成功] {server_name} 已强制停止")
                return True
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.log_message(f"停止 {server_name} 时发生错误: {e}", "ERROR")
            return False
        except Exception as e:
            self.log_message(f"停止 {server_name} 时发生未知错误: {e}", "ERROR")
            return False
            
    def stop_server_by_name(self, server_key):
        """根据服务端名称停止服务端"""
        server = self.servers[server_key]
        server_name = server["name"]
        port = server["port"]
        
        stopped_count = 0
        
        # 方法1: 根据进程名查找
        processes = self.find_processes_by_name(server_name)
        for process in processes:
            if self.stop_process(process, server_name):
                stopped_count += 1
                
        # 方法2: 根据端口查找
        processes = self.find_processes_by_port(port)
        for process in processes:
            if self.stop_process(process, f"{server_name} (端口{port})"): 
                stopped_count += 1
                
        if stopped_count > 0:
            self.log_message(f"[成功] 停止了 {stopped_count} 个 {server_name} 进程")
        else:
            self.log_message(f"[信息] 未找到运行中的 {server_name} 进程")
            
        return stopped_count > 0
        
    def stop_all_servers(self, running_servers=None):
        """停止所有服务端"""
        self.log_message("=== 开始停止所有服务端 ===")
        
        # 创建停止标志文件，防止自动重启
        stop_flag_file = self.project_root / "stop_flag.tmp"
        try:
            stop_flag_file.touch()
            self.log_message("[成功] 已创建停止标志文件，禁用自动重启")
        except Exception as e:
            self.log_message(f"[警告] 创建停止标志文件失败: {e}", "WARNING")
        
        total_stopped = 0
        
        # 如果没有传入运行中的服务端列表，则重新检查
        if running_servers is None:
            running_servers = self.show_running_servers()
            
        if not running_servers:
            self.log_message("[信息] 没有找到运行中的服务端进程")
            self.log_message("=== 服务端停止完成 ===")
            return False
            
        # 创建运行中服务端的映射
        running_server_names = {server['name'] for server in running_servers}
        
        # 按停止顺序停止服务端，但只停止实际运行中的
        for server_key in self.stop_order:
            server_name = self.servers[server_key]["name"]
            if server_name in running_server_names:
                if self.stop_server_by_name(server_key):
                    total_stopped += 1
                time.sleep(1)  # 等待进程完全停止
            
        # 额外检查：停止所有可能遗漏的相关进程
        self.log_message("检查是否有遗漏的进程...")
        additional_stopped = 0
        
        processes = self.find_processes_by_name("wicked-waifus")
        for process in processes:
            if self.stop_process(process, "遗漏的服务端进程"):
                additional_stopped += 1
                    
        if additional_stopped > 0:
            self.log_message(f"[成功] 额外停止了 {additional_stopped} 个遗漏的进程")
            total_stopped += additional_stopped
            
        if total_stopped > 0:
            self.log_message(f"[成功] 总共停止了 {total_stopped} 个服务端进程")
        else:
            self.log_message("[信息] 没有找到运行中的服务端进程")
            
        # 清理停止标志文件
        try:
            if stop_flag_file.exists():
                stop_flag_file.unlink()
                self.log_message("[成功] 已清理停止标志文件")
        except Exception as e:
            self.log_message(f"[警告] 清理停止标志文件失败: {e}", "WARNING")
        
        self.log_message("=== 服务端停止完成 ===")
        return total_stopped > 0
        
    def show_running_servers(self):
        """显示当前运行的服务端"""
        self.log_message("=== 检查运行中的服务端 ===")
        
        running_servers = []
        start_time = time.time()
        
        for server_key, server in self.servers.items():
            # 检查是否超时（3秒限制）
            if time.time() - start_time > 3:
                self.log_message("[警告] 检查超时，使用快速模式", "WARNING")
                break
                
            server_name = server["name"]
            port = server["port"]
            
            # 检查进程（使用快速模式）
            processes = self.find_processes_by_name_fast(server_name)
            port_processes = self.find_processes_by_port_fast(port)
            
            if processes or port_processes:
                running_servers.append({
                    'name': server_name,
                    'port': port,
                    'processes': len(processes),
                    'port_processes': len(port_processes)
                })
                
        if running_servers:
            self.log_message(f"发现 {len(running_servers)} 个运行中的服务端:")
            for server in running_servers:
                self.log_message(f"  - {server['name']} (端口{server['port']}) - 进程数: {server['processes'] + server['port_processes']}")
        else:
            self.log_message("[成功] 没有发现运行中的服务端")
            
        return running_servers

def main():
    """主函数"""
    project_root = Path(__file__).parent.parent
    stopper = WuWaStop(project_root)
    
    print("鸣潮服务端一键停止工具")
    print("=" * 40)
    
    try:
        # 显示当前运行的服务端
        running_servers = stopper.show_running_servers()
        
        if running_servers:
            # 询问是否停止
            confirm = input("\n是否停止所有运行中的服务端？(Y/n): ").strip().lower()
            if confirm in ['', 'y', 'yes']:
                stopper.stop_all_servers(running_servers)
            else:
                print("取消停止操作")
        else:
            print("\n没有需要停止的服务端")
            
    except KeyboardInterrupt:
        print("\n\n操作被用户中断")
    except Exception as e:
        print(f"\n发生错误: {e}")
        
    input("\n按回车键退出...")

if __name__ == "__main__":
    main()