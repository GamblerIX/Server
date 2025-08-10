#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
鸣潮服务器运行脚本

功能：
- 启动所有服务器
- 监控服务器状态
- 僵死进程检测
- 自动重启机制
- 优雅关闭
"""

import os
import sys
import subprocess
import time
import signal
import psutil
import toml
from pathlib import Path
from datetime import datetime
from threading import Thread, Event
from check import WuWaEnvironmentChecker

class WuWaRun:
    """鸣潮服务器运行类"""
    
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.wicked_waifus_path = self.project_root / "wicked-waifus-rs"
        self.logs_dir = self.project_root / "logs"
        self.release_dir = self.project_root / "release"
        
        # logs目录功能已移除
        
        # 服务器配置
        self.servers = {
            "config-server": {
                "name": "wicked-waifus-config-server",
                "port": 10001,
                "process": None,
                "start_time": None,
                "restart_count": 0
            },
            "hotpatch-server": {
                "name": "wicked-waifus-hotpatch-server",
                "port": 10002,
                "process": None,
                "start_time": None,
                "restart_count": 0
            },
            "login-server": {
                "name": "wicked-waifus-login-server",
                "port": 5500,
                "process": None,
                "start_time": None,
                "restart_count": 0
            },
            "gateway-server": {
                "name": "wicked-waifus-gateway-server",
                "port": 10003,
                "process": None,
                "start_time": None,
                "restart_count": 0
            },
            "game-server": {
                "name": "wicked-waifus-game-server",
                "port": 10004,
                "process": None,
                "start_time": None,
                "restart_count": 0
            }
        }
        
        # 启动顺序（重要：config-server必须先启动）
        self.start_order = [
            "config-server",
            "hotpatch-server", 
            "login-server",
            "gateway-server",
            "game-server"
        ]
        
        # 控制标志
        self.shutdown_event = Event()
        self.monitor_thread = None
        self.auto_restart_enabled = True  # 自动重启开关
        self.stop_flag_file = self.project_root / "stop_flag.tmp"  # 停止标志文件
        
        # 注册信号处理器
        self._setup_signal_handlers()
        
    def _setup_signal_handlers(self):
        """设置信号处理器"""
        def signal_handler(signum, frame):
            self.log_message(f"接收到信号 {signum}，正在停止所有服务端...")
            self.shutdown_event.set()
            self.stop_all_servers()
            sys.exit(0)
            
        # 注册信号处理器
        if os.name == 'nt':  # Windows
            signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
            signal.signal(signal.SIGTERM, signal_handler)  # 终止信号
        else:  # Unix-like系统
            signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
            signal.signal(signal.SIGTERM, signal_handler)  # 终止信号
            signal.signal(signal.SIGHUP, signal_handler)  # 挂起信号
            
    def log_message(self, message, log_type="INFO"):
        """记录日志消息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{log_type}] {message}"
        
        # 输出到控制台
        print(log_entry)
            
    def check_port_available(self, port):
        """检查端口是否可用"""
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                    return False
            return True
        except (psutil.AccessDenied, AttributeError):
            # 如果无法获取网络连接信息，尝试其他方法
            import socket
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('127.0.0.1', port))
                    return True
            except OSError:
                return False
                
    def kill_process_on_port(self, port):
        """杀死占用指定端口的进程"""
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                    try:
                        process = psutil.Process(conn.pid)
                        self.log_message(f"杀死占用端口{port}的进程: {process.name()} (PID: {conn.pid})")
                        process.terminate()
                        time.sleep(2)
                        if process.is_running():
                            process.kill()
                        return True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except (psutil.AccessDenied, AttributeError):
            self.log_message(f"无法检查端口{port}的占用情况", "WARNING")
        return False
        
    def start_single_server(self, server_key, use_release=True):
        """启动单个服务端"""
        server = self.servers[server_key]
        server_name = server["name"]
        port = server["port"]
        
        self.log_message(f"启动 {server_name}...")
        
        # 检查端口是否被占用
        if not self.check_port_available(port):
            self.log_message(f"端口 {port} 被占用，尝试释放...", "WARNING")
            if self.kill_process_on_port(port):
                time.sleep(3)  # 等待端口释放
            else:
                self.log_message(f"无法释放端口 {port}", "ERROR")
                return False
                
        try:
            # 确定可执行文件路径
            if use_release:
                exe_path = self.release_dir / f"{server_name}.exe"
                if not exe_path.exists():
                    self.log_message(f"Release版本不存在，使用cargo run: {exe_path}", "WARNING")
                    use_release = False
            
            if use_release:
                # 使用预编译的可执行文件
                cmd = [str(exe_path)]
                cwd = str(self.release_dir)  # 修复：使用release目录作为工作目录
            else:
                # 使用cargo run
                cmd = ["cargo", "run", "-r", "--bin", server_name]
                cwd = str(self.wicked_waifus_path)
                
            self.log_message(f"执行命令: {' '.join(cmd)}")
            
            # 启动进程
            if os.name == 'nt':  # Windows
                # 在Windows上不使用CREATE_NEW_PROCESS_GROUP，这样Ctrl+C信号可以传播到子进程
                process = subprocess.Popen(
                    cmd,
                    cwd=cwd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:  # Unix-like系统
                process = subprocess.Popen(
                    cmd,
                    cwd=cwd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid
                )
            
            # 等待一段时间检查进程是否正常启动
            time.sleep(1)
            
            if process.poll() is None:
                # 进程仍在运行
                server["process"] = process
                server["start_time"] = time.time()
                self.log_message(f"✅ {server_name} 启动成功 (PID: {process.pid})")
                
                # 日志监控功能已移除
                
                return True
            else:
                # 进程已退出
                return_code = process.returncode
                error_msg = f"❌ {server_name} 启动失败 (退出码: {return_code})"
                self.log_message(error_msg, "ERROR")
                return False
                
        except Exception as e:
            self.log_message(f"❌ {server_name} 启动异常: {e}", "ERROR")
            return False
            
    # _monitor_server_output方法已移除
            
    def stop_single_server(self, server_key):
        """停止单个服务端"""
        server = self.servers[server_key]
        server_name = server["name"]
        process = server["process"]
        
        if process is None:
            return True
            
        self.log_message(f"停止 {server_name}...")
        
        try:
            # 尝试优雅关闭
            if os.name == 'nt':
                # Windows - 直接终止进程
                process.terminate()
            else:
                # Unix-like - 发送SIGTERM信号
                process.terminate()
                
            # 等待进程结束
            try:
                process.wait(timeout=10)
                self.log_message(f"✅ {server_name} 已优雅停止")
            except subprocess.TimeoutExpired:
                # 强制杀死进程
                self.log_message(f"强制停止 {server_name}...", "WARNING")
                process.kill()
                process.wait()
                self.log_message(f"✅ {server_name} 已强制停止")
                
            # 在Windows上，还需要确保杀死可能的子进程
            if os.name == 'nt':
                try:
                    parent = psutil.Process(process.pid)
                    children = parent.children(recursive=True)
                    for child in children:
                        try:
                            child.terminate()
                        except psutil.NoSuchProcess:
                            pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
        except Exception as e:
            self.log_message(f"停止 {server_name} 时发生错误: {e}", "ERROR")
            
        finally:
            server["process"] = None
            server["start_time"] = None
            
        return True
        
    def start_all_servers(self, use_release=True):
        """启动所有服务端"""
        self.log_message("=== 开始启动所有服务端 ===")
        
        # 环境检查
        self.log_message("正在进行环境检查...")
        env_checker = WuWaEnvironmentChecker(self.project_root)
        if not env_checker.check_for_startup():
            self.log_message("❌ 环境检查失败，无法启动服务器", "ERROR")
            return False
        self.log_message("✅ 环境检查通过")
        
        # 检查可执行文件是否存在
        if use_release:
            missing_files = []
            for server_key in self.start_order:
                server_name = self.servers[server_key]["name"]
                exe_path = self.release_dir / f"{server_name}.exe"
                if not exe_path.exists():
                    missing_files.append(server_name)
                    
            if missing_files:
                self.log_message(f"以下可执行文件不存在: {', '.join(missing_files)}", "WARNING")
                self.log_message("将使用cargo run模式启动", "WARNING")
                use_release = False
                
        # 按顺序启动服务端
        success_count = 0
        for server_key in self.start_order:
            if self.start_single_server(server_key, use_release):
                success_count += 1
                # 等待服务端完全启动
                time.sleep(2)
            else:
                self.log_message(f"❌ 停止启动，因为 {self.servers[server_key]['name']} 启动失败", "ERROR")
                break
                
        if success_count == len(self.start_order):
            self.log_message(f"✅ 所有服务端启动完成 ({success_count}/{len(self.start_order)})")
            
            # 启动监控线程
            self.start_monitoring()
            
            self.log_message("=== 服务端启动完成 ===")
            return True
        else:
            self.log_message(f"❌ 服务端启动失败 ({success_count}/{len(self.start_order)})")
            # 停止已启动的服务端
            self.stop_all_servers()
            self.log_message("=== 服务端启动失败 ===")
            return False
            
    def stop_all_servers(self):
        """停止所有服务端"""
        self.log_message("=== 开始停止所有服务端 ===")
        
        # 设置关闭标志
        self.shutdown_event.set()
        
        # 按相反顺序停止服务端
        for server_key in reversed(self.start_order):
            self.stop_single_server(server_key)
            time.sleep(2)
            
        # 等待监控线程结束
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
            
        self.log_message("✅ 所有服务端已停止")
        self.log_message("=== 服务端停止完成 ===")
        
    def start_monitoring(self):
        """启动监控线程"""
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.monitor_thread = Thread(target=self._monitor_servers)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.log_message("✅ 服务端监控已启动")
            
    def _monitor_servers(self):
        """监控服务端状态"""
        while not self.shutdown_event.is_set():
            try:
                for server_key, server in self.servers.items():
                    process = server["process"]
                    if process is not None:
                        # 检查进程是否还在运行
                        if process.poll() is not None:
                            # 进程已退出
                            return_code = process.returncode
                            
                            # 检查是否是通过stop.py停止的
                            if self.stop_flag_file.exists():
                                self.log_message(f"ℹ️  {server['name']} 通过stop.py正常停止 (退出码: {return_code})")
                                server["process"] = None
                                server["start_time"] = None
                                continue
                            
                            self.log_message(f"⚠️  {server['name']} 意外退出 (退出码: {return_code})", "WARNING")
                            
                            # 禁用自动重启功能（根据用户要求）
                            self.log_message(f"ℹ️  自动重启已禁用，{server['name']} 不会自动重启")
                            server["process"] = None
                            server["start_time"] = None
                                
                # 每2秒检查一次（优化检查速度）
                time.sleep(2)
                
            except Exception as e:
                self.log_message(f"监控线程发生错误: {e}", "ERROR")
                time.sleep(2)
                
    def get_server_status(self):
        """获取服务端状态"""
        status = {}
        for server_key, server in self.servers.items():
            process = server["process"]
            if process is not None and process.poll() is None:
                # 服务端正在运行
                uptime = time.time() - server["start_time"] if server["start_time"] else 0
                status[server_key] = {
                    "running": True,
                    "pid": process.pid,
                    "uptime": uptime,
                    "restart_count": server["restart_count"],
                    "port": server["port"]
                }
            else:
                # 服务端未运行
                status[server_key] = {
                    "running": False,
                    "pid": None,
                    "uptime": 0,
                    "restart_count": server["restart_count"],
                    "port": server["port"]
                }
        return status
        
    def wait_for_servers(self):
        """等待服务端运行"""
        try:
            while not self.shutdown_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
            
    def restart_server(self, server_key):
        """重启指定服务端"""
        self.log_message(f"重启 {self.servers[server_key]['name']}...")
        
        # 停止服务端
        self.stop_single_server(server_key)
        time.sleep(3)
        
        # 启动服务端
        return self.start_single_server(server_key)
        
    def check_postgresql_connection(self):
        """检查PostgreSQL数据库连接"""
        try:
            import psycopg2
            
            # 尝试连接数据库
            conn = psycopg2.connect(
                host="127.0.0.1",
                port=5432,
                database="users",
                user="users",
                password="password"
            )
            conn.close()
            self.log_message("✅ PostgreSQL数据库连接正常")
            return True
            
        except ImportError:
            self.log_message("⚠️  psycopg2模块未安装，无法检查数据库连接", "WARNING")
            return True  # 假设数据库正常
            
        except Exception as e:
            self.log_message(f"❌ PostgreSQL数据库连接失败: {e}", "ERROR")
            self.log_message("请确保PostgreSQL已安装并按照环境配置指南正确配置", "ERROR")
            self.log_message("配置指南位置: docs/环境配置完整指南.md", "INFO")
            return False
    

            


def main():
    """测试函数"""
    project_root = Path(__file__).parent.parent
    runner = WuWaRun(project_root)
    
    print("开始运行测试...")
    
    try:
        success = runner.start_all_servers(use_release=False)
        
        if success:
            print("所有服务器启动成功，按Ctrl+C停止")
            runner.wait_for_servers()
        else:
            print("服务器启动失败")
            
    except KeyboardInterrupt:
        print("\n正在停止服务器...")
        runner.stop_all_servers()
        print("服务器已停止")

if __name__ == "__main__":
    main()