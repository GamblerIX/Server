#!/usr/bin/env python3

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
    
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.wicked_waifus_path = self.project_root / "wicked-waifus-rs"
        self.logs_dir = self.project_root / "logs"
        self.release_dir = self.project_root / "release"
        
        
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
        
        
        self.start_order = [
            "config-server",
            "hotpatch-server", 
            "login-server",
            "gateway-server",
            "game-server"
        ]
        
        
        self.shutdown_event = Event()
        self.monitor_thread = None
        self.auto_restart_enabled = True
        self.stop_flag_file = self.project_root / "stop_flag.tmp"
        
        
            
    def log_message(self, message, log_type="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{log_type}] {message}"
        
        
        print(log_entry)
            
    def check_port_available(self, port):
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                    return False
            return True
        except (psutil.AccessDenied, AttributeError):
            
            import socket
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('127.0.0.1', port))
                    return True
            except OSError:
                return False
                
    def kill_process_on_port(self, port):
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
        server = self.servers[server_key]
        server_name = server["name"]
        port = server["port"]
        
        self.log_message(f"启动 {server_name}...")
        
        
        if not self.check_port_available(port):
            self.log_message(f"端口 {port} 被占用，尝试释放...", "WARNING")
            if self.kill_process_on_port(port):
                time.sleep(3)
            else:
                self.log_message(f"无法释放端口 {port}", "ERROR")
                return False
                
        try:
            
            if use_release:
                exe_path = self.release_dir / f"{server_name}.exe"
                if not exe_path.exists():
                    self.log_message(f"Release版本不存在，使用cargo run: {exe_path}", "WARNING")
                    use_release = False
            
            if use_release:
                # 使用预编译的可执行文件
                cmd = [str(exe_path)]
                cwd = str(self.release_dir)
            else:
                
                cmd = ["cargo", "run", "-r", "--bin", server_name]
                cwd = str(self.wicked_waifus_path)
                
            self.log_message(f"执行命令: {' '.join(cmd)}")
            
            if os.name == 'nt':
                process = subprocess.Popen(
                    cmd,
                    cwd=cwd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS,
                    close_fds=True
                )
            else:
                process = subprocess.Popen(
                    cmd,
                    cwd=cwd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    preexec_fn=os.setsid,
                    close_fds=True
                )
            
            
            time.sleep(1)
            
            if process.poll() is None:
                server["process"] = process
                server["start_time"] = time.time()
                self.log_message(f"[成功] {server_name} 启动成功 (PID: {process.pid})")
                
                return True
            else:
                return_code = process.returncode
                error_msg = f"[错误] {server_name} 启动失败 (退出码: {return_code})"
                self.log_message(error_msg, "ERROR")
                return False
                
        except Exception as e:
            self.log_message(f"[错误] {server_name} 启动异常: {e}", "ERROR")
            return False
            
    def stop_single_server(self, server_key):
        server = self.servers[server_key]
        server_name = server["name"]
        process = server["process"]
        
        if process is None:
            return True
            
        self.log_message(f"停止 {server_name}...")
        
        try:
            if os.name == 'nt':
                process.terminate()
            else:
                process.terminate()
                
            
            try:
                process.wait(timeout=10)
                self.log_message(f"[成功] {server_name} 已优雅停止")
            except subprocess.TimeoutExpired:
                
                self.log_message(f"强制停止 {server_name}...", "WARNING")
                process.kill()
                process.wait()
                self.log_message(f"[成功] {server_name} 已强制停止")
                
            
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
        self.log_message("=== 开始启动所有服务端 ===")
        
        
        self.log_message("正在进行环境检查...")
        env_checker = WuWaEnvironmentChecker(self.project_root)
        if not env_checker.check_for_startup():
            self.log_message("[错误] 环境检查失败，无法启动服务器", "ERROR")
            return False
        self.log_message("[成功] 环境检查通过")
        
        
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
                
        
        success_count = 0
        for server_key in self.start_order:
            if self.start_single_server(server_key, use_release):
                success_count += 1
                
                time.sleep(1)
            else:
                self.log_message(f"[错误] 停止启动，因为 {self.servers[server_key]['name']} 启动失败", "ERROR")
                break
                
        if success_count == len(self.start_order):
            self.log_message(f"[成功] 所有服务端启动完成 ({success_count}/{len(self.start_order)})")
            
            
            self.start_monitoring()
            
            self.log_message("=== 服务端启动完成 ===")
            return True
        else:
            self.log_message(f"[错误] 服务端启动失败 ({success_count}/{len(self.start_order)})")
            
            self.stop_all_servers()
            self.log_message("=== 服务端启动失败 ===")
            return False
            
    def stop_all_servers(self):
        self.log_message("=== 开始停止所有服务端 ===")
        
        
        self.shutdown_event.set()
        
        
        for server_key in reversed(self.start_order):
            self.stop_single_server(server_key)
            time.sleep(1)
            
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
            
        self.log_message("[成功] 所有服务端已停止")
        self.log_message("=== 服务端停止完成 ===")
        
    def start_monitoring(self):
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.monitor_thread = Thread(target=self._monitor_servers)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.log_message("[成功] 服务端监控已启动")
            
    def _monitor_servers(self):
        while not self.shutdown_event.is_set():
            try:
                for server_key, server in self.servers.items():
                    process = server["process"]
                    if process is not None:
                        if process.poll() is not None:
                            return_code = process.returncode
                            
                            
                            if self.stop_flag_file.exists():
                                self.log_message(f"[信息] {server['name']} 通过stop.py正常停止 (退出码: {return_code})")
                                server["process"] = None
                                server["start_time"] = None
                                continue
                            
                            self.log_message(f"[警告] {server['name']} 意外退出 (退出码: {return_code})", "WARNING")
                            
                            
                            self.log_message(f"[信息] 自动重启已禁用，{server['name']} 不会自动重启")
                            server["process"] = None
                            server["start_time"] = None
                                
                
                time.sleep(2)
                
            except Exception as e:
                self.log_message(f"监控线程发生错误: {e}", "ERROR")
                time.sleep(2)
                
    def get_server_status(self):
        status = {}
        for server_key, server in self.servers.items():
            process = server["process"]
            if process is not None and process.poll() is None:
                uptime = time.time() - server["start_time"] if server["start_time"] else 0
                status[server_key] = {
                    "running": True,
                    "pid": process.pid,
                    "uptime": uptime,
                    "restart_count": server["restart_count"],
                    "port": server["port"]
                }
            else:
                status[server_key] = {
                    "running": False,
                    "pid": None,
                    "uptime": 0,
                    "restart_count": server["restart_count"],
                    "port": server["port"]
                }
        return status
        
    def wait_for_servers(self):
        try:
            while not self.shutdown_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
            
    def restart_server(self, server_key):
        self.log_message(f"重启 {self.servers[server_key]['name']}...")
        
        
        self.stop_single_server(server_key)
        time.sleep(3)
        
        
        return self.start_single_server(server_key)
        
    def check_postgresql_connection(self):
        try:
            import psycopg2
            
            
            conn = psycopg2.connect(
                host="127.0.0.1",
                port=5432,
                database="users",
                user="users",
                password="password"
            )
            conn.close()
            self.log_message("[成功] PostgreSQL数据库连接正常")
            return True
            
        except ImportError:
            self.log_message("[警告] psycopg2模块未安装，无法检查数据库连接", "WARNING")
            return True
            
        except Exception as e:
            self.log_message(f"[错误] PostgreSQL数据库连接失败: {e}", "ERROR")
            self.log_message("请确保PostgreSQL已安装并按照环境配置指南正确配置", "ERROR")
            self.log_message("配置指南位置: docs/环境配置完整指南.md", "INFO")
            return False
    

            


def main():
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