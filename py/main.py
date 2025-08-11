#!/usr/bin/env python3

import os
import sys
import time
import platform
import msvcrt
import signal
from pathlib import Path


sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from run import WuWaRun
    from status import WuWaStatus
    from uninstall import WuWaUninstaller
    from stop import WuWaStop
    from check import WuWaEnvironmentChecker
except ImportError as e:
    print(f"导入模块失败: {e}")
    print("请确保所有必要的Python文件都存在")
    sys.exit(1)

class WuWaManager:
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.wicked_waifus_path = self.project_root / "wicked-waifus-rs"
        self.logs_dir = self.project_root / "logs"
        self.release_dir = self.project_root / "release"
        
        
        self.logs_dir.mkdir(exist_ok=True)
        
        
        self.runner = WuWaRun(self.project_root)
        self.status_checker = WuWaStatus(self.project_root)
        self.uninstaller = WuWaUninstaller(self.project_root)
        self.stopper = WuWaStop(self.project_root)
        self.env_checker = WuWaEnvironmentChecker(self.project_root)
        
        
        self.setup_main_logging()
        
        
        self._setup_signal_handlers()
        
    def _setup_signal_handlers(self):
        def signal_handler(signum, frame):
            print("\n提示: 服务端将继续在后台运行，如需停止请使用菜单选项2")
            print("退出主菜单...")
            print("\n感谢使用鸣潮服务端一键部署工具！")
            
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)
            
    def setup_main_logging(self):
        self.main_log_file = self.logs_dir / "main.log"
        
    def log_message(self, message, log_type="INFO"):
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{log_type}] {message}"
        
        
        print(log_entry)
        
        
        with open(self.main_log_file, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
        

        
    def show_banner(self):
        banner = """
================================================================================
                            鸣潮服务端一键部署工具
项目地址: https://github.com/GamblerIX/Server
服务端源码: https://git.xeondev.com/wickedwaifus/
================================================================================
        """
        print(banner)
        
    def show_menu(self):
        menu = """
=== 主菜单 ===
1. 运行服务端
2. 停止服务端
3. 完全卸载项目
4. 监控服务端状态
5. 调试运行 (分窗口显示)
6. 环境检查
7. 退出主菜单

请选择操作 (1-7): """
        return input(menu).strip()
        
    def show_server_info(self):
        info = """
=== 服务端口信息 ===
- 10001 - 配置服务端 (config-server)
- 5500  - 登录服务端 (login-server)
- 10003 - 网关服务端 (gateway-server)
- 10004 - 游戏服务端 (game-server)
- 10002 - 热更新服务端 (hotpatch-server)

=== 数据库配置 ===
- 主机: 127.0.0.1:5432
- 数据库名: users
- 用户: users
- 密码: password
        """
        print(info)
        

            
    def handle_run(self):
        print("\n=== 运行服务端 ===")
        
        try:
            print("\n正在启动服务端...")
            success = self.runner.start_all_servers()
                
            if success:
                print("[成功] 所有服务端启动完成")
                print("\n=== 启动完成，自动返回主菜单 ===")
                print("提示: 服务端继续在后台运行，如需停止请选择菜单选项2")
                print("[完成] 已自动返回主菜单")
                return
            else:
                print("[错误] 服务端启动失败")
        except KeyboardInterrupt:
            print("\n\n=== 退出运行菜单 ===")
            print("提示: 服务端继续在后台运行，如需停止请选择菜单选项2")
            print("[完成] 已退出运行菜单")
            return
        except Exception as e:
            print(f"[错误] 运行过程中发生错误: {e}")
            
    def handle_uninstall(self):
        print("\n=== 完全卸载项目 ===")
        confirm = input("[警告] 这将删除所有项目文件和日志，确定要继续吗？(y/N): ").strip().lower()
        if confirm in ['y', 'yes']:
            try:
                success = self.uninstaller.uninstall_all()
                if success:
                    print("[成功] 项目卸载完成")
                else:
                    print("[错误] 项目卸载失败")
            except Exception as e:
                print(f"[错误] 卸载过程中发生错误: {e}")
        else:
            print("取消卸载操作")
            
    def handle_status(self):
        print("\n=== 监控服务端状态 ===")
        try:
            self.status_checker.show_status()
        except Exception as e:
            print(f"[错误] 状态检查过程中发生错误: {e}")
            

            

            
    def handle_debug_run(self):
        print("\n=== 调试运行服务端 ===")
        print("这将在5个独立的PowerShell窗口中运行各个服务端")
        print("每个窗口将显示对应服务端的实时输出")
        
        confirm = input("\n是否继续？(Y/n): ").strip().lower()
        if confirm in ['', 'y', 'yes']:
            try:
                
                import subprocess
                import sys
                
                debug_script = self.project_root / "py" / "debug_run.py"
                if debug_script.exists():
                    print("\n正在启动调试模式...")
                    subprocess.run([sys.executable, str(debug_script)], cwd=str(self.project_root / "py"))
                    print("\n[成功] 调试模式启动完成")
                    print("提示: 请查看各个PowerShell窗口的输出")
                    print("提示: 关闭窗口即可停止对应的服务端")
                else:
                    print("\n[错误] 调试脚本不存在，请确保debug_run.py文件存在")
            except Exception as e:
                print(f"\n[错误] 调试运行过程中发生错误: {e}")
        else:
            print("\n取消调试运行操作")
            
    def handle_env_check(self):
        print("\n=== 环境检查 ===")
        self.env_checker.run_all_checks()
            
    def wait_for_esc_key(self):
        if os.name == 'nt':
            import msvcrt
            while True:
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key == b'\x1b':
                        
                        while msvcrt.kbhit():
                            msvcrt.getch()
                        return
                time.sleep(0.05)
        else:
            import termios
            import tty
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                while True:
                    key = sys.stdin.read(1)
                    if ord(key) == 27:
                        return
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            
    def handle_stop(self):
        print("\n=== 停止服务端 ===")
        try:
            
            confirm = input("是否停止所有运行中的服务端？(Y/n): ").strip().lower()
            if confirm in ['', 'y', 'yes']:
                
                success = self.stopper.stop_all_servers()
                
                
                print("\n正在检查停止结果...")
                time.sleep(1)
                running_servers = self.stopper.show_running_servers()
                
                if not running_servers:
                    print("[成功] 所有服务端已成功停止")
                else:
                    print(f"[警告] 仍有 {len(running_servers)} 个服务端在运行")
                    for server in running_servers:
                        print(f"  - {server['name']} (端口{server['port']})")
            else:
                print("取消停止操作")
        except Exception as e:
            print(f"[错误] 停止过程中发生错误: {e}")
            

            
    def run(self):
        try:
            
            self.log_message("=== 鸣潮服务端一键部署工具启动 ===")
            
            
            os.system('cls' if os.name == 'nt' else 'clear')
            
            
            self.show_banner()
            
            
            while True:
                try:
                    choice = self.show_menu()
                    
                    if choice == '7':
                        print("\n感谢使用鸣潮服务端一键运行工具！")
                        break
                    elif choice == '1':
                        self.handle_run()
                    elif choice == '2':
                        self.handle_stop()
                    elif choice == '3':
                        self.handle_uninstall()
                    elif choice == '4':
                        self.handle_status()
                    elif choice == '5':
                        self.handle_debug_run()
                    elif choice == '6':
                        self.handle_env_check()
                    else:
                        print("[错误] 无效选择，请输入 1-7 之间的数字")
                        
                    
                    if choice != '7' and choice != '1':
                        input("\n按回车键继续...")
                        
                except KeyboardInterrupt:
                    
                    print("\n")
                    continue
                except Exception as e:
                    
                    if str(e).strip():
                        print(f"\n[错误] 发生未知错误: {e}")
                        input("按回车键继续...")
                    else:
                        
                        continue
                    
        except Exception as e:
            print(f"程序启动失败: {e}")
            sys.exit(1)

def main():
    manager = WuWaManager()
    manager.run()

if __name__ == "__main__":
    main()