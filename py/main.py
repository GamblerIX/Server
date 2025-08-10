#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
鸣潮服务端一键部署工具 - 主入口脚本

功能：
- 1 - 运行服务端
- 2 - 停止服务端
- 3 - 完全卸载项目
- 4 - 监控服务端状态
- 5 - 调试运行
- 6 - 环境检查
"""

import os
import sys
import time
import platform
import msvcrt
import signal
from pathlib import Path

# 添加当前目录到Python路径
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
    """鸣潮服务端管理器主类"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.wicked_waifus_path = self.project_root / "wicked-waifus-rs"
        self.logs_dir = self.project_root / "logs"
        self.release_dir = self.project_root / "release"
        
        # 确保日志目录存在
        self.logs_dir.mkdir(exist_ok=True)
        
        # 初始化各个模块
        self.runner = WuWaRun(self.project_root)
        self.status_checker = WuWaStatus(self.project_root)
        self.uninstaller = WuWaUninstaller(self.project_root)
        self.stopper = WuWaStop(self.project_root)
        self.env_checker = WuWaEnvironmentChecker(self.project_root)
        
        # 初始化主程序日志
        self.setup_main_logging()
        
        # 设置信号处理器
        self._setup_signal_handlers()
        
    def _setup_signal_handlers(self):
        """设置信号处理器"""
        def signal_handler(signum, frame):
            print(f"\n接收到信号 {signum}，退出程序...")
            print("ℹ️  如有服务端正在运行，请使用菜单选项3手动停止")
            sys.exit(0)
            
        # 注册信号处理器
        signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)  # 终止信号
            
    def setup_main_logging(self):
        """设置主程序日志"""
        self.main_log_file = self.logs_dir / "main.log"
        
    def log_message(self, message, log_type="INFO"):
        """记录日志消息"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{log_type}] {message}"
        
        # 输出到控制台
        print(log_entry)
        
        # 写入日志文件
        with open(self.main_log_file, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
        

        
    def show_banner(self):
        """显示程序横幅"""
        banner = """
════════════════════════════════════════════════
鸣潮服务端一键部署工具
项目地址: https://github.com/GamblerIX/Server
服务端源码: https://git.xeondev.com/wickedwaifus/
════════════════════════════════════════════════
        """
        print(banner)
        
    def show_menu(self):
        """显示主菜单"""
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
        """显示服务端信息"""
        info = """
=== 服务端口信息 ===
• 10001 - 配置服务端 (config-server)
        • 5500  - 登录服务端 (login-server)
        • 10003 - 网关服务端 (gateway-server)
        • 10004 - 游戏服务端 (game-server)
        • 10002 - 热更新服务端 (hotpatch-server)

=== 数据库配置 ===
• 主机: 127.0.0.1:5432
• 数据库名: users
• 用户: users
• 密码: password
        """
        print(info)
        

            
    def handle_run(self):
        """处理运行服务端"""
        print("\n=== 运行服务端 ===")
        
        try:
            print("\n正在启动服务端...")
            success = self.runner.start_all_servers()
                
            if success:
                print("✅ 所有服务端启动完成")
                print("\n服务端正在运行中...")
                print("按ESC退出运行菜单")
                self.wait_for_esc_key()
                print("\n=== 退出运行菜单 ===")
                print("ℹ️  服务端继续在后台运行，如需停止请选择菜单选项3")
                print("✅ 已退出运行菜单")
            else:
                print("❌ 服务端启动失败")
        except KeyboardInterrupt:
            print("\n\n=== 退出运行菜单 ===")
            print("ℹ️  服务端继续在后台运行，如需停止请选择菜单选项3")
            print("✅ 已退出运行菜单")
        except Exception as e:
            print(f"❌ 运行过程中发生错误: {e}")
            
    def handle_uninstall(self):
        """处理卸载项目"""
        print("\n=== 完全卸载项目 ===")
        confirm = input("⚠️  警告: 这将删除所有项目文件和日志，确定要继续吗？(y/N): ").strip().lower()
        if confirm in ['y', 'yes']:
            try:
                success = self.uninstaller.uninstall_all()
                if success:
                    print("✅ 项目卸载完成")
                else:
                    print("❌ 项目卸载失败")
            except Exception as e:
                print(f"❌ 卸载过程中发生错误: {e}")
        else:
            print("取消卸载操作")
            
    def handle_status(self):
        """处理监控服务端状态"""
        print("\n=== 监控服务端状态 ===")
        try:
            self.status_checker.show_status()
        except Exception as e:
            print(f"❌ 状态检查过程中发生错误: {e}")
            

            

            
    def handle_debug_run(self):
        """处理调试运行服务端"""
        print("\n=== 调试运行服务端 ===")
        print("这将在5个独立的PowerShell窗口中运行各个服务端")
        print("每个窗口将显示对应服务端的实时输出")
        
        confirm = input("\n是否继续？(Y/n): ").strip().lower()
        if confirm in ['', 'y', 'yes']:
            try:
                # 导入并运行debug_run脚本
                import subprocess
                import sys
                
                debug_script = self.project_root / "py" / "debug_run.py"
                if debug_script.exists():
                    print("\n正在启动调试模式...")
                    subprocess.run([sys.executable, str(debug_script)], cwd=str(self.project_root / "py"))
                    print("\n✅ 调试模式启动完成")
                    print("ℹ️  请查看各个PowerShell窗口的输出")
                    print("ℹ️  关闭窗口即可停止对应的服务端")
                else:
                    print("\n❌ 调试脚本不存在，请确保debug_run.py文件存在")
            except Exception as e:
                print(f"\n❌ 调试运行过程中发生错误: {e}")
        else:
            print("\n取消调试运行操作")
            
    def handle_env_check(self):
        """处理环境检查"""
        print("\n=== 环境检查 ===")
        self.env_checker.run_all_checks()
            
    def wait_for_esc_key(self):
        """等待ESC键按下"""
        if os.name == 'nt':  # Windows
            while True:
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key == b'\x1b':  # ESC键
                        break
                time.sleep(0.1)
        else:  # Unix-like系统
            import termios
            import tty
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                while True:
                    key = sys.stdin.read(1)
                    if ord(key) == 27:  # ESC键
                        break
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            
    def handle_stop(self):
        """处理停止服务端"""
        print("\n=== 停止服务端 ===")
        try:
            # 直接询问是否停止（优化流程）
            confirm = input("是否停止所有运行中的服务端？(Y/n): ").strip().lower()
            if confirm in ['', 'y', 'yes']:
                # 先停止服务端
                success = self.stopper.stop_all_servers()
                
                # 停止后再检查状态
                print("\n正在检查停止结果...")
                time.sleep(1)  # 短暂等待确保进程完全停止
                running_servers = self.stopper.show_running_servers()
                
                if not running_servers:
                    print("✅ 所有服务端已成功停止")
                else:
                    print(f"⚠️  仍有 {len(running_servers)} 个服务端在运行")
                    for server in running_servers:
                        print(f"  • {server['name']} (端口{server['port']})")
            else:
                print("取消停止操作")
        except Exception as e:
            print(f"❌ 停止过程中发生错误: {e}")
            

            
    def run(self):
        """运行主程序"""
        try:
            # 记录程序启动
            self.log_message("=== 鸣潮服务端一键部署工具启动 ===")
            
            # 清屏
            os.system('cls' if os.name == 'nt' else 'clear')
            
            # 显示横幅
            self.show_banner()
            
            # 主循环
            while True:
                try:
                    choice = self.show_menu()
                    
                    if choice == '7':
                        print("\n感谢使用鸣潮服务端一键部署工具！")
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
                        print("❌ 无效选择，请输入 1-7 之间的数字")
                        
                    if choice != '7':
                            input("\n按回车键继续...")
                        
                except KeyboardInterrupt:
                    print("\n\n程序被用户中断")
                    break
                except Exception as e:
                    print(f"\n❌ 发生未知错误: {e}")
                    input("按回车键继续...")
                    
        except Exception as e:
            print(f"程序启动失败: {e}")
            sys.exit(1)

def main():
    """主函数"""
    manager = WuWaManager()
    manager.run()

if __name__ == "__main__":
    main()