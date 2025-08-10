#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
鸣潮服务端调试运行脚本

功能：
- 用Python打开五个PowerShell窗口
- 每个窗口运行一个服务端可执行文件
- 直接显示服务端原始输出，便于调试
"""

import os
import sys
import time
import subprocess
from pathlib import Path
from datetime import datetime

class WuWaDebugRun:
    """鸣潮服务端调试运行类"""
    
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.release_dir = self.project_root / "release"
        # logs目录功能已移除
        
        # 服务端配置（按启动顺序）
        self.servers = [
            {
                "name": "wicked-waifus-config-server",
                "exe": "wicked-waifus-config-server.exe",
                "port": 10001,
                "description": "配置服务端"
            },
            {
                "name": "wicked-waifus-hotpatch-server",
                "exe": "wicked-waifus-hotpatch-server.exe",
                "port": 10002,
                "description": "热更新服务端"
            },
            {
                "name": "wicked-waifus-login-server",
                "exe": "wicked-waifus-login-server.exe",
                "port": 5500,
                "description": "登录服务端"
            },
            {
                "name": "wicked-waifus-gateway-server",
                "exe": "wicked-waifus-gateway-server.exe",
                "port": 10003,
                "description": "网关服务端"
            },
            {
                "name": "wicked-waifus-game-server",
                "exe": "wicked-waifus-game-server.exe",
                "port": 10004,
                "description": "游戏服务端"
            }
        ]
        
    def log_message(self, message, level="INFO"):
        """记录日志消息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # 输出到控制台
        print(log_entry)
            
    def check_release_files(self):
        """检查release目录下的可执行文件"""
        self.log_message("=== 检查服务端可执行文件 ===")
        
        if not self.release_dir.exists():
            self.log_message(f"❌ Release目录不存在: {self.release_dir}", "ERROR")
            return False
            
        missing_files = []
        for server in self.servers:
            exe_path = self.release_dir / server["exe"]
            if exe_path.exists():
                self.log_message(f"✅ {server['description']} - {server['exe']}")
            else:
                self.log_message(f"❌ {server['description']} - {server['exe']} (缺失)", "ERROR")
                missing_files.append(server["exe"])
                
        if missing_files:
            self.log_message(f"❌ 缺失文件: {', '.join(missing_files)}", "ERROR")
            return False
            
        self.log_message("✅ 所有服务端可执行文件检查完成")
        return True
        
    def open_powershell_window(self, server):
        """打开PowerShell窗口运行服务端"""
        exe_path = self.release_dir / server["exe"]
        
        # 构建PowerShell命令
        # 使用Start-Process打开新窗口，并保持窗口打开
        ps_command = f"""
        Set-Location '{self.release_dir}'
        Write-Host '=== {server['description']} ({server['name']}) ===' -ForegroundColor Green
        Write-Host '端口: {server['port']}' -ForegroundColor Yellow
        Write-Host '可执行文件: {server['exe']}' -ForegroundColor Yellow
        Write-Host '工作目录: {self.release_dir}' -ForegroundColor Yellow
        Write-Host '启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}' -ForegroundColor Yellow
        Write-Host '按 Ctrl+C 停止服务端' -ForegroundColor Cyan
        Write-Host '=' * 60 -ForegroundColor Green
        Write-Host ''
        .\\{server['exe']}
        Write-Host ''
        Write-Host '=== 服务端已退出 ===' -ForegroundColor Red
        Write-Host '按任意键关闭窗口...'
        Read-Host
        """
        
        try:
            # 使用PowerShell打开新窗口
            cmd = [
                "powershell",
                "-NoExit",
                "-Command",
                ps_command
            ]
            
            # 启动新的PowerShell窗口
            process = subprocess.Popen(
                cmd,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                cwd=str(self.release_dir)
            )
            
            self.log_message(f"✅ {server['description']} PowerShell窗口已打开 (PID: {process.pid})")
            return process
            
        except Exception as e:
            self.log_message(f"❌ 打开 {server['description']} PowerShell窗口失败: {e}", "ERROR")
            return None
            
    def run_debug_mode(self):
        """运行调试模式"""
        self.log_message("=== 鸣潮服务端调试运行模式启动 ===")
        
        # 检查可执行文件
        if not self.check_release_files():
            self.log_message("❌ 可执行文件检查失败，无法启动调试模式", "ERROR")
            return False
            
        print("\n" + "=" * 80)
        print("                    鸣潮服务端调试运行模式")
        print("=" * 80)
        print("\n📋 即将打开5个PowerShell窗口，每个窗口运行一个服务端：")
        
        for i, server in enumerate(self.servers, 1):
            print(f"  {i}. {server['description']} (端口: {server['port']})")
            
        print("\n⚠️  注意事项：")
        print("  • 每个服务端将在独立的PowerShell窗口中运行")
        print("  • 可以直接看到服务端的原始输出和错误信息")
        print("  • 在各个窗口中按 Ctrl+C 可停止对应的服务端")
        print("  • 建议按顺序启动：config → hotpatch → login → gateway → game")
        print("  • 如果某个服务端启动失败，请检查配置文件和数据库连接")
        
        confirm = input("\n是否继续启动调试模式？(Y/n): ").strip().lower()
        if confirm not in ['', 'y', 'yes']:
            self.log_message("用户取消调试模式启动")
            return False
            
        self.log_message("=== 开始启动调试模式 ===")
        
        processes = []
        
        # 依次打开PowerShell窗口
        for i, server in enumerate(self.servers):
            self.log_message(f"启动 {server['description']} ({i+1}/{len(self.servers)})...")
            
            process = self.open_powershell_window(server)
            if process:
                processes.append(process)
                
                # 等待一段时间再启动下一个服务端
                if i < len(self.servers) - 1:
                    self.log_message(f"等待1秒后启动下一个服务端...")
                    time.sleep(1)
            else:
                self.log_message(f"❌ {server['description']} 启动失败", "ERROR")
                
        if processes:
            self.log_message(f"✅ 调试模式启动完成，已打开 {len(processes)} 个PowerShell窗口")
            self.log_message("=== 调试模式运行中 ===")
            
            print("\n" + "=" * 80)
            print("                    调试模式运行中")
            print("=" * 80)
            print(f"\n✅ 已成功打开 {len(processes)} 个PowerShell窗口")
            print("\n📋 服务端状态：")
            
            for i, server in enumerate(self.servers[:len(processes)]):
                print(f"  {i+1}. {server['description']} - PowerShell窗口已打开")
                
            print("\n💡 使用说明：")
            print("  • 每个服务端在独立的PowerShell窗口中运行")
            print("  • 可以直接查看服务端的输出和错误信息")
            print("  • 在对应窗口中按 Ctrl+C 停止服务端")
            print("  • 关闭PowerShell窗口也会停止对应的服务端")
            print("  • 按 Enter 键退出调试模式监控（不会停止服务端）")
            
            input("\n按 Enter 键退出调试模式监控...")
            
            self.log_message("用户退出调试模式监控")
            self.log_message("=== 调试模式监控结束 ===")
            
            print("\n✅ 调试模式监控已退出")
            print("💡 服务端仍在各自的PowerShell窗口中运行")
            print("💡 如需停止服务端，请在对应的PowerShell窗口中按 Ctrl+C")
            
            return True
        else:
            self.log_message("❌ 没有成功启动任何服务端", "ERROR")
            return False
            
def main():
    """主函数"""
    try:
        # 获取项目根目录
        current_dir = Path(__file__).parent
        project_root = current_dir.parent
        
        # 创建调试运行实例
        debug_runner = WuWaDebugRun(project_root)
        
        # 运行调试模式
        success = debug_runner.run_debug_mode()
        
        if success:
            print("\n✅ 调试模式执行完成")
        else:
            print("\n❌ 调试模式执行失败")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  用户中断操作")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 调试模式执行过程中发生错误: {e}")
        sys.exit(1)
        
if __name__ == "__main__":
    main()