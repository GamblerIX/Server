#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
鸣潮服务端完全卸载脚本

功能：
- 停止所有服务端进程（调用stop.py）
- 备份重要数据
- 删除整个Server项目文件夹
- 处理自身删除问题
"""

import os
import sys
import time
import shutil
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime

class WuWaUninstaller:
    """鸣潮服务端卸载类"""
    
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.log_file = self.project_root / "uninstall.log"
        self.stop_script = self.project_root / "py" / "stop.py"
        
        # 确保日志目录存在
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
    def log_message(self, message, log_type="INFO"):
        """记录日志消息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{log_type}] {message}"
        
        # 输出到控制台
        if log_type == "ERROR":
            print(f"❌ {message}")
        elif log_type == "WARNING":
            print(f"⚠️  {message}")
        elif log_type == "SUCCESS":
            print(f"✅ {message}")
        else:
            print(f"ℹ️  {message}")
        
        # 写入日志文件
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"写入日志失败: {e}")
    
    def stop_all_servers(self):
        """调用stop.py停止所有服务端"""
        self.log_message("=== 开始停止所有服务端 ===")
        
        if not self.stop_script.exists():
            self.log_message(f"stop.py脚本不存在: {self.stop_script}", "ERROR")
            return False
        
        try:
            # 调用stop.py脚本
            result = subprocess.run(
                [sys.executable, str(self.stop_script)],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                self.log_message("✅ 所有服务端已成功停止", "SUCCESS")
                return True
            else:
                self.log_message(f"停止服务端时出现错误: {result.stderr}", "ERROR")
                return False
                
        except subprocess.TimeoutExpired:
            self.log_message("停止服务端超时", "ERROR")
            return False
        except Exception as e:
            self.log_message(f"调用stop.py时发生错误: {e}", "ERROR")
            return False
    
    def backup_important_data(self):
        """备份重要数据"""
        self.log_message("=== 开始备份重要数据 ===")
        
        # 创建备份目录
        backup_dir = Path.home() / "Desktop" / f"Server_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        backup_items = [
            ("config", "配置文件"),
            ("logs", "日志文件"),
            ("data", "数据文件"),
            ("saves", "存档文件")
        ]
        
        backed_up = False
        
        for item, description in backup_items:
            source_path = self.project_root / item
            if source_path.exists():
                try:
                    if source_path.is_file():
                        shutil.copy2(source_path, backup_dir / item)
                    else:
                        shutil.copytree(source_path, backup_dir / item, dirs_exist_ok=True)
                    self.log_message(f"✅ 已备份{description}: {item}", "SUCCESS")
                    backed_up = True
                except Exception as e:
                    self.log_message(f"备份{description}失败: {e}", "ERROR")
        
        if backed_up:
            self.log_message(f"✅ 数据已备份到: {backup_dir}", "SUCCESS")
        else:
            self.log_message("ℹ️  没有找到需要备份的数据")
        
        return backup_dir if backed_up else None
    
    def create_deletion_script(self):
        """创建临时批处理文件来删除整个Server文件夹"""
        self.log_message("=== 创建删除脚本 ===")
        
        # 创建临时批处理文件
        temp_dir = Path(tempfile.gettempdir())
        batch_file = temp_dir / f"delete_Server_{int(time.time())}.bat"
        
        # 批处理脚本内容
        batch_content = f'''@echo off
echo 等待uninstall.py退出...
timeout /t 3 /nobreak >nul
echo 开始删除Server文件夹...
rd /s /q "{self.project_root}"
if exist "{self.project_root}" (
    echo 删除失败，可能有文件正在使用中
    pause
) else (
    echo Server文件夹已成功删除
)
echo 清理临时文件...
del "%~f0"
'''
        
        try:
            with open(batch_file, 'w', encoding='gbk') as f:
                f.write(batch_content)
            
            self.log_message(f"✅ 删除脚本已创建: {batch_file}", "SUCCESS")
            return batch_file
            
        except Exception as e:
            self.log_message(f"创建删除脚本失败: {e}", "ERROR")
            return None
    
    def complete_uninstall(self):
        """执行完全卸载"""
        self.log_message("=== 开始鸣潮服务端完全卸载 ===")
        
        # 步骤1: 停止所有服务端
        if not self.stop_all_servers():
            self.log_message("停止服务端失败，但继续卸载过程", "WARNING")
        
        # 步骤2: 备份重要数据
        backup_dir = self.backup_important_data()
        if backup_dir:
            self.log_message(f"重要数据已备份到桌面: {backup_dir.name}", "SUCCESS")
        
        # 步骤3: 创建删除脚本
        batch_file = self.create_deletion_script()
        if not batch_file:
            self.log_message("创建删除脚本失败，无法完成完全卸载", "ERROR")
            return False
        
        # 步骤4: 执行删除脚本并退出
        self.log_message("=== 准备删除Server文件夹 ===")
        self.log_message("即将启动删除脚本并退出uninstall.py")
        
        try:
            # 启动批处理文件
            subprocess.Popen([str(batch_file)], shell=True)
            self.log_message("✅ 删除脚本已启动，uninstall.py即将退出", "SUCCESS")
            return True
        except Exception as e:
            self.log_message(f"启动删除脚本失败: {e}", "ERROR")
            return False
        
def main():
    """主函数"""
    project_root = Path(__file__).parent.parent
    uninstaller = WuWaUninstaller(project_root)
    
    print("鸣潮服务端完全卸载工具")
    print("=" * 40)
    print("⚠️  警告: 此操作将完全删除Server文件夹及其所有内容！")
    print("⚠️  重要数据将自动备份到桌面")
    print("=" * 40)
    
    try:
        # 确认卸载
        confirm = input("\n确定要完全卸载鸣潮服务端吗？(输入 'YES' 确认): ").strip()
        if confirm != 'YES':
            print("取消卸载操作")
            return
        
        # 执行完全卸载
        if uninstaller.complete_uninstall():
            print("\n✅ 卸载脚本已启动，程序即将退出")
            print("删除过程将在后台继续进行...")
            time.sleep(2)  # 给用户时间看到消息
        else:
            print("\n❌ 卸载过程中出现错误")
            input("按回车键退出...")
            
    except KeyboardInterrupt:
        print("\n\n操作被用户中断")
    except Exception as e:
        print(f"\n发生错误: {e}")
        input("按回车键退出...")

if __name__ == "__main__":
    main()