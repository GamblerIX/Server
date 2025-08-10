#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
鸣潮服务端环境检查模块

功能：
- 检查系统要求（操作系统、Python版本）
- 检查发行版可执行文件
- 检查数据库连接
- 提供环境检查结果和建议
"""

import os
import sys
import platform
import subprocess
import shutil
import socket
from pathlib import Path
from typing import Dict, List, Tuple

class WuWaEnvironmentChecker:
    """鸣潮服务端环境检查器"""
    
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.wicked_waifus_path = self.project_root / "wicked-waifus-rs"
        self.release_dir = self.project_root / "release"
        self.check_results = []
        
    def add_result(self, check_name: str, passed: bool, message: str, suggestion: str = ""):
        """添加检查结果"""
        self.check_results.append({
            'name': check_name,
            'passed': passed,
            'message': message,
            'suggestion': suggestion
        })
        
    def check_operating_system(self) -> bool:
        """检查操作系统 - 仅支持Windows 10+和Windows Server 2019+"""
        try:
            os_name = platform.system()
            
            if os_name != "Windows":
                self.add_result(
                    "操作系统", False, 
                    f"❌ 不支持的操作系统: {os_name}",
                    "发行版仅支持Windows 10+和Windows Server 2019+"
                )
                return False
            
            # 获取详细的Windows版本信息
            platform_info = platform.platform()
            os_version = platform.release()
            
            # 检查Windows版本
            if "Windows-10" in platform_info or os_version == "10":
                # Windows 10
                self.add_result(
                    "操作系统", True, 
                    f"✅ Windows 10 (支持)",
                    ""
                )
                return True
            elif "Windows-11" in platform_info or os_version == "11":
                # Windows 11
                self.add_result(
                    "操作系统", True, 
                    f"✅ Windows 11 (支持)",
                    ""
                )
                return True
            elif "Server" in platform_info:
                # Windows Server版本检查
                if "2019" in platform_info or "2022" in platform_info:
                    self.add_result(
                        "操作系统", True, 
                        f"✅ Windows Server (支持)",
                        ""
                    )
                    return True
                else:
                    self.add_result(
                        "操作系统", False, 
                        f"❌ 不支持的Windows Server版本",
                        "发行版仅支持Windows Server 2019+"
                    )
                    return False
            else:
                # 其他Windows版本（如Windows 7, 8, 8.1等）
                self.add_result(
                    "操作系统", False, 
                    f"❌ 不支持的Windows版本: {os_version}",
                    "发行版仅支持Windows 10+和Windows Server 2019+"
                )
                return False
                
        except Exception as e:
            self.add_result(
                "操作系统", False, 
                f"❌ 无法检测操作系统: {e}",
                "请确保系统环境正常，仅支持Windows 10+和Windows Server 2019+"
            )
            return False
            
    def check_python_version(self) -> bool:
        """检查Python版本"""
        try:
            python_version = sys.version_info
            version_str = f"{python_version.major}.{python_version.minor}.{python_version.micro}"
            
            if python_version.major >= 3 and python_version.minor >= 8:
                self.add_result(
                    "Python版本", True, 
                    f"✅ Python {version_str}",
                    ""
                )
                return True
            else:
                self.add_result(
                    "Python版本", False, 
                    f"❌ Python版本过低: {version_str}",
                    "请升级到Python 3.8或更高版本"
                )
                return False
        except Exception as e:
            self.add_result(
                "Python版本", False, 
                f"❌ 无法检测Python版本: {e}",
                "请确保Python环境正常"
            )
            return False
            

            
    def check_executables_for_runtime(self) -> bool:
        """检查可执行文件（用于运行时）"""
        try:
            if not self.release_dir.exists():
                self.add_result(
                    "可执行文件", False, 
                    "❌ release目录不存在",
                    "请确保release目录和可执行文件存在"
                )
                return False
                
            # 检查关键可执行文件
            required_executables = [
                "wicked-waifus-config-server.exe",
                "wicked-waifus-login-server.exe",
                "wicked-waifus-gateway-server.exe",
                "wicked-waifus-game-server.exe",
                "wicked-waifus-hotpatch-server.exe"
            ]
            
            missing_files = []
            for exe in required_executables:
                exe_path = self.release_dir / exe
                if not exe_path.exists():
                    missing_files.append(exe)
                    
            if missing_files:
                # 检查是否有源码和Rust环境作为备选
                has_source = self.wicked_waifus_path.exists() and (self.wicked_waifus_path / "Cargo.toml").exists()
                has_rust = self._check_rust_available()
                
                self.add_result(
                    "可执行文件", False, 
                    f"❌ 缺少可执行文件: {', '.join(missing_files)}",
                    "请确保release目录包含所有必要的可执行文件"
                )
                return False
            else:
                self.add_result(
                    "可执行文件", True, 
                    "✅ 所有必要的可执行文件都存在",
                    ""
                )
                return True
                
        except Exception as e:
            self.add_result(
                "可执行文件", False, 
                f"❌ 检查可执行文件时出错: {e}",
                "请检查文件系统权限"
            )
            return False
            

            
    def check_postgresql_connection(self) -> bool:
        """检查PostgreSQL连接"""
        try:
            # 默认连接参数
            host = "127.0.0.1"
            port = 5432
            database = "users"
            username = "users"
            password = "password"
            
            # 首先检查端口是否开放
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5)
                    result = sock.connect_ex((host, port))
                    if result != 0:
                        self.add_result(
                            "PostgreSQL连接", False,
                            f"❌ 无法连接到PostgreSQL服务器 {host}:{port}",
                            "请确保PostgreSQL服务已启动并监听在5432端口"
                        )
                        return False
            except Exception as e:
                self.add_result(
                    "PostgreSQL连接", False,
                    f"❌ 网络连接检查失败: {e}",
                    "请检查网络配置和防火墙设置"
                )
                return False
            
            # 首先检查是否有psycopg2模块
            psycopg2_available = False
            try:
                import psycopg2
                psycopg2_available = True
            except ImportError:
                pass
            
            # 检查是否有psql命令
            psql_available = False
            try:
                result = subprocess.run(
                    ['psql', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                psql_available = result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            
            # 如果两者都不可用，提供安装建议
            if not psycopg2_available and not psql_available:
                self.add_result(
                    "PostgreSQL连接", False,
                    "❌ 无法测试PostgreSQL连接：缺少必要的连接工具",
                    "请选择以下方案之一：\n" +
                    "    1. 安装Python库: pip install psycopg2-binary\n" +
                    "    2. 安装PostgreSQL客户端工具（包含psql命令）\n" +
                    "    3. 运行: pip install -r requirements.txt 安装所有依赖"
                )
                return False
            
            # 尝试使用psycopg2进行数据库连接测试
            if psycopg2_available:
                try:
                    import psycopg2
                    
                    # 构建连接字符串
                    conn_string = f"host={host} port={port} dbname={database} user={username} password={password}"
                    
                    # 尝试连接
                    with psycopg2.connect(conn_string) as conn:
                        with conn.cursor() as cursor:
                            # 执行简单查询测试连接
                            cursor.execute("SELECT version();")
                            version = cursor.fetchone()[0]
                            
                            self.add_result(
                                "PostgreSQL连接", True,
                                f"✅ PostgreSQL连接成功\n    数据库: {database}@{host}:{port}\n    版本: {version[:50]}...",
                                ""
                            )
                            return True
                            
                except Exception as e:
                    error_msg = str(e)
                    if "authentication failed" in error_msg.lower():
                        suggestion = "请检查数据库用户名和密码是否正确"
                    elif "database" in error_msg.lower() and "does not exist" in error_msg.lower():
                        suggestion = "请确保数据库'users'已创建"
                    elif "connection refused" in error_msg.lower():
                        suggestion = "请确保PostgreSQL服务已启动"
                    else:
                        suggestion = "请检查PostgreSQL配置和网络连接"
                        
                    self.add_result(
                        "PostgreSQL连接", False,
                        f"❌ PostgreSQL连接失败: {error_msg}",
                        suggestion
                    )
                    return False
            
            # 如果psycopg2不可用但psql可用，使用psql命令测试
            elif psql_available:
                try:
                    # 设置环境变量避免密码提示
                    env = os.environ.copy()
                    env['PGPASSWORD'] = password
                    
                    # 执行psql命令测试连接
                    result = subprocess.run(
                        ['psql', '-h', host, '-p', str(port), '-U', username, '-d', database, '-c', 'SELECT version();'],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        env=env
                    )
                    
                    if result.returncode == 0:
                        self.add_result(
                            "PostgreSQL连接", True,
                            f"✅ PostgreSQL连接成功（通过psql命令）\n    数据库: {database}@{host}:{port}",
                            "建议安装psycopg2以获得更好的连接测试: pip install psycopg2-binary"
                        )
                        return True
                    else:
                        error_msg = result.stderr.strip() if result.stderr else "未知错误"
                        self.add_result(
                            "PostgreSQL连接", False,
                            f"❌ PostgreSQL连接失败: {error_msg}",
                            "请检查数据库配置、用户权限和密码"
                        )
                        return False
                        
                except Exception as e:
                    self.add_result(
                        "PostgreSQL连接", False,
                        f"❌ 使用psql命令测试连接时出错: {e}",
                        "请检查PostgreSQL客户端工具安装"
                    )
                    return False

                
        except Exception as e:
            self.add_result(
                "PostgreSQL连接", False,
                f"❌ PostgreSQL连接检查时出错: {e}",
                "请检查系统环境和网络配置"
            )
            return False
            

            
    def check_release_directory(self) -> bool:
        """检查release目录和可执行文件"""
        try:
            if not self.release_dir.exists():
                self.add_result(
                    "Release目录", False, 
                    "❌ release目录不存在",
                    "请确保release目录存在"
                )
                return False
                
            # 检查关键可执行文件
            required_executables = [
                "wicked-waifus-config-server.exe",
                "wicked-waifus-login-server.exe",
                "wicked-waifus-gateway-server.exe",
                "wicked-waifus-game-server.exe",
                "wicked-waifus-hotpatch-server.exe"
            ]
            
            missing_files = []
            for exe in required_executables:
                exe_path = self.release_dir / exe
                if not exe_path.exists():
                    missing_files.append(exe)
                    
            if missing_files:
                self.add_result(
                        "Release目录", False, 
                        f"❌ 缺少可执行文件: {', '.join(missing_files)}",
                        "请确保release目录包含所有必要的可执行文件"
                    )
                return False
            else:
                self.add_result(
                    "Release目录", True, 
                    "✅ release目录存在且包含所有必要的可执行文件",
                    ""
                )
                return True
                
        except Exception as e:
            self.add_result(
                "Release目录", False, 
                f"❌ 检查release目录时出错: {e}",
                "请检查文件系统权限"
            )
            return False
            
    def check_dependencies(self) -> bool:
        """检查Python依赖"""
        try:
            required_modules = ['psutil', 'toml']
            missing_modules = []
            
            for module in required_modules:
                try:
                    __import__(module)
                except ImportError:
                    missing_modules.append(module)
                    
            if missing_modules:
                self.add_result(
                    "Python依赖", False, 
                    f"❌ 缺少Python模块: {', '.join(missing_modules)}",
                    "请运行: pip install -r requirements.txt"
                )
                return False
            else:
                self.add_result(
                    "Python依赖", True, 
                    "✅ 所有必要的Python模块已安装",
                    ""
                )
                return True
                
        except Exception as e:
            self.add_result(
                "Python依赖", False, 
                f"❌ 检查Python依赖时出错: {e}",
                "请检查Python环境"
            )
            return False
            
    def run_all_checks(self, silent: bool = False) -> Tuple[bool, List[Dict]]:
        """运行所有环境检查
        
        Args:
            silent: 是否静默模式（不输出到控制台）
            
        Returns:
            Tuple[bool, List[Dict]]: (是否全部通过, 检查结果列表)
        """
        self.check_results.clear()
        
        if not silent:
            print("\n=== 环境检查 ===")
            
        # 执行所有检查
        checks = [
            self.check_operating_system(),
            self.check_python_version(),
            self.check_dependencies(),
            self.check_release_directory(),
            self.check_postgresql_connection()
        ]
        
        # 输出结果
        if not silent:
            for result in self.check_results:
                print(result['message'])
                if result['suggestion']:
                    print(f"    建议: {result['suggestion']}")
                    
        # 检查是否全部通过
        all_passed = all(checks)
        
        if not silent:
            if all_passed:
                print("\n✅ 环境检查通过，可以启动服务端")
            else:
                print("\n❌ 环境检查未通过，请解决上述问题后重试")
            print()
            
        return all_passed, self.check_results
        
    def check_for_startup(self) -> bool:
        """启动前的环境检查（运行时检查）
        
        Returns:
            bool: 是否可以启动服务端
        """
        print("正在检查运行环境...")
        
        # 运行时关键检查
        critical_checks = [
            self.check_python_version(),
            self.check_dependencies(),
            self.check_executables_for_runtime(),  # 运行时检查可执行文件
            self.check_postgresql_connection()     # 运行时必须检查数据库连接
        ]
        
        # 检查关键项目是否通过
        if not all(critical_checks):
            print("❌ 运行环境检查失败，请解决问题后重试")
            return False
            
        print("✅ 运行环境检查通过")
        return True
        


def main():
    """主函数 - 用于独立运行环境检查"""
    import sys
    from pathlib import Path
    
    # 获取项目根目录
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    # 创建检查器
    checker = WuWaEnvironmentChecker(project_root)
    
    # 运行检查
    all_passed, results = checker.run_all_checks()
    
    # 返回适当的退出码
    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()