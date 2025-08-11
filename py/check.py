#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import shutil
import socket
from pathlib import Path
from typing import Dict, List, Tuple

class WuWaEnvironmentChecker:
    
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.wicked_waifus_path = self.project_root / "wicked-waifus-rs"
        self.release_dir = self.project_root / "release"
        self.check_results = []
        
    def add_result(self, check_name: str, passed: bool, message: str, suggestion: str = ""):
        self.check_results.append({
            'name': check_name,
            'passed': passed,
            'message': message,
            'suggestion': suggestion
        })
        
    def check_operating_system(self) -> bool:
        try:
            os_name = platform.system()
            
            if os_name != "Windows":
                self.add_result(
                    "操作系统", False, 
                    f"[错误] 不支持的操作系统: {os_name}",
                    "发行版仅支持Windows 10+和Windows Server 2019+"
                )
                return False
            

            platform_info = platform.platform()
            os_version = platform.release()
            

            if "Windows-10" in platform_info or os_version == "10":

                self.add_result(
                    "操作系统", True, 
                    f"[成功] Windows 10 (支持)",
                    ""
                )
                return True
            elif "Windows-11" in platform_info or os_version == "11":

                self.add_result(
                    "操作系统", True, 
                    f"[成功] Windows 11 (支持)",
                    ""
                )
                return True
            elif "Server" in platform_info:

                if "2019" in platform_info or "2022" in platform_info:
                    self.add_result(
                        "操作系统", True, 
                        f"[成功] Windows Server (支持)",
                        ""
                    )
                    return True
                else:
                    self.add_result(
                        "操作系统", False, 
                        f"[错误] 不支持的Windows Server版本",
                        "发行版仅支持Windows Server 2019+"
                    )
                    return False
            else:

                self.add_result(
                    "操作系统", False, 
                    f"[错误] 不支持的Windows版本: {os_version}",
                    "发行版仅支持Windows 10+和Windows Server 2019+"
                )
                return False
                
        except Exception as e:
            self.add_result(
                "操作系统", False, 
                f"[错误] 无法检测操作系统: {e}",
                "请确保系统环境正常，仅支持Windows 10+和Windows Server 2019+"
            )
            return False
            
    def check_python_version(self) -> bool:
        try:
            python_version = sys.version_info
            version_str = f"{python_version.major}.{python_version.minor}.{python_version.micro}"
            
            if python_version.major >= 3 and python_version.minor >= 8:
                self.add_result(
                    "Python版本", True, 
                    f"[成功] Python {version_str}",
                    ""
                )
                return True
            else:
                self.add_result(
                    "Python版本", False, 
                    f"[错误] Python版本过低: {version_str}",
                    "请升级到Python 3.8或更高版本"
                )
                return False
        except Exception as e:
            self.add_result(
                "Python版本", False, 
                f"[错误] 无法检测Python版本: {e}",
                "请确保Python环境正常"
            )
            return False
            

            
    def check_executables_for_runtime(self) -> bool:
        try:
            if not self.release_dir.exists():
                self.add_result(
                    "可执行文件", False, 
                    "[错误] release目录不存在",
                    "请确保release目录和可执行文件存在"
                )
                return False
                

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

                has_source = self.wicked_waifus_path.exists() and (self.wicked_waifus_path / "Cargo.toml").exists()
                has_rust = self._check_rust_available()
                
                self.add_result(
                    "可执行文件", False, 
                    f"[错误] 缺少可执行文件: {', '.join(missing_files)}",
                    "请确保release目录包含所有必要的可执行文件"
                )
                return False
            else:
                self.add_result(
                    "可执行文件", True, 
                    "[成功] 所有必要的可执行文件都存在",
                    ""
                )
                return True
                
        except Exception as e:
            self.add_result(
                "可执行文件", False, 
                f"[错误] 检查可执行文件时出错: {e}",
                "请检查文件系统权限"
            )
            return False
            

            
    def check_postgresql_connection(self) -> bool:
        try:

            host = "127.0.0.1"
            port = 5432
            database = "users"
            username = "users"
            password = "password"
            

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5)
                    result = sock.connect_ex((host, port))
                    if result != 0:
                        self.add_result(
                            "PostgreSQL连接", False,
                            f"[错误] 无法连接到PostgreSQL服务器 {host}:{port}",
                            "请确保PostgreSQL服务已启动并监听在5432端口"
                        )
                        return False
            except Exception as e:
                self.add_result(
                    "PostgreSQL连接", False,
                    f"[错误] 网络连接检查失败: {e}",
                    "请检查网络配置和防火墙设置"
                )
                return False
            

            psycopg2_available = False
            try:
                import psycopg2
                psycopg2_available = True
            except ImportError:
                pass
            

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
            

            if not psycopg2_available and not psql_available:
                self.add_result(
                    "PostgreSQL连接", False,
                    "[错误] 无法测试PostgreSQL连接：缺少必要的连接工具",
                    "请选择以下方案之一：\n" +
                    "    1. 安装Python库: pip install psycopg2-binary\n" +
                    "    2. 安装PostgreSQL客户端工具（包含psql命令）\n" +
                    "    3. 运行: pip install -r requirements.txt 安装所有依赖"
                )
                return False
            

            if psycopg2_available:
                try:
                    import psycopg2
                    

                    conn_string = f"host={host} port={port} dbname={database} user={username} password={password}"
                    

                    with psycopg2.connect(conn_string) as conn:
                        with conn.cursor() as cursor:
    
                            cursor.execute("SELECT version();")
                            version = cursor.fetchone()[0]
                            
                            self.add_result(
                                "PostgreSQL连接", True,
                                f"[成功] PostgreSQL连接成功\n    数据库: {database}@{host}:{port}\n    版本: {version[:50]}...",
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
                        f"[错误] PostgreSQL连接失败: {error_msg}",
                        suggestion
                    )
                    return False
            

            elif psql_available:
                try:

                    env = os.environ.copy()
                    env['PGPASSWORD'] = password
                    

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
                            f"[成功] PostgreSQL连接成功（通过psql命令）\n    数据库: {database}@{host}:{port}",
                            "建议安装psycopg2以获得更好的连接测试: pip install psycopg2-binary"
                        )
                        return True
                    else:
                        error_msg = result.stderr.strip() if result.stderr else "未知错误"
                        self.add_result(
                            "PostgreSQL连接", False,
                            f"[错误] PostgreSQL连接失败: {error_msg}",
                            "请检查数据库配置、用户权限和密码"
                        )
                        return False
                        
                except Exception as e:
                    self.add_result(
                        "PostgreSQL连接", False,
                        f"[错误] 使用psql命令测试连接时出错: {e}",
                        "请检查PostgreSQL客户端工具安装"
                    )
                    return False

                
        except Exception as e:
            self.add_result(
                "PostgreSQL连接", False,
                f"[错误] PostgreSQL连接检查时出错: {e}",
                "请检查系统环境和网络配置"
            )
            return False
            

            
    def check_release_directory(self) -> bool:
        try:
            if not self.release_dir.exists():
                self.add_result(
                    "Release目录", False, 
                    "[错误] release目录不存在",
                    "请确保release目录存在"
                )
                return False
                

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
                        f"[错误] 缺少可执行文件: {', '.join(missing_files)}",
                        "请确保release目录包含所有必要的可执行文件"
                    )
                return False
            else:
                self.add_result(
                    "Release目录", True, 
                    "[成功] release目录存在且包含所有必要的可执行文件",
                    ""
                )
                return True
                
        except Exception as e:
            self.add_result(
                "Release目录", False, 
                f"[错误] 检查release目录时出错: {e}",
                "请检查文件系统权限"
            )
            return False
            
    def check_dependencies(self) -> bool:
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
                    f"[错误] 缺少Python模块: {', '.join(missing_modules)}",
                    "请运行: pip install -r requirements.txt"
                )
                return False
            else:
                self.add_result(
                    "Python依赖", True, 
                    "[成功] 所有必要的Python模块已安装",
                    ""
                )
                return True
                
        except Exception as e:
            self.add_result(
                "Python依赖", False, 
                f"[错误] 检查Python依赖时出错: {e}",
                "请检查Python环境"
            )
            return False
            
    def run_all_checks(self, silent: bool = False) -> Tuple[bool, List[Dict]]:
        self.check_results.clear()
        
        if not silent:
            print("\n=== 环境检查 ===")
            

        checks = [
            self.check_operating_system(),
            self.check_python_version(),
            self.check_dependencies(),
            self.check_release_directory(),
            self.check_postgresql_connection()
        ]
        

        if not silent:
            for result in self.check_results:
                print(result['message'])
                if result['suggestion']:
                    print(f"    建议: {result['suggestion']}")
                    

        all_passed = all(checks)
        
        if not silent:
            if all_passed:
                print("\n[成功] 环境检查通过，可以启动服务端")
            else:
                print("\n[错误] 环境检查未通过，请解决上述问题后重试")
            print()
            
        return all_passed, self.check_results
        
    def check_for_startup(self) -> bool:
        print("正在检查运行环境...")
        

        critical_checks = [
            self.check_python_version(),
            self.check_dependencies(),
            self.check_executables_for_runtime(),
            self.check_postgresql_connection()
        ]
        

        if not all(critical_checks):
            print("[错误] 运行环境检查失败，请解决问题后重试")
            return False
            
        print("[成功] 运行环境检查通过")
        return True
        


def main():
    import sys
    from pathlib import Path
    

    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    

    checker = WuWaEnvironmentChecker(project_root)
    

    all_passed, results = checker.run_all_checks()
    

    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()