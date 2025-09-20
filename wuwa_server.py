#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
鸣潮服务端一键运行工具 - 合并版本
整合了原有的所有功能模块：环境检查、服务端运行、状态监控、日志管理、调试运行等
"""

import os
import re
import sys
import time
import gzip
import json
import shutil
import psutil
import socket
import subprocess
import logging
import logging.handlers
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Event
from collections import defaultdict, Counter


# ==================== 配置管理模块 ====================
class WuWaConfig:
    """统一配置管理类 - 消除硬编码"""
    
    # 服务器配置
    SERVERS = [
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
    
    # 路径配置
    PATHS = {
        "client_binary": "Client/Client/Binaries/Win64",
        "launcher_exe": "launcher.exe",
        "pak_file": "rr_fixes_100_p.pak",
        "config_file": "config.toml",
        "logs_dir": "logs",
        "release_dir": "release"
    }
    
    # 文件扩展名
    FILE_EXTENSIONS = {
        "dll": "*.dll",
        "exe": "*.exe",
        "log": "*.log",
        "toml": "*.toml"
    }
    
    # 超时和重试配置
    TIMEOUTS = {
        "server_start": 30,
        "server_stop": 10,
        "process_check": 5,
        "file_operation": 10
    }
    
    # 日志配置
    LOG_CONFIG = {
        "format": "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        "date_format": "%Y-%m-%d %H:%M:%S",
        "level": logging.INFO,
        "max_bytes": 10 * 1024 * 1024,  # 10MB
        "backup_count": 5
    }
    
    # 性能优化配置
    PERFORMANCE = {
        "max_concurrent_servers": 5,  # 最大并发启动服务端数量
        "startup_delay": 2,  # 服务端启动间隔（秒）
        "cache_enabled": True,  # 启用缓存机制
        "cache_ttl": 300,  # 缓存生存时间（秒）
        "thread_pool_size": 4  # 线程池大小
    }
    
    # 日志文件配置
    LOG_FILES = {
        "config": "config-server.log",
        "hotpatch": "hotpatch-server.log", 
        "login": "login-server.log",
        "gateway": "gateway-server.log",
        "game": "game-server.log"
    }


# ==================== 异常类定义 ====================

class WuWaException(Exception):
    """鸣潮工具基础异常类"""
    def __init__(self, message: str, error_code: int = 1000):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

    def __str__(self):
        return f"[错误码:{self.error_code}] {self.message}"


class WuWaConfigException(WuWaException):
    """配置相关异常"""
    def __init__(self, message: str):
        super().__init__(message, 1001)


class WuWaFileException(WuWaException):
    """文件操作异常"""
    def __init__(self, message: str):
        super().__init__(message, 1002)


class WuWaProcessException(WuWaException):
    """进程操作异常"""
    def __init__(self, message: str):
        super().__init__(message, 1003)


class WuWaNetworkException(WuWaException):
    """网络相关异常"""
    def __init__(self, message: str):
        super().__init__(message, 1004)


class WuWaServerException(WuWaException):
    """服务器相关异常"""
    def __init__(self, message: str):
        super().__init__(message, 1005)


class WuWaEnvironmentException(WuWaException):
    """环境检查异常"""
    def __init__(self, message: str):
        super().__init__(message, 1006)


class WuWaVersionException(WuWaException):
    """版本管理异常"""
    def __init__(self, message: str):
        super().__init__(message, 1007)


class WuWaClientException(WuWaException):
    """客户端相关异常"""
    def __init__(self, message: str):
        super().__init__(message, 1008)


# 错误码常量
class ErrorCodes:
    """错误码定义"""
    # 通用错误 1000-1099
    UNKNOWN_ERROR = 1000
    
    # 配置错误 1100-1199
    CONFIG_FILE_NOT_FOUND = 1101
    CONFIG_PARSE_ERROR = 1102
    CONFIG_VALIDATION_ERROR = 1103
    
    # 文件错误 1200-1299
    FILE_NOT_FOUND = 1201
    FILE_PERMISSION_ERROR = 1202
    FILE_IO_ERROR = 1203
    DIRECTORY_NOT_FOUND = 1204
    
    # 进程错误 1300-1399
    PROCESS_START_ERROR = 1301
    PROCESS_STOP_ERROR = 1302
    PROCESS_NOT_FOUND = 1303
    PROCESS_ACCESS_DENIED = 1304
    
    # 网络错误 1400-1499
    PORT_IN_USE = 1401
    PORT_NOT_ACCESSIBLE = 1402
    NETWORK_CONNECTION_ERROR = 1403
    
    # 服务器错误 1500-1599
    SERVER_START_ERROR = 1501
    SERVER_STOP_ERROR = 1502
    SERVER_CONFIG_ERROR = 1503
    
    # 环境错误 1600-1699
    OS_NOT_SUPPORTED = 1601
    DEPENDENCY_MISSING = 1602
    ENVIRONMENT_SETUP_ERROR = 1603
    
    # 版本错误 1700-1799
    VERSION_NOT_FOUND = 1701
    VERSION_INVALID = 1702
    VERSION_CONFLICT = 1703
    
    # 客户端错误 1800-1899
    CLIENT_NOT_FOUND = 1801
    CLIENT_PATCH_ERROR = 1802
    CLIENT_VERSION_MISMATCH = 1803


# ==================== 公共基类 ====================
class BaseWuWaComponent:
    """鸣潮工具组件基类 - 提供公共功能"""
    
    def __init__(self, project_root: Path, component_name: str):
        self.project_root = project_root
        self.component_name = component_name
        self.logs_dir = project_root / WuWaConfig.PATHS["logs_dir"]
        self.logs_dir.mkdir(exist_ok=True)
        
        # 初始化缓存系统
        self._cache = {}
        self._cache_timestamps = {}
        
        # 初始化日志系统
        self._setup_logger()
        
    def _setup_logger(self) -> None:
        """设置组件专用日志器"""
        self.logger = logging.getLogger(f"WuWa.{self.component_name}")
        
        # 避免重复添加处理器
        if not self.logger.handlers:
            # 文件处理器
            log_file = self.logs_dir / f"{self.component_name.lower()}.log"
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=WuWaConfig.LOG_CONFIG["max_bytes"],
                backupCount=WuWaConfig.LOG_CONFIG["backup_count"],
                encoding="utf-8"
            )
            file_handler.setFormatter(logging.Formatter(
                WuWaConfig.LOG_CONFIG["format"],
                WuWaConfig.LOG_CONFIG["date_format"]
            ))
            
            # 控制台处理器
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(
                WuWaConfig.LOG_CONFIG["format"],
                WuWaConfig.LOG_CONFIG["date_format"]
            ))
            
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
            self.logger.setLevel(WuWaConfig.LOG_CONFIG["level"])
    
    def log_message(self, message: str, log_type: str = "INFO") -> None:
        """统一的日志记录方法"""
        level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }
        
        level = level_map.get(log_type.upper(), logging.INFO)
        self.logger.log(level, message)
    
    def handle_exception(self, e: Exception, context: str = "") -> None:
        """统一的异常处理方法"""
        if isinstance(e, WuWaException):
            self.log_message(f"{context}: {e.message} (错误码: {e.error_code})", "ERROR")
        else:
            # 将通用异常转换为具体的WuWa异常
            if isinstance(e, FileNotFoundError):
                wuwa_e = WuWaFileException(f"文件未找到: {str(e)}")
                wuwa_e.error_code = ErrorCodes.FILE_NOT_FOUND
            elif isinstance(e, PermissionError):
                wuwa_e = WuWaFileException(f"权限不足: {str(e)}")
                wuwa_e.error_code = ErrorCodes.FILE_PERMISSION_ERROR
            elif isinstance(e, OSError):
                wuwa_e = WuWaFileException(f"系统错误: {str(e)}")
                wuwa_e.error_code = ErrorCodes.FILE_IO_ERROR
            elif isinstance(e, psutil.NoSuchProcess):
                wuwa_e = WuWaProcessException(f"进程不存在: {str(e)}")
                wuwa_e.error_code = ErrorCodes.PROCESS_NOT_FOUND
            elif isinstance(e, psutil.AccessDenied):
                wuwa_e = WuWaProcessException(f"进程访问被拒绝: {str(e)}")
                wuwa_e.error_code = ErrorCodes.PROCESS_ACCESS_DENIED
            else:
                wuwa_e = WuWaException(f"未知错误: {str(e)}")
                wuwa_e.error_code = ErrorCodes.UNKNOWN_ERROR
            
            self.log_message(f"{context}: {wuwa_e.message} (错误码: {wuwa_e.error_code})", "ERROR")
    
    def validate_path(self, path: Path, must_exist: bool = True) -> bool:
        """路径验证方法"""
        try:
            if must_exist and not path.exists():
                raise WuWaFileException(f"路径不存在: {path}")
                # 设置具体错误码
                if path.is_file():
                    raise WuWaFileException(f"文件不存在: {path}")
                else:
                    raise WuWaFileException(f"目录不存在: {path}")
            return True
        except WuWaException:
            raise  # 重新抛出WuWa异常
        except Exception as e:
            self.handle_exception(e, "路径验证失败")
            return False
    
    def safe_file_operation(self, operation: callable, *args, **kwargs) -> Any:
        """安全的文件操作包装器"""
        try:
            return operation(*args, **kwargs)
        except (FileNotFoundError, PermissionError, OSError) as e:
            raise WuWaFileException(f"文件操作失败: {str(e)}")
        except Exception as e:
            self.handle_exception(e, "文件操作异常")
            raise
    
    def safe_process_operation(self, operation: callable, *args, **kwargs) -> Any:
        """安全的进程操作包装器"""
        try:
            return operation(*args, **kwargs)
        except psutil.NoSuchProcess as e:
            raise WuWaProcessException(f"进程不存在: {str(e)}")
        except psutil.AccessDenied as e:
            raise WuWaProcessException(f"进程访问被拒绝: {str(e)}")
        except Exception as e:
            self.handle_exception(e, "进程操作异常")
            raise
    
    def get_cached_data(self, key: str) -> Optional[Any]:
        """获取缓存数据"""
        if not WuWaConfig.PERFORMANCE["cache_enabled"]:
            return None
            
        if key not in self._cache:
            return None
            
        # 检查缓存是否过期
        timestamp = self._cache_timestamps.get(key, 0)
        if time.time() - timestamp > WuWaConfig.PERFORMANCE["cache_ttl"]:
            self.clear_cache_key(key)
            return None
            
        return self._cache[key]
    
    def set_cached_data(self, key: str, data: Any) -> None:
        """设置缓存数据"""
        if not WuWaConfig.PERFORMANCE["cache_enabled"]:
            return
            
        self._cache[key] = data
        self._cache_timestamps[key] = time.time()
    
    def clear_cache_key(self, key: str) -> None:
        """清除指定缓存键"""
        self._cache.pop(key, None)
        self._cache_timestamps.pop(key, None)
    
    def clear_all_cache(self) -> None:
        """清除所有缓存"""
        self._cache.clear()
        self._cache_timestamps.clear()
        self.log_message("已清除所有缓存数据")


class WuWaConfigManager(BaseWuWaComponent):
    """配置管理类 - 处理动态路径检测和配置文件生成"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "ConfigManager")
    def detect_script_directory(self) -> Path:
        """自动检测脚本所在目录"""
        script_dir = Path(__file__).parent.absolute()
        self.log_message(f"检测到脚本目录: {script_dir}")
        return script_dir
    
    def find_client_directory(self, base_path: Path) -> Optional[Path]:
        """查找客户端目录，通过'Client\\Client\\Binaries\\Win64'标识"""
        self.log_message(f"在 {base_path} 中搜索客户端目录...")
        
        # 使用配置类中的路径
        client_binary_path = WuWaConfig.PATHS["client_binary"]
        
        # 搜索可能的客户端路径
        possible_paths = [
            base_path / client_binary_path,
            base_path.parent / client_binary_path,
            base_path.parent.parent / client_binary_path
        ]
        
        # 也搜索当前目录的所有子目录
        try:
            for item in base_path.rglob("*"):
                if item.is_dir() and item.name == "Win64":
                    parent_path = item.parent
                    if (parent_path.name == "Binaries" and 
                        parent_path.parent.name == "Client" and 
                        parent_path.parent.parent.name == "Client"):
                        possible_paths.append(item)
        except Exception as e:
            self.handle_exception(e, "搜索客户端目录")
        
        for client_path in possible_paths:
            if self.validate_path(client_path, must_exist=True):
                self.log_message(f"找到客户端目录: {client_path}")
                return client_path
        
        self.log_message("未找到客户端目录", "WARNING")
        return None
    
    def find_dll_files(self, client_path: Path) -> List[str]:
        """在客户端目录中查找DLL文件"""
        dll_files = []
        try:
            for dll_file in client_path.glob("*.dll"):
                if "wicked-waifus" in dll_file.name.lower():
                    dll_files.append(str(dll_file))
                    self.log_message(f"找到DLL文件: {dll_file.name}")
        except Exception as e:
            self.log_message(f"搜索DLL文件时出错: {e}", "ERROR")
        
        return dll_files
    
    def update_config_paths(self, config_path: Path, client_path: Path, dll_files: List[str]) -> bool:
        """更新配置文件中的路径，使用新的TOML格式规范"""
        try:
            # 备份原配置文件
            backup_path = config_path.with_suffix('.toml.backup')
            if config_path.exists():
                shutil.copy2(config_path, backup_path)
                self.log_message(f"已备份配置文件到: {backup_path}")
            
            # 获取项目根目录路径（不包括盘符）
            script_dir = self.get_script_directory()
            project_root = script_dir.parent  # Server的父目录
            
            # 构建标准化路径
            drive_letter = str(project_root).split(':')[0]  # 获取盘符
            path_without_drive = str(project_root).replace(f'{drive_letter}:', '').replace('\\', '/')
            
            # 构建标准化的客户端路径
            client_bin_path = f"{drive_letter}:{path_without_drive}/Client/Client/Binaries/Win64"
            
            # 构建DLL文件路径列表
            dll_list = []
            if dll_files:
                for dll_file in dll_files:
                    # 提取DLL文件名
                    dll_name = Path(dll_file).name
                    dll_path = f"{client_bin_path}/{dll_name}"
                    dll_list.append(dll_path)
            
            # 写入新的配置文件（完全覆盖）
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write("[launcher]\n")
                f.write("executable_file = 'Client-Win64-Shipping.exe'\n")
                f.write("cmd_line_args = '-fileopenlog'\n")
                f.write(f"current_dir = '{client_bin_path}'\n")
                f.write(f"dll_list = {dll_list}\n")
                f.write("\n[environment]\n")
                f.write("#vars = ['TESTVAR1=AAAAAA', 'TESTVAR2=AAAAAA']\n")
                f.write("#use_system_env = true\n")
                f.write("#environment_append = false\n")
            
            self.log_message(f"已更新配置文件: {config_path}")
            self.log_message(f"  current_dir: {client_bin_path}")
            if dll_list:
                self.log_message(f"  dll_list: {len(dll_list)} 个文件")
            
            return True
            
        except Exception as e:
            self.log_message(f"更新配置文件失败: {e}", "ERROR")
            return False
    
    def process_all_configs(self, version: Optional[str] = None) -> bool:
        """处理所有版本的配置文件"""
        script_dir = self.detect_script_directory()
        client_path = self.find_client_directory(script_dir)
        
        if not client_path:
            self.log_message("无法找到客户端目录，跳过配置文件更新", "WARNING")
            return False
        
        dll_files = self.find_dll_files(client_path)
        if not dll_files:
            self.log_message("未找到DLL文件，跳过配置文件更新", "WARNING")
            return False
        
        release_dir = self.project_root / "release"
        updated_count = 0
        
        if version:
            # 处理指定版本
            version_dir = release_dir / version
            config_path = version_dir / "config.toml"
            if config_path.exists():
                if self.update_config_paths(config_path, client_path, dll_files):
                    updated_count += 1
        else:
            # 处理所有版本
            for version_dir in release_dir.iterdir():
                if version_dir.is_dir():
                    config_path = version_dir / "config.toml"
                    if config_path.exists():
                        if self.update_config_paths(config_path, client_path, dll_files):
                            updated_count += 1
            
            # 也处理根目录的config.toml
            root_config = release_dir / "config.toml"
            if root_config.exists():
                if self.update_config_paths(root_config, client_path, dll_files):
                    updated_count += 1
        
        self.log_message(f"共更新了 {updated_count} 个配置文件")
        return updated_count > 0


class WuWaClientPatcher(BaseWuWaComponent):
    """客户端补丁管理类 - 处理客户端文件复制和补丁应用"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "ClientPatcher")
    def get_script_directory(self) -> Path:
        """获取脚本所在目录"""
        return Path(__file__).parent.absolute()
    
    def patch_client(self, version: str) -> bool:
        """应用客户端补丁"""
        try:
            self.log_message(f"开始应用客户端补丁，版本: {version}")
            
            # 获取项目根目录路径
            script_dir = self.get_script_directory()
            project_root = script_dir.parent  # Server的父目录
            
            # 构建路径
            drive_letter = str(project_root).split(':')[0]  # 获取盘符
            path_without_drive = str(project_root).replace(f'{drive_letter}:', '').replace('\\', '/')
            
            # 源文件目录（Server/release/版本号）
            source_dir = script_dir / "release" / version
            if not source_dir.exists():
                self.log_message(f"版本目录不存在: {source_dir}", "ERROR")
                return False
            
            # 目标目录
            client_bin_dir = Path(f"{drive_letter}:{path_without_drive}/Client/Client/Binaries/Win64")
            client_pak_dir = Path(f"{drive_letter}:{path_without_drive}/Client/Client/Content/Paks")
            
            # 确保目标目录存在
            client_bin_dir.mkdir(parents=True, exist_ok=True)
            client_pak_dir.mkdir(parents=True, exist_ok=True)
            
            # 需要复制的文件列表
            files_to_copy = []
            
            # 1. 自动查找所有.dll文件
            dll_files = list(source_dir.glob("*.dll"))
            for dll_file in dll_files:
                files_to_copy.append({
                    "source_file": dll_file,
                    "target_dir": client_bin_dir,
                    "description": f"DLL文件 ({dll_file.name})"
                })
            
            # 2. 添加其他固定文件
            other_files = [
                {
                    "pattern": "rr_fixes_100_p.pak",
                    "target_dir": client_pak_dir,
                    "description": "PAK文件"
                },
                {
                    "pattern": "launcher.exe",
                    "target_dir": client_bin_dir,
                    "description": "启动器"
                },
                {
                    "pattern": "config.toml",
                    "target_dir": client_bin_dir,
                    "description": "配置文件"
                }
            ]
            
            # 添加其他文件到复制列表
            for file_info in other_files:
                source_file = source_dir / file_info["pattern"]
                if source_file.exists():
                    files_to_copy.append({
                        "source_file": source_file,
                        "target_dir": file_info["target_dir"],
                        "description": file_info["description"]
                    })
            
            copied_count = 0
            for file_info in files_to_copy:
                source_file = file_info["source_file"]
                target_dir = file_info["target_dir"]
                description = file_info["description"]
                
                target_file = target_dir / source_file.name
                try:
                    shutil.copy2(source_file, target_file)
                    self.log_message(f"[成功] 复制{description}: {source_file.name}")
                    copied_count += 1
                except Exception as e:
                    self.log_message(f"[错误] 复制{description}失败: {e}", "ERROR")
            
            if copied_count > 0:
                self.log_message(f"客户端补丁应用完成，共复制 {copied_count} 个文件")
                return True
            else:
                self.log_message("没有文件被复制", "WARNING")
                return False
                
        except Exception as e:
            self.log_message(f"应用客户端补丁失败: {e}", "ERROR")
            return False


class WuWaServerEnvironmentChecker(BaseWuWaComponent):
    """服务端环境检查类 - 专门检查服务端运行环境"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "ServerEnvironmentChecker")
    
    def check_operating_system(self) -> bool:
        """检查操作系统"""
        self.log_message("=== 检查操作系统 ===")
        
        if os.name == 'nt':
            try:
                import platform
                system_info = platform.system()
                version_info = platform.version()
                self.log_message(f"[成功] 操作系统: {system_info} {version_info}")
                return True
            except Exception as e:
                self.log_message(f"[错误] 获取系统信息失败: {e}", "ERROR")
                return False
        else:
            self.log_message("[错误] 不支持的操作系统，需要Windows系统", "ERROR")
            return False
    
    def check_python_version(self) -> bool:
        """检查Python版本"""
        self.log_message("=== 检查Python版本 ===")
        
        try:
            version = sys.version_info
            version_str = f"{version.major}.{version.minor}.{version.micro}"
            
            if version.major >= 3 and version.minor >= 8:
                self.log_message(f"[成功] Python版本: {version_str}")
                return True
            else:
                self.log_message(f"[错误] Python版本过低: {version_str}，需要3.8或更高版本", "ERROR")
                return False
        except Exception as e:
            self.log_message(f"[错误] 检查Python版本失败: {e}", "ERROR")
            return False
    
    def check_server_executable_files(self, version: Optional[str] = None) -> bool:
        """检查服务端可执行文件"""
        self.log_message("=== 检查服务端可执行文件 ===")
        
        release_dir = self.project_root / "release"
        
        # 如果指定了版本，使用指定版本目录
        if version:
            version_dir = release_dir / version
            if version_dir.exists():
                release_dir = version_dir
                self.log_message(f"[信息] 使用指定版本目录: {release_dir}")
            else:
                self.log_message(f"[错误] 指定版本目录不存在: {version_dir}", "ERROR")
                return False
        else:
            # 如果没有指定版本，尝试自动选择最新版本
            if release_dir.exists():
                version_dirs = [d for d in release_dir.iterdir() if d.is_dir() and d.name.replace('.', '').isdigit()]
                if version_dirs:
                    # 按版本号排序，选择最新版本
                    latest_version = max(version_dirs, key=lambda x: tuple(map(int, x.name.split('.'))))
                    release_dir = latest_version
                    self.log_message(f"[信息] 自动选择最新版本目录: {release_dir}")
                else:
                    # 如果没有版本子目录，使用release根目录
                    self.log_message(f"[信息] 使用release根目录: {release_dir}")
        
        if not release_dir.exists():
            self.log_message(f"[错误] Release目录不存在: {release_dir}", "ERROR")
            return False
        
        required_files = [
            "wicked-waifus-config-server.exe",
            "wicked-waifus-hotpatch-server.exe", 
            "wicked-waifus-login-server.exe",
            "wicked-waifus-gateway-server.exe",
            "wicked-waifus-game-server.exe"
        ]
        
        missing_files = []
        for exe_file in required_files:
            exe_path = release_dir / exe_file
            if exe_path.exists():
                self.log_message(f"[成功] {exe_file}")
            else:
                self.log_message(f"[错误] {exe_file} (缺失)", "ERROR")
                missing_files.append(exe_file)
        
        if missing_files:
            self.log_message(f"[错误] 缺失文件: {', '.join(missing_files)}", "ERROR")
            return False
        
        self.log_message("[成功] 所有服务端可执行文件检查完成")
        return True
    
    def check_port_availability(self) -> bool:
        """检查服务端端口可用性"""
        self.log_message("=== 检查服务端端口可用性 ===")
        
        required_ports = [10001, 10002, 5500, 10003, 10004]
        occupied_ports = []
        
        # 使用并发检查所有端口，提高检查速度
        import concurrent.futures
        
        def check_single_port(port):
            """检查单个端口的状态"""
            is_occupied = self._is_port_occupied(port)
            if is_occupied:
                self.log_message(f"[警告] 端口 {port} 已被占用", "WARNING")
                return port, True
            else:
                self.log_message(f"[成功] 端口 {port} 可用")
                return port, False
        
        # 并发检查所有端口
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_port = {executor.submit(check_single_port, port): port for port in required_ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_occupied = future.result()
                if is_occupied:
                    occupied_ports.append(port)
        
        if occupied_ports:
            self.log_message(f"[警告] 被占用的端口: {occupied_ports}", "WARNING")
            return False
        
        self.log_message("[成功] 所有服务端端口检查完成")
        return True
    
    def _is_port_occupied(self, port: int) -> bool:
        """检查端口是否被占用"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)  # 100ms超时
                result = s.connect_ex(('127.0.0.1', port))
                return result == 0
        except Exception:
            return False
    
    def run_server_checks(self, version: Optional[str] = None) -> bool:
        """运行服务端环境检查"""
        self.log_message("开始服务端环境检查...")
        
        checks = [
            ("操作系统", self.check_operating_system),
            ("Python版本", self.check_python_version),
            ("服务端可执行文件", lambda: self.check_server_executable_files(version)),
            ("服务端端口可用性", self.check_port_availability)
        ]
        
        results = {}
        for check_name, check_func in checks:
            try:
                results[check_name] = check_func()
            except Exception as e:
                self.log_message(f"[错误] {check_name}检查失败: {e}", "ERROR")
                results[check_name] = False
        
        # 输出检查结果摘要
        self.log_message("=== 服务端环境检查结果摘要 ===")
        passed_count = sum(results.values())
        total_count = len(results)
        
        for check_name, result in results.items():
            status = "[通过]" if result else "[失败]"
            self.log_message(f"{status} {check_name}")
        
        self.log_message(f"服务端检查完成: {passed_count}/{total_count} 项通过")
        
        # 关键检查项
        critical_checks = ["操作系统", "Python版本", "服务端可执行文件"]
        critical_passed = all(results.get(check, False) for check in critical_checks)
        
        if critical_passed:
            self.log_message("[成功] 服务端关键环境检查通过，可以启动服务端")
            return True
        else:
            self.log_message("[错误] 服务端关键环境检查失败，请修复后重试", "ERROR")
            return False


class WuWaClientEnvironmentChecker(BaseWuWaComponent):
    """客户端环境检查类 - 专门检查客户端运行环境"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "ClientEnvironmentChecker")
    
    def check_client_directory(self) -> bool:
        """检查客户端目录是否存在"""
        self.log_message("=== 检查客户端目录 ===")
        
        script_dir = Path(__file__).parent.absolute()
        client_path = self._find_client_directory(script_dir)
        
        if client_path:
            self.log_message(f"[成功] 找到客户端目录: {client_path}")
            return True
        else:
            self.log_message("[错误] 未找到客户端目录", "ERROR")
            return False
    
    def check_client_files(self, version: Optional[str] = None) -> bool:
        """检查客户端必需文件"""
        self.log_message("=== 检查客户端必需文件 ===")
        
        script_dir = Path(__file__).parent.absolute()
        client_path = self._find_client_directory(script_dir)
        
        if not client_path:
            self.log_message("[错误] 客户端目录不存在，无法检查文件", "ERROR")
            if version:
                self.log_message(f"[提示] 请执行命令修补客户端: python wuwa_server.py --patchclient --version {version}", "INFO")
            else:
                self.log_message("[提示] 请执行命令修补客户端: python wuwa_server.py --patchclient --version <版本号>", "INFO")
            return False
        
        # 检查必需文件列表
        required_files = [
            ("rr_fixes_100_p.pak", "补丁文件"),
            ("launcher.exe", "启动器"),
            ("config.toml", "配置文件")
        ]
        
        missing_files = []
        found_files = []
        
        for filename, description in required_files:
            file_path = client_path / filename
            if file_path.exists():
                self.log_message(f"[成功] {description}: {filename}")
                found_files.append(filename)
            else:
                self.log_message(f"[错误] {description}缺失: {filename}", "ERROR")
                missing_files.append(filename)
        
        if missing_files:
            self.log_message(f"[错误] 缺失文件: {', '.join(missing_files)}", "ERROR")
            if version:
                self.log_message(f"[提示] 请执行命令修补客户端: python wuwa_server.py --patchclient --version {version}", "INFO")
            else:
                self.log_message("[提示] 请执行命令修补客户端: python wuwa_server.py --patchclient --version <版本号>", "INFO")
            return False
        else:
            self.log_message(f"[成功] 所有必需文件检查完成: {', '.join(found_files)}")
            self.log_message("[提示] 由于DLL文件名可能变化，本次检查未包含DLL文件验证", "INFO")
            return True
    
    def check_client_dll_files(self) -> bool:
        """检查客户端DLL文件"""
        self.log_message("=== 检查客户端DLL文件 ===")
        
        script_dir = Path(__file__).parent.absolute()
        client_path = self._find_client_directory(script_dir)
        
        if not client_path:
            self.log_message("[错误] 客户端目录不存在，无法检查DLL文件", "ERROR")
            return False
        
        dll_files = []
        try:
            for dll_file in client_path.glob("*.dll"):
                if "wicked-waifus" in dll_file.name.lower():
                    dll_files.append(dll_file)
                    self.log_message(f"[成功] 找到DLL文件: {dll_file.name}")
        except Exception as e:
            self.log_message(f"[错误] 搜索DLL文件时出错: {e}", "ERROR")
            return False
        
        if dll_files:
            self.log_message(f"[成功] 找到 {len(dll_files)} 个DLL文件")
            return True
        else:
            self.log_message("[警告] 未找到客户端DLL文件", "WARNING")
            return False
    
    def check_rust_installation(self) -> bool:
        """检查Rust安装（客户端补丁需要）"""
        self.log_message("=== 检查Rust安装（客户端补丁需要） ===")
        
        try:
            result = subprocess.run(
                ["rustc", "--version"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                version = result.stdout.strip()
                self.log_message(f"[成功] Rust已安装: {version}")
                return True
            else:
                self.log_message("[警告] Rust未安装或版本过低", "WARNING")
                return False
        except (FileNotFoundError):
            self.log_message("[警告] Rust未安装", "WARNING")
            return False
        except Exception as e:
            self.log_message(f"[错误] 检查Rust安装失败: {e}", "ERROR")
            return False
    
    def _find_client_directory(self, base_path: Path) -> Optional[Path]:
        """查找客户端目录"""
        # 使用配置类中的路径
        client_binary_path = WuWaConfig.PATHS["client_binary"]
        
        # 搜索可能的客户端路径
        possible_paths = [
            base_path / client_binary_path,
            base_path.parent / client_binary_path,
            base_path.parent.parent / client_binary_path
        ]
        
        # 也搜索当前目录的所有子目录
        try:
            for item in base_path.rglob("*"):
                if item.is_dir() and item.name == "Win64":
                    parent_path = item.parent
                    if (parent_path.name == "Binaries" and 
                        parent_path.parent.name == "Client" and 
                        parent_path.parent.parent.name == "Client"):
                        possible_paths.append(item)
        except Exception:
            pass
        
        for client_path in possible_paths:
            if client_path.exists() and client_path.is_dir():
                return client_path
        
        return None
    
    def run_client_checks(self, version: Optional[str] = None) -> bool:
        """运行客户端环境检查"""
        self.log_message("开始客户端环境检查...")
        
        # 直接调用检查方法，避免lambda函数重复调用
        directory_result = self.check_client_directory()
        files_result = self.check_client_files(version)
        
        results = {
            "客户端目录": directory_result,
            "客户端必需文件": files_result
        }
        
        # 输出检查结果摘要
        self.log_message("=== 客户端环境检查结果摘要 ===")
        passed_count = sum(results.values())
        total_count = len(results)
        
        for check_name, result in results.items():
            status = "[通过]" if result else "[失败]"
            self.log_message(f"{status} {check_name}")
        
        self.log_message(f"客户端检查完成: {passed_count}/{total_count} 项通过")
        
        # 关键检查项
        critical_checks = ["客户端目录", "客户端必需文件"]
        critical_passed = all(results.get(check, False) for check in critical_checks)
        
        if critical_passed:
            self.log_message("[成功] 客户端关键环境检查通过")
            return True
        else:
            self.log_message("[错误] 客户端关键环境检查失败，请修复后重试", "ERROR")
            return False


class WuWaEnvironmentChecker(BaseWuWaComponent):
    """环境检查类 - 统一管理服务端和客户端环境检查"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "EnvironmentChecker")
        self.server_checker = WuWaServerEnvironmentChecker(project_root)
        self.client_checker = WuWaClientEnvironmentChecker(project_root)
    
    def run_server_checks(self, version: Optional[str] = None) -> bool:
        """运行服务端环境检查"""
        self.log_message("=== 开始服务端环境检查 ===")
        result = self.server_checker.run_server_checks(version)
        
        if result:
            self.log_message("[成功] 服务端环境检查通过")
        else:
            self.log_message("[失败] 服务端环境检查未通过", "ERROR")
        
        return result
    
    def run_client_checks(self, version: Optional[str] = None) -> bool:
        """运行客户端环境检查"""
        self.log_message("=== 开始客户端环境检查 ===")
        result = self.client_checker.run_client_checks(version)
        
        if result:
            self.log_message("[成功] 客户端环境检查通过")
        else:
            self.log_message("[失败] 客户端环境检查未通过", "ERROR")
        
        return result
    
    def run_all_checks(self, version: Optional[str] = None, check_client: bool = True) -> bool:
        """运行所有环境检查
        
        Args:
            version: 服务端版本
            check_client: 是否检查客户端环境
        """
        self.log_message("=== 开始完整环境检查 ===")
        
        # 运行服务端检查
        server_result = self.run_server_checks(version)
        
        # 运行客户端检查（可选）
        client_result = True
        if check_client:
            client_result = self.run_client_checks(version)
        else:
            self.log_message("[信息] 跳过客户端环境检查")
        
        # 综合结果
        overall_result = server_result and client_result
        
        self.log_message("=== 环境检查总结 ===")
        self.log_message(f"服务端检查: {'通过' if server_result else '失败'}")
        if check_client:
            self.log_message(f"客户端检查: {'通过' if client_result else '失败'}")
        
        if overall_result:
            self.log_message("[成功] 所有环境检查通过")
        else:
            self.log_message("[失败] 环境检查存在问题，请修复后重试", "ERROR")
        
        return overall_result
    
    # 保持向后兼容性的方法
    def check_operating_system(self) -> bool:
        """检查操作系统（向后兼容）"""
        return self.server_checker.check_operating_system()
    
    def check_python_version(self) -> bool:
        """检查Python版本（向后兼容）"""
        return self.server_checker.check_python_version()
    
    def check_executable_files(self, version: Optional[str] = None) -> bool:
        """检查可执行文件（向后兼容）"""
        return self.server_checker.check_server_executable_files(version)
    
    def check_rust_installation(self) -> bool:
        """检查Rust安装（向后兼容）"""
        return self.client_checker.check_rust_installation()
    
    def check_port_availability(self) -> bool:
        """检查端口可用性（向后兼容）"""
        return self.server_checker.check_port_availability()


class WuWaRun(BaseWuWaComponent):
    """服务端运行类 - 负责启动和管理服务端进程"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "ServerRun")
        self.release_dir = project_root / WuWaConfig.PATHS["release_dir"]
        self.selected_version = None
        
        # 使用配置类中的服务器配置
        self.servers = WuWaConfig.SERVERS
    
    def set_release_version(self, version: str) -> None:
        """设置release版本目录"""
        try:
            if not version:
                # 如果没有指定版本，尝试自动选择最新版本
                base_release_dir = self.project_root / "release"
                if base_release_dir.exists():
                    version_dirs = [d for d in base_release_dir.iterdir() if d.is_dir() and d.name.replace('.', '').isdigit()]
                    if version_dirs:
                        # 按版本号排序，选择最新版本
                        latest_version = max(version_dirs, key=lambda x: tuple(map(int, x.name.split('.'))))
                        self.release_dir = latest_version
                        self.selected_version = latest_version.name
                        self.log_message(f"自动选择最新版本目录: {self.release_dir}")
                    else:
                        # 如果没有版本子目录，使用release根目录
                        self.release_dir = base_release_dir
                        self.selected_version = None
                        self.log_message(f"使用release根目录: {self.release_dir}")
                return
                
            candidate = self.project_root / "release" / version
            if candidate.exists() and candidate.is_dir():
                self.release_dir = candidate
                self.selected_version = version
                self.log_message(f"已选择版本目录: {self.release_dir}")
            else:
                self.log_message(f"[警告] 版本目录不存在: {candidate}，使用默认release目录", "WARNING")
        except Exception as e:
            self.log_message(f"[错误] 设置版本目录失败: {e}", "ERROR")
    
    def start_server(self, server_index: int) -> Optional[subprocess.Popen]:
        """启动单个服务端"""
        if server_index < 0 or server_index >= len(self.servers):
            self.log_message(f"[错误] 无效的服务端索引: {server_index}", "ERROR")
            return None
        
        server = self.servers[server_index]
        exe_path = self.release_dir / server["exe"]
        
        if not exe_path.exists():
            self.log_message(f"[错误] 可执行文件不存在: {exe_path}", "ERROR")
            return None
        
        try:
            self.log_message(f"启动 {server['description']}...")
            
            log_file_path = self.logs_dir / f"{server['name']}.log"
            
            with open(log_file_path, "a", encoding="utf-8") as log_file:
                process = subprocess.Popen(
                    [str(exe_path)],
                    cwd=str(self.release_dir),
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    text=True
                )
            
            self.log_message(f"[成功] {server['description']} 已启动 (PID: {process.pid})")
            return process
            
        except Exception as e:
            self.log_message(f"[错误] 启动 {server['description']} 失败: {e}", "ERROR")
            return None
    
    def start_all_servers(self) -> List[subprocess.Popen]:
        """启动所有服务端（并发版本）"""
        self.log_message("=== 开始并发启动所有服务端 ===")
        
        if not self.release_dir.exists():
            self.log_message(f"[错误] Release目录不存在: {self.release_dir}", "ERROR")
            return []
        
        # 检查缓存中是否有进程信息
        cache_key = "running_processes"
        cached_processes = self.get_cached_data(cache_key)
        if cached_processes:
            self.log_message("从缓存中获取到运行中的进程信息")
            return cached_processes
        
        processes = []
        
        # 使用线程池并发启动服务端
        max_workers = min(len(self.servers), WuWaConfig.PERFORMANCE["max_concurrent_servers"])
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有启动任务
            future_to_server = {
                executor.submit(self._start_server_with_delay, i): (i, server) 
                for i, server in enumerate(self.servers)
            }
            
            # 收集结果
            for future in as_completed(future_to_server):
                server_index, server = future_to_server[future]
                try:
                    process = future.result()
                    if process:
                        processes.append(process)
                        self.log_message(f"[成功] {server['description']} 并发启动完成")
                    else:
                        self.log_message(f"[错误] {server['description']} 并发启动失败", "ERROR")
                except Exception as e:
                    self.log_message(f"[错误] {server['description']} 并发启动异常: {e}", "ERROR")
        
        if processes:
            self.log_message(f"[成功] 并发启动完成，共启动 {len(processes)}/{len(self.servers)} 个服务端")
            # 缓存进程信息
            self.set_cached_data(cache_key, processes)
        else:
            self.log_message("[错误] 没有成功启动任何服务端", "ERROR")
        
        self.log_message("=== 并发服务端启动完成 ===")
        return processes
    
    def _start_server_with_delay(self, server_index: int) -> Optional[subprocess.Popen]:
        """带延迟的服务端启动（用于并发启动）"""
        # 添加启动延迟，避免同时启动造成资源竞争
        delay = server_index * WuWaConfig.PERFORMANCE["startup_delay"]
        if delay > 0:
            time.sleep(delay)
            
        return self.start_server(server_index)
    
    def stop_all_servers(self) -> bool:
        """停止所有服务端进程"""
        self.log_message("=== 开始停止所有服务端 ===")
        
        stopped_count = 0
        
        for server in self.servers:
            processes = self._find_processes_by_name(server["name"])
            for process in processes:
                if self._stop_process(process, server["name"]):
                    stopped_count += 1
        
        if stopped_count > 0:
            self.log_message(f"[成功] 总共停止了 {stopped_count} 个服务端进程")
        else:
            self.log_message("[信息] 没有找到运行中的服务端进程")
        
        self.log_message("=== 服务端停止完成 ===")
        return stopped_count > 0
    
    def _find_processes_by_name(self, process_name: str) -> List[psutil.Process]:
        """根据进程名查找进程"""
        processes = []
        try:
            # 使用更高效的进程查找方式，减少延时
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if process_name.lower() in proc.info['name'].lower():
                        processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.log_message(f"查找进程时发生错误: {e}", "ERROR")
        return processes
    
    def _stop_process(self, process: psutil.Process, server_name: str) -> bool:
        """停止进程"""
        try:
            self.log_message(f"停止进程: {server_name} (PID: {process.pid})")
            
            # 发送终止信号
            process.terminate()
            
            # 检查进程是否已经停止，不等待
            try:
                if process.is_running():
                    # 如果进程仍在运行，强制杀死
                    process.kill()
            except psutil.NoSuchProcess:
                # 进程已经不存在，说明已经停止
                pass
            
            self.log_message(f"[成功] {server_name} 已停止")
            return True
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.log_message(f"停止 {server_name} 时发生错误: {e}", "ERROR")
            return False
        except Exception as e:
            self.log_message(f"停止 {server_name} 时发生未知错误: {e}", "ERROR")
            return False


class WuWaStatus(BaseWuWaComponent):
    """状态监控类 - 监控服务端运行状态"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "StatusMonitor")
        
        # 将服务器配置转换为字典格式以便查找
        self.servers = {
            server["name"].replace("wicked-waifus-", "").replace("-server", ""): {
                "name": server["name"],
                "port": server["port"],
                "description": server["description"]
            }
            for server in WuWaConfig.SERVERS
        }
        
        self.monitoring = False
        self.monitor_event = Event()
    
    def check_port_status(self, port: int) -> Dict[str, Any]:
        """检查端口状态"""
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                    return {
                        "listening": True,
                        "pid": conn.pid,
                        "address": f"{conn.laddr.ip}:{conn.laddr.port}"
                    }
        except (psutil.AccessDenied, AttributeError):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    result = s.connect_ex(('127.0.0.1', port))
                    if result == 0:
                        return {
                            "listening": True,
                            "pid": None,
                            "address": f"127.0.0.1:{port}"
                        }
            except Exception:
                pass
                
        return {
            "listening": False,
            "pid": None,
            "address": None
        }
    
    def find_server_processes(self) -> Dict[str, Dict[str, Any]]:
        """查找服务端进程"""
        processes = {}
        server_names = {
            server_key: [server['name'].lower(), f"{server['name']}.exe".lower()]
            for server_key, server in self.servers.items()
        }
        
        try:
            all_processes = list(psutil.process_iter([
                'pid', 'name', 'cmdline', 'create_time', 
                'cpu_percent', 'memory_info'
            ]))
            
            for proc in all_processes:
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower() if proc_info['name'] else ''
                    cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
                    
                    for server_key, names in server_names.items():
                        if any(name in proc_name or name in cmdline.lower() for name in names):
                            try:
                                cpu_percent = proc.cpu_percent(interval=None)
                                memory_info = proc_info['memory_info']
                                
                                processes[server_key] = {
                                    'pid': proc_info['pid'],
                                    'name': proc_info['name'],
                                    'cmdline': cmdline,
                                    'create_time': proc_info['create_time'],
                                    'cpu_percent': cpu_percent,
                                    'memory_mb': memory_info.rss / 1024 / 1024 if memory_info else 0,
                                    'uptime': time.time() - proc_info['create_time'] if proc_info['create_time'] else 0
                                }
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
                            break
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
        except Exception as e:
            self.log_message(f"查找服务端进程时发生错误: {e}", "ERROR")
            
        return processes
    
    def get_system_info(self) -> Optional[Dict[str, Any]]:
        """获取系统信息"""
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            cpu_count = psutil.cpu_count()
            
            memory = psutil.virtual_memory()
            memory_total_gb = memory.total / 1024 / 1024 / 1024
            memory_used_gb = memory.used / 1024 / 1024 / 1024
            memory_percent = memory.percent
            
            disk = psutil.disk_usage(str(self.project_root))
            disk_total_gb = disk.total / 1024 / 1024 / 1024
            disk_used_gb = disk.used / 1024 / 1024 / 1024
            disk_percent = (disk.used / disk.total) * 100
            
            return {
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count
                },
                "memory": {
                    "total_gb": memory_total_gb,
                    "used_gb": memory_used_gb,
                    "percent": memory_percent
                },
                "disk": {
                    "total_gb": disk_total_gb,
                    "used_gb": disk_used_gb,
                    "percent": disk_percent
                }
            }
        except Exception as e:
            self.log_message(f"获取系统信息时发生错误: {e}", "ERROR")
            return None
    
    def format_uptime(self, uptime: float) -> str:
        """格式化运行时间"""
        if isinstance(uptime, timedelta):
            total_seconds = int(uptime.total_seconds())
        else:
            total_seconds = int(uptime)
            
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        if days > 0:
            return f"{days}天 {hours}小时 {minutes}分钟"
        elif hours > 0:
            return f"{hours}小时 {minutes}分钟"
        elif minutes > 0:
            return f"{minutes}分钟 {seconds}秒"
        else:
            return f"{seconds}秒"
    
    def show_status(self, detailed: bool = True) -> None:
        """显示服务端状态（带缓存优化）"""
        # 检查缓存
        cache_key = f"server_status_{detailed}"
        cached_status = self.get_cached_data(cache_key)
        if cached_status:
            self.log_message("从缓存中获取服务端状态信息", "DEBUG")
            for line in cached_status:
                self.log_message(line, "INFO")
            return
        
        # 收集状态信息
        status_lines = []
        
        status_lines.append("=" * 80)
        status_lines.append("                        鸣潮服务端状态监控")
        status_lines.append("=" * 80)
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status_lines.append(f"检查时间: {current_time}")
        
        processes = self.find_server_processes()
        
        status_lines.append("[服务端状态]")
        status_lines.append("-" * 80)
        
        running_count = 0
        for server_key, server in self.servers.items():
            port = server['port']
            description = server['description']
            
            port_status = self.check_port_status(port)
            
            if server_key in processes:
                proc_info = processes[server_key]
                status = "[运行中]"
                running_count += 1
                
                if detailed:
                    status_lines.append(f"\n{description} (端口 {port}):")
                    status_lines.append(f"  状态: {status}")
                    status_lines.append(f"  进程ID: {proc_info['pid']}")
                    status_lines.append(f"  运行时间: {self.format_uptime(proc_info['uptime'])}")
                    status_lines.append(f"  CPU使用率: {proc_info['cpu_percent']:.1f}%")
                    status_lines.append(f"  内存使用: {proc_info['memory_mb']:.1f} MB")
                    if port_status['listening']:
                        status_lines.append(f"  监听地址: {port_status['address']}")
                else:
                    status_line = (
                        f"{description:15} | 端口 {port:4} | {status} | "
                        f"PID {proc_info['pid']:6} | {self.format_uptime(proc_info['uptime'])}"
                    )
                    status_lines.append(status_line)
            else:
                status = "[未运行]"
                if detailed:
                    status_lines.append(f"\n{description} (端口 {port}):")
                    status_lines.append(f"  状态: {status}")
                    if port_status['listening']:
                        status_lines.append(f"  端口状态: 被其他进程占用 ({port_status['address']})")
                    else:
                        status_lines.append(f"  端口状态: 空闲")
                else:
                    status_line = f"{description:15} | 端口 {port:4} | {status}"
                    status_lines.append(status_line)
        
        # 添加总计信息
        status_lines.append(f"\n总计运行数量: {running_count}/{len(self.servers)}")
        
        # 添加系统资源信息
        if detailed:
            status_lines.append("\n[系统资源]")
            status_lines.append("-" * 80)
            
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            status_lines.append(f"CPU使用率: {cpu_percent:.1f}%")
            status_lines.append(f"内存使用: {memory.used / 1024**3:.1f} GB / {memory.total / 1024**3:.1f} GB ({memory.percent:.1f}%)")
            status_lines.append(f"磁盘使用: {disk.used / 1024**3:.1f} GB / {disk.total / 1024**3:.1f} GB ({disk.percent:.1f}%)")
        
        status_lines.append("=" * 80)
        
        # 缓存状态信息
        self.set_cached_data(cache_key, status_lines)
        
        # 输出状态信息
        for line in status_lines:
            self.log_message(line, "INFO")
        
        self.log_message("=" * 80, "INFO")


class WuWaLogs(BaseWuWaComponent):
    """日志管理类 - 管理和分析日志文件"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "LogsManager")
        
        # 使用配置类中的日志文件配置
        self.log_files = WuWaConfig.LOG_FILES
        
        self.log_colors = {
            "ERROR": "\033[91m",
            "WARN": "\033[93m",
            "WARNING": "\033[93m",
            "INFO": "\033[92m",
            "DEBUG": "\033[94m",
            "RESET": "\033[0m"
        }
    
    def get_log_files_info(self) -> Dict[str, Dict[str, Any]]:
        """获取日志文件信息"""
        files_info = {}
        
        for log_key, log_filename in self.log_files.items():
            log_path = self.logs_dir / log_filename
            
            if log_path.exists():
                stat = log_path.stat()
                files_info[log_key] = {
                    "filename": log_filename,
                    "path": log_path,
                    "size_bytes": stat.st_size,
                    "size_mb": stat.st_size / 1024 / 1024,
                    "modified_time": datetime.fromtimestamp(stat.st_mtime),
                    "exists": True
                }
            else:
                files_info[log_key] = {
                    "filename": log_filename,
                    "path": log_path,
                    "size_bytes": 0,
                    "size_mb": 0,
                    "modified_time": None,
                    "exists": False
                }
                
        return files_info
    
    def show_log_files_list(self) -> None:
        """显示日志文件列表"""
        self.log_message("=" * 80, "INFO")
        self.log_message("                        鸣潮服务端日志文件", "INFO")
        self.log_message("=" * 80, "INFO")
        
        files_info = self.get_log_files_info()
        
        self.log_message(f"{'序号':<4} {'类型':<12} {'文件名':<25} {'大小':<10} {'最后修改时间':<20} {'状态':<8}", "INFO")
        self.log_message("-" * 80, "INFO")
        
        for i, (log_key, info) in enumerate(files_info.items(), 1):
            if info['exists']:
                size_str = f"{info['size_mb']:.1f} MB"
                mtime_str = info['modified_time'].strftime("%Y-%m-%d %H:%M:%S")
                status = "存在"
            else:
                size_str = "0 MB"
                mtime_str = "-"
                status = "不存在"
                
            self.log_message(f"{i:<4} {log_key:<12} {info['filename']:<25} {size_str:<10} {mtime_str:<20} {status:<8}", "INFO")
            
        self.log_message("=" * 80, "INFO")
    
    def read_log_file(self, log_key: str, lines: int = 50) -> None:
        """读取日志文件"""
        if log_key not in self.log_files:
            self.log_message(f"错误: 未知的日志类型 '{log_key}'", "ERROR")
            return
            
        log_path = self.logs_dir / self.log_files[log_key]
        
        if not log_path.exists():
            self.log_message(f"日志文件不存在: {log_path}", "ERROR")
            return
        
        self.log_message(f"[文件] 日志文件: {log_path.name}", "INFO")
        self.log_message(f"[内容] 最后 {lines} 行内容:", "INFO")
        self.log_message("-" * 80, "INFO")
        
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
                last_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
                
                for line in last_lines:
                    colored_line = self._colorize_log_line(line.rstrip())
                    self.log_message(colored_line, "INFO")
                    
        except UnicodeDecodeError:
            try:
                with open(log_path, "r", encoding="gbk") as f:
                    all_lines = f.readlines()
                    last_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
                    
                    for line in last_lines:
                        colored_line = self._colorize_log_line(line.rstrip())
                        self.log_message(colored_line, "INFO")
            except Exception as e:
                self.log_message(f"无法读取文件 (编码错误): {e}", "ERROR")
                
        self.log_message("-" * 80, "INFO")
    
    def _colorize_log_line(self, line: str) -> str:
        """为日志行添加颜色"""
        for level, color in self.log_colors.items():
            if level == "RESET":
                continue
                
            if f"[{level}]" in line or f" {level} " in line:
                return f"{color}{line}{self.log_colors['RESET']}"
                
        return line
    
    def clean_logs(self, days_to_keep: int = 7) -> None:
        """清理日志文件"""
        self.log_message(f"[清理] 清理日志文件 (保留最近 {days_to_keep} 天)", "INFO")
        self.log_message("=" * 60, "INFO")
        
        cutoff_time = datetime.now() - timedelta(days=days_to_keep)
        cleaned_files = []
        
        for log_key, log_filename in self.log_files.items():
            log_path = self.logs_dir / log_filename
            
            if log_path.exists():
                stat = log_path.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime)
                
                if mtime < cutoff_time:
                    log_path.unlink()
                    cleaned_files.append(log_filename)
        
        if cleaned_files:
            self.log_message(f"[成功] 已清理 {len(cleaned_files)} 个文件:", "INFO")
            for filename in cleaned_files:
                self.log_message(f"  - {filename}", "INFO")
        else:
            self.log_message("[信息] 没有需要清理的文件", "INFO")
            
        self.log_message("=" * 60, "INFO")


class WuWaDebugRun(BaseWuWaComponent):
    """调试运行类 - 在独立窗口中运行服务端以便调试"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "DebugRun")
        self.release_dir = self.project_root / WuWaConfig.PATHS["release_dir"]
        self.selected_version = None
        
        # 使用配置类中的服务器配置
        self.servers = WuWaConfig.SERVERS
    
    def set_release_version(self, version: str) -> None:
        """设置release版本目录"""
        try:
            if not version:
                # 如果没有指定版本，尝试自动选择最新版本
                base_release_dir = self.project_root / "release"
                if base_release_dir.exists():
                    version_dirs = [d for d in base_release_dir.iterdir() if d.is_dir() and d.name.replace('.', '').isdigit()]
                    if version_dirs:
                        # 按版本号排序，选择最新版本
                        latest_version = max(version_dirs, key=lambda x: tuple(map(int, x.name.split('.'))))
                        self.release_dir = latest_version
                        self.selected_version = latest_version.name
                        self.log_message(f"自动选择最新版本目录: {self.release_dir}")
                    else:
                        # 如果没有版本子目录，使用release根目录
                        self.release_dir = base_release_dir
                        self.selected_version = None
                        self.log_message(f"使用release根目录: {self.release_dir}")
                return
                
            candidate = self.project_root / "release" / version
            if candidate.exists() and candidate.is_dir():
                self.release_dir = candidate
                self.selected_version = version
                self.log_message(f"已选择版本目录: {self.release_dir}")
            else:
                self.log_message(f"[警告] 版本目录不存在: {candidate}，使用默认release目录", "WARNING")
        except Exception as e:
            self.log_message(f"[错误] 设置版本目录失败: {e}", "ERROR")
    
    def check_release_files(self) -> bool:
        """检查release文件"""
        self.log_message("=== 检查服务端可执行文件 ===")
        
        if not self.release_dir.exists():
            self.log_message(f"[错误] Release目录不存在: {self.release_dir}", "ERROR")
            return False
        
        try:
            if self.selected_version:
                self.log_message(f"[信息] 当前检查的版本目录: {self.release_dir}")
        except Exception:
            pass
            
        missing_files = []
        for server in self.servers:
            exe_path = self.release_dir / server["exe"]
            if exe_path.exists():
                self.log_message(f"[成功] {server['description']} - {server['exe']}")
            else:
                self.log_message(f"[错误] {server['description']} - {server['exe']} (缺失)", "ERROR")
                missing_files.append(server["exe"])
        
        if missing_files:
            self.log_message(f"[错误] 缺失文件: {', '.join(missing_files)}", "ERROR")
            return False
            
        self.log_message("[成功] 所有服务端可执行文件检查完成")
        return True
    
    def open_powershell_window(self, server: Dict[str, Any]) -> Optional[subprocess.Popen]:
        """打开PowerShell窗口运行服务端"""
        exe_path = self.release_dir / server["exe"]
        
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
            cmd = [
                "powershell",
                "-NoExit",
                "-Command",
                ps_command
            ]
            
            process = subprocess.Popen(
                cmd,
                cwd=str(self.release_dir),
                creationflags=(
                    subprocess.CREATE_NEW_CONSOLE | 
                    subprocess.CREATE_NEW_PROCESS_GROUP | 
                    subprocess.DETACHED_PROCESS
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True
            )
            
            self.log_message(f"[成功] {server['description']} PowerShell窗口已打开 (PID: {process.pid})")
            return process
            
        except Exception as e:
            self.log_message(f"[错误] 打开 {server['description']} PowerShell窗口失败: {e}", "ERROR")
            return None
    
    def run_debug_mode(self) -> bool:
        """运行调试模式"""
        self.log_message("=== 鸣潮服务端调试运行模式启动 ===")
        
        if not self.check_release_files():
            self.log_message("[错误] 可执行文件检查失败，无法启动调试模式", "ERROR")
            return False
            
        self.log_message("=" * 80, "INFO")
        self.log_message("                    鸣潮服务端调试运行模式", "INFO")
        self.log_message("=" * 80, "INFO")
        self.log_message("📋 即将打开5个PowerShell窗口，每个窗口运行一个服务端：", "INFO")
        
        for i, server in enumerate(self.servers, 1):
            self.log_message(f"  {i}. {server['description']} (端口: {server['port']})", "INFO")
            
        self.log_message("[注意] 注意事项：", "INFO")
        self.log_message("  - 每个服务端将在独立的PowerShell窗口中运行", "INFO")
        self.log_message("  - 可以直接看到服务端的原始输出和错误信息", "INFO")
        self.log_message("  - 在各个窗口中按 Ctrl+C 可停止对应的服务端", "INFO")
        self.log_message("  - 建议按顺序启动：config → hotpatch → login → gateway → game", "INFO")
        self.log_message("  - 如果某个服务端启动失败，请检查配置文件和数据库连接", "INFO")
        
        confirm = input("\n是否继续启动调试模式？(Y/n): ").strip().lower()
        if confirm not in ['', 'y', 'yes']:
            self.log_message("用户取消调试模式启动")
            return False
            
        self.log_message("=== 开始启动调试模式 ===")
        
        processes = []
        
        for i, server in enumerate(self.servers):
            self.log_message(f"启动 {server['description']} ({i+1}/{len(self.servers)})...")
            
            process = self.open_powershell_window(server)
            if process:
                processes.append(process)
                if i < len(self.servers) - 1:
                    self.log_message(f"准备启动下一个服务端...")
            else:
                self.log_message(f"[错误] {server['description']} 启动失败", "ERROR")
                
        if processes:
            self.log_message(f"[成功] 调试模式启动完成，已打开 {len(processes)} 个PowerShell窗口")
            self.log_message("=== 调试模式运行中 ===")
            
            self.log_message("=" * 80, "INFO")
            self.log_message("                    调试模式运行中", "INFO")
            self.log_message("=" * 80, "INFO")
            self.log_message(f"[成功] 已成功打开 {len(processes)} 个PowerShell窗口", "INFO")
            self.log_message("[状态] 服务端状态：", "INFO")
            
            for i, server in enumerate(self.servers[:len(processes)]):
                self.log_message(f"  {i+1}. {server['description']} - PowerShell窗口已打开", "INFO")
                
            self.log_message("[说明] 使用说明：", "INFO")
            self.log_message("  - 每个服务端在独立的PowerShell窗口中运行", "INFO")
            self.log_message("  - 可以直接查看服务端的输出和错误信息", "INFO")
            self.log_message("  - 在对应窗口中按 Ctrl+C 停止服务端", "INFO")
            self.log_message("  - 关闭PowerShell窗口也会停止对应的服务端", "INFO")
            self.log_message("  - 按 Enter 键退出调试模式监控（不会停止服务端）", "INFO")
            
            input("\n按 Enter 键退出调试模式监控...")
            
            self.log_message("用户退出调试模式监控")
            self.log_message("=== 调试模式监控结束 ===")
            
            self.log_message("[成功] 调试模式监控已退出", "INFO")
            self.log_message("[提示] 服务端仍在各自的PowerShell窗口中运行", "INFO")
            self.log_message("[提示] 如需停止服务端，请在对应的PowerShell窗口中按 Ctrl+C", "INFO")
            
            return True
        else:
            self.log_message("[错误] 没有成功启动任何服务端", "ERROR")
            return False


class WuWaManager(BaseWuWaComponent):
    """主管理类 - 整合所有功能模块"""
    
    def __init__(self):
        project_root = Path(__file__).parent
        super().__init__(project_root, "Manager")
        
        # 初始化各个组件
        self.checker = WuWaEnvironmentChecker(self.project_root)
        self.runner = WuWaRun(self.project_root)
        self.status = WuWaStatus(self.project_root)
        self.logs = WuWaLogs(self.project_root)
        self.debug_runner = WuWaDebugRun(self.project_root)
        self.config_manager = WuWaConfigManager(self.project_root)
        self.client_patcher = WuWaClientPatcher(self.project_root)
        
        # 版本设置
        self.selected_version = None
    
    def set_version(self, version: str) -> None:
        """设置版本"""
        self.selected_version = version
        self.runner.set_release_version(version)
        self.debug_runner.set_release_version(version)
        self.log_message(f"已设置版本: {version}")
    
    def show_help(self) -> None:
        """显示帮助信息"""
        self.log_message("=" * 80, "INFO")
        self.log_message("                    鸣潮服务端一键运行工具", "INFO")
        self.log_message("=" * 80, "INFO")
        self.log_message("可用命令:", "INFO")
        self.log_message("  --run              启动所有服务端", "INFO")
        self.log_message("  --stop             停止所有服务端", "INFO")
        self.log_message("  --status           查看服务端状态", "INFO")
        self.log_message("  --debug            调试模式运行", "INFO")
        self.log_message("  --check            环境检查", "INFO")
        self.log_message("    --server-only    仅检查服务端环境", "INFO")
        self.log_message("    --client-only    仅检查客户端环境", "INFO")
        self.log_message("  --patchclient      应用客户端补丁 (需要 --version)", "INFO")
        self.log_message("  --runserverandclient 启动服务端并应用客户端补丁", "INFO")
        self.log_message("  --version <ver>    指定版本目录", "INFO")
        self.log_message("  --help             显示帮助信息", "INFO")
        self.log_message("示例:", "INFO")
        self.log_message("  python wuwa_server.py --run", "INFO")
        self.log_message("  python wuwa_server.py --version 2.6 --run", "INFO")
        self.log_message("  python wuwa_server.py --version 2.5 --patchclient", "INFO")
        self.log_message("  python wuwa_server.py --version 2.6 --runserverandclient", "INFO")
        self.log_message("  python wuwa_server.py --check --server-only", "INFO")
        self.log_message("  python wuwa_server.py --check --client-only", "INFO")
        self.log_message("=" * 80, "INFO")
    
    def run(self) -> None:
        """主运行方法"""
        try:
            args = self._parse_arguments()
            if not args:
                return
                
            self._execute_command(args)
            
        except WuWaException as e:
            self.handle_exception(e, "运行失败")
        except Exception as e:
            self.handle_exception(e, "运行时发生未知错误")
    
    def _parse_arguments(self) -> Optional[dict]:
        """解析命令行参数"""
        args = sys.argv[1:]
        
        if not args or "--help" in args:
            self.show_help()
            return None
        
        parsed_args = {
            'command': None,
            'version': None,
            'check_type': 'all',  # 新增：检查类型 (all, server, client)
            'raw_args': args
        }
        
        # 处理版本参数
        if "--version" in args:
            try:
                idx = args.index("--version")
                if idx + 1 < len(args):
                    parsed_args['version'] = args[idx + 1]
                    self.set_version(parsed_args['version'])
                    # 移除版本参数
                    args.pop(idx)  # 移除 --version
                    args.pop(idx)  # 移除版本号
                else:
                    raise WuWaConfigException("--version 参数需要指定版本号")
            except (IndexError, ValueError) as e:
                raise WuWaConfigException(f"版本参数解析失败: {str(e)}")
        
        # 处理检查类型参数
        if "--server-only" in args:
            parsed_args['check_type'] = 'server'
            args.remove("--server-only")
        elif "--client-only" in args:
            parsed_args['check_type'] = 'client'
            args.remove("--client-only")
        
        # 确定主命令
        commands = ["--check", "--run", "--stop", "--status", "--debug", 
                   "--patchclient", "--runserverandclient"]
        
        for cmd in commands:
            if cmd in args:
                parsed_args['command'] = cmd
                break
        
        if not parsed_args['command']:
            raise WuWaConfigException("未指定有效的命令参数")
        
        return parsed_args
    
    def _execute_command(self, args: dict) -> None:
        """执行具体命令"""
        command = args['command']
        version = args['version']
        check_type = args.get('check_type', 'all')
        
        if command == "--check":
            self._handle_check_command(version, check_type)
        elif command == "--run":
            self._handle_run_command(version)
        elif command == "--stop":
            self._handle_stop_command()
        elif command == "--status":
            self._handle_status_command()
        elif command == "--debug":
            self._handle_debug_command()
        elif command == "--patchclient":
            self._handle_patchclient_command(version)
        elif command == "--runserverandclient":
            self._handle_runserverandclient_command(version)
    
    def _handle_check_command(self, version: Optional[str], check_type: str = 'all') -> None:
        """处理环境检查命令
        
        Args:
            version: 版本号
            check_type: 检查类型 ('all', 'server', 'client')
        """
        target_version = version or self.selected_version
        
        if check_type == 'server':
            self.log_message("开始服务端环境检查...")
            success = self.checker.run_server_checks(target_version)
            if success:
                self.log_message("服务端环境检查通过", "INFO")
            else:
                self.log_message("服务端环境检查未通过", "ERROR")
        elif check_type == 'client':
            self.log_message("开始客户端环境检查...")
            success = self.checker.run_client_checks(target_version)
            if success:
                self.log_message("客户端环境检查通过", "INFO")
            else:
                self.log_message("客户端环境检查未通过", "ERROR")
        else:  # check_type == 'all'
            self.log_message("开始完整环境检查...")
            success = self.checker.run_all_checks(target_version, check_client=True)
            if success:
                self.log_message("环境检查通过", "INFO")
            else:
                self.log_message("环境检查未通过", "ERROR")
    
    def _handle_run_command(self, version: Optional[str]) -> None:
        """处理启动服务端命令"""
        self.log_message("开始启动服务端...")
        target_version = version or self.selected_version
        
        # 设置runner的版本目录
        self.runner.set_release_version(target_version)
        
        # 自动更新配置文件路径
        self.log_message("正在检测并更新配置文件路径...", "INFO")
        config_success = self.config_manager.process_all_configs(target_version)
        if config_success:
            self.log_message("配置文件路径已更新", "INFO")
        else:
            self.log_message("配置文件路径更新失败，将使用现有配置", "WARNING")
        
        # 先进行环境检查
        if self.checker.run_all_checks(target_version):
            processes = self.runner.start_all_servers()
            if processes:
                self.log_message(f"已启动 {len(processes)} 个服务端", "INFO")
                self.log_message("使用 --status 查看运行状态", "INFO")
                self.log_message("使用 --stop 停止所有服务端", "INFO")
            else:
                self.log_message("服务端启动失败", "ERROR")
        else:
            self.log_message("环境检查未通过，无法启动服务端", "ERROR")
    
    def _handle_stop_command(self) -> None:
        """处理停止服务端命令"""
        self.log_message("开始停止服务端...", "INFO")
        success = self.runner.stop_all_servers()
        if success:
            self.log_message("服务端已停止", "INFO")
        else:
            self.log_message("没有运行中的服务端", "INFO")
    
    def _handle_status_command(self) -> None:
        """处理状态查看命令"""
        self.status.show_status()
    
    def _handle_debug_command(self) -> None:
        """处理调试模式命令"""
        self.log_message("开始调试模式...")
        success = self.debug_runner.run_debug_mode()
        if not success:
            self.log_message("调试模式启动失败", "ERROR")
    
    def _handle_patchclient_command(self, version: Optional[str]) -> None:
        """处理客户端补丁命令"""
        target_version = version or self.selected_version
        if not target_version:
            raise WuWaConfigException("--patchclient 需要指定版本参数，使用 --version <版本号> --patchclient")
        
        self.log_message(f"开始应用客户端补丁 (版本: {target_version})...")
        success = self.client_patcher.patch_client(target_version)
        if success:
            self.log_message(f"客户端补丁应用完成 (版本: {target_version})", "INFO")
            self.log_message("可以启动客户端了", "INFO")
        else:
            self.log_message(f"客户端补丁应用失败 (版本: {target_version})", "ERROR")
    
    def _handle_runserverandclient_command(self, version: Optional[str]) -> None:
        """处理同时运行服务端和客户端命令"""
        target_version = version or self.selected_version
        if not target_version:
            raise WuWaConfigException("--runserverandclient 需要指定版本参数，使用 --version <版本号> --runserverandclient")
        
        self.log_message(f"开始运行服务端和客户端 (版本: {target_version})...")
        
        # 1. 启动服务端
        self.log_message("=== 步骤 1: 启动服务端 ===", "INFO")
        self._start_server_for_combined_mode(target_version)
        
        # 2. 应用客户端补丁
        self.log_message("=== 步骤 2: 应用客户端补丁 ===", "INFO")
        success = self.client_patcher.patch_client(target_version)
        if success:
            self.log_message("客户端补丁应用完成", "INFO")
        else:
            self.log_message("客户端补丁应用失败，但服务端已启动", "ERROR")
            return
    
    def _start_server_for_combined_mode(self, version: str) -> None:
        """为组合模式启动服务端"""
        # 设置runner的版本目录
        self.runner.set_release_version(version)
        
        # 自动更新配置文件路径
        self.log_message("正在检测并更新配置文件路径...", "INFO")
        config_success = self.config_manager.process_all_configs(version)
        if config_success:
            self.log_message("配置文件路径已更新", "INFO")
        else:
            self.log_message("配置文件路径更新失败，将使用现有配置", "WARNING")
        
        if self.checker.check_environment(version):
            processes = self.runner.start_all_servers()
            if processes:
                self.log_message(f"已启动 {len(processes)} 个服务端", "INFO")
                
                # 3. 启动客户端
                self.log_message("=== 步骤 3: 启动客户端 ===", "INFO")
                try:
                    client_dir = self.client_patcher.get_script_dir().parent / "Client" / "Client" / "Binaries" / "Win64"
                    launcher_path = client_dir / "launcher.exe"
                    
                    if launcher_path.exists():
                        import subprocess
                        subprocess.Popen([str(launcher_path)], cwd=str(client_dir))
                        self.log_message("[成功] 客户端已启动", "INFO")
                        self.log_message("=== 全部完成 ===", "INFO")
                        self.log_message("[提示] 服务端和客户端都已启动", "INFO")
                        self.log_message("[提示] 使用 --status 查看服务端状态", "INFO")
                        self.log_message("[提示] 使用 --stop 停止服务端", "INFO")
                    else:
                        self.log_message(f"[错误] 客户端启动器不存在: {launcher_path}", "ERROR")
                        
                except Exception as e:
                    self.log_message(f"[错误] 启动客户端失败: {e}", "ERROR")
            else:
                raise WuWaServerException("服务端启动失败")
        else:
            raise WuWaEnvironmentException("环境检查未通过")


def main():
    """主入口函数"""
    manager = WuWaManager()
    manager.run()


if __name__ == "__main__":
    main()