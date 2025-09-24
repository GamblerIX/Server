#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
鸣潮服务端一键运行工具
"""

import os
import re
import sys
import time
import shutil
import psutil
import socket
import subprocess

import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Event
from dataclasses import dataclass


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
        "client_content": "Client/Client/Content/Paks",
        "server_version": "Server/version",
        "launcher_exe": "launcher.exe",
        "pak_file": "rr_fixes_100_p.pak",
        "config_file": "config.toml",

        "release_dir": "release"
    }
    
    # 文件类型到目标目录的映射配置
    FILE_TARGET_MAPPING = {
        # .pak文件复制到Content/Paks目录
        "pak": "client_content",
        # .dll和.exe文件复制到Binaries/Win64目录
        "dll": "client_binary",
        "exe": "client_binary",
        # 配置文件复制到Binaries/Win64目录
        "toml": "client_binary",
        # 默认目录
        "default": "client_binary"
    }
    
    # 文件扩展名
    FILE_EXTENSIONS = {
        "dll": "*.dll",
        "exe": "*.exe",
        "log": "*.log",
        "toml": "*.toml"
    }
    
    # 日志配置
    LOG_CONFIG = {
        "format": "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        "date_format": "%Y-%m-%d %H:%M:%S",
        "level": logging.INFO,
        # 可选日志记录功能配置
        "enable_file_logging": True,  # 是否启用文件日志记录
        "log_file_path": "logs/wuwa_server.log",  # 日志文件路径
        "max_file_size": 10 * 1024 * 1024,  # 单个日志文件最大大小（10MB）
        "backup_count": 5,  # 保留的日志文件备份数量
        "enable_console_logging": True,  # 是否启用控制台日志输出
        "log_levels": {  # 不同组件的日志级别配置
            "server": logging.INFO,
            "client": logging.INFO,
            "network": logging.WARNING,
            "file_ops": logging.INFO,
            "performance": logging.WARNING
        }
    }
    
    # 性能优化配置
    PERFORMANCE = {
        "max_concurrent_servers": 5,  # 最大并发启动服务端数量
        "cache_enabled": True,  # 启用缓存机制
        "cache_ttl": 300,  # 缓存生存时间（秒）
        "thread_pool_size": 4  # 线程池大小
    }
    
    # 构建配置
    BUILD_CONFIG = {
        "cargo_command": "cargo",  # Cargo命令
        "build_mode": "release",  # 构建模式：debug 或 release
        "target_dir": "target",  # 构建目标目录
        "parallel_builds": True,  # 是否并行构建
        "max_parallel_jobs": 4,  # 最大并行任务数
        "build_timeout": 600,  # 构建超时时间（秒）
        "required_tools": ["cargo", "rustc"],  # 必需的工具
        "environment_vars": {  # 构建环境变量
            "RUST_BACKTRACE": "1",
            "CARGO_TERM_COLOR": "always"
        },
        "build_features": [],  # 构建特性
        "build_args": ["--release"],  # 额外的构建参数
        "artifact_patterns": [  # 构建产物模式
            "*.exe",
            "*.dll",
            "*.pdb"
        ]
    }

class PathResolver:
    """路径解析器 - 统一管理和解析所有路径配置"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        # 修正路径配置 - project_root已经是Server目录
        self.server_dir = project_root  # 不需要再添加"Server"
        self.client_dir = project_root.parent / "Client"  # 上级目录的Client
        
        # 缓存解析结果
        self._path_cache = {}
        
    def get_client_binary_path(self) -> Path:
        """获取客户端二进制文件目录路径"""
        cache_key = "client_binary"
        if cache_key not in self._path_cache:
            self._path_cache[cache_key] = self.client_dir / "Client" / "Binaries" / "Win64"
        return self._path_cache[cache_key]
    
    def get_client_content_path(self) -> Path:
        """获取客户端内容目录路径"""
        cache_key = "client_content"
        if cache_key not in self._path_cache:
            self._path_cache[cache_key] = self.client_dir / "Client" / "Content" / "Paks"
        return self._path_cache[cache_key]
    
    def get_server_release_path(self, version: str = None) -> Path:
        """获取服务端发布目录路径"""
        base_path = self.server_dir / "release"
        if version:
            return base_path / version
        return base_path
    
    def get_version_path(self, version: str) -> Path:
        """获取指定版本的路径"""
        return self.get_server_release_path(version)
    

    def resolve_file_target_path(self, filename: str) -> Path:
        """根据文件名解析目标路径"""
        file_mappings = WuWaConfig.FILE_TARGET_MAPPING
        
        # 检查文件扩展名
        file_ext = Path(filename).suffix.lower()
        if file_ext in file_mappings:
            target_type = file_mappings[file_ext]
        else:
            # 检查特定文件名
            if filename in file_mappings:
                target_type = file_mappings[filename]
            else:
                # 默认到二进制目录
                target_type = "binary"
        
        # 根据目标类型返回路径
        if target_type == "content":
            return self.get_client_content_path()
        else:  # binary
            return self.get_client_binary_path()
    
    def validate_path(self, path: Path, create_if_missing: bool = False) -> bool:
        """验证路径是否存在，可选择自动创建"""
        if path.exists():
            return True
        
        if create_if_missing:
            try:
                path.mkdir(parents=True, exist_ok=True)
                return True
            except Exception:
                return False
        
        return False
    
    def get_relative_path(self, absolute_path: Path) -> str:
        """获取相对于项目根目录的相对路径"""
        try:
            return str(absolute_path.relative_to(self.project_root))
        except ValueError:
            return str(absolute_path)
    
    def clear_cache(self):
        """清空路径缓存"""
        self._path_cache.clear()


# ==================== 数据模型定义 ====================

@dataclass
class ServerStatusInfo:
    """服务器状态信息数据模型"""
    name: str
    port: int
    process_id: Optional[int] = None
    is_running: bool = False
    uptime: Optional[float] = None
    memory_usage: Optional[float] = None
    cpu_usage: Optional[float] = None
    error_message: Optional[str] = None
    listening_address: Optional[str] = None

@dataclass
class SystemResourceInfo:
    """系统资源信息数据模型"""
    cpu_percent: float = 0.0
    cpu_count: int = 0
    memory_total_gb: float = 0.0
    memory_used_gb: float = 0.0
    memory_percent: float = 0.0
    disk_total_gb: float = 0.0
    disk_used_gb: float = 0.0
    disk_percent: float = 0.0

@dataclass
class StatusSummary:
    """状态摘要数据模型"""
    total_servers: int
    running_servers: int
    check_time: str
    servers: List[ServerStatusInfo]
    system_resources: Optional[SystemResourceInfo] = None
    errors: List[str] = None

@dataclass
class BuildResult:
    """构建结果数据模型"""
    component_name: str
    success: bool
    build_time: float
    output_path: Optional[Path] = None
    error_message: Optional[str] = None
    warnings: List[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None

@dataclass
class BuildEnvironment:
    """构建环境信息数据模型"""
    cargo_version: Optional[str] = None
    rustc_version: Optional[str] = None
    target_triple: Optional[str] = None
    environment_valid: bool = False
    missing_tools: List[str] = None
    error_message: Optional[str] = None


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


class WuWaPathException(WuWaException):
    """路径相关异常"""
    def __init__(self, message: str):
        super().__init__(message, 1009)


class DetailedWuWaException(WuWaException):
    """增强的异常类 - 提供详细的错误信息和上下文"""
    
    def __init__(self, message: str, error_code: int, context: dict = None, 
                 suggestions: list = None, recoverable: bool = False):
        super().__init__(message, error_code)
        self.context = context or {}
        self.suggestions = suggestions or []
        self.recoverable = recoverable
        self.timestamp = datetime.now()
    
    def get_detailed_message(self) -> str:
        """获取详细的错误信息"""
        details = [f"[错误码:{self.error_code}] {self.message}"]
        details.append(f"时间: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.context:
            details.append("上下文信息:")
            for key, value in self.context.items():
                details.append(f"  - {key}: {value}")
        
        if self.suggestions:
            details.append("建议解决方案:")
            for i, suggestion in enumerate(self.suggestions, 1):
                details.append(f"  {i}. {suggestion}")
        
        details.append(f"可恢复: {'是' if self.recoverable else '否'}")
        
        return "\n".join(details)
    
    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context,
            "suggestions": self.suggestions,
            "recoverable": self.recoverable
        }


class ErrorHandler:
    """错误处理器 - 统一管理错误处理逻辑"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.error_history = []
        self.max_history = 100
    
    def handle_exception(self, exception: Exception, operation: str = "", 
                        context: dict = None, suggestions: list = None) -> DetailedWuWaException:
        """处理异常并转换为详细异常"""
        
        # 如果已经是DetailedWuWaException，直接返回
        if isinstance(exception, DetailedWuWaException):
            self._log_exception(exception, operation)
            self._add_to_history(exception)
            return exception
        
        # 如果是WuWaException，转换为DetailedWuWaException
        if isinstance(exception, WuWaException):
            detailed_exception = DetailedWuWaException(
                message=exception.message,
                error_code=exception.error_code,
                context=context or {"operation": operation},
                suggestions=suggestions or self._get_default_suggestions(exception),
                recoverable=self._is_recoverable(exception)
            )
        else:
            # 其他异常类型
            detailed_exception = DetailedWuWaException(
                message=str(exception),
                error_code=9999,  # 未知错误
                context=context or {"operation": operation, "exception_type": type(exception).__name__},
                suggestions=suggestions or ["检查系统环境", "查看详细日志", "联系技术支持"],
                recoverable=False
            )
        
        self._log_exception(detailed_exception, operation)
        self._add_to_history(detailed_exception)
        return detailed_exception
    
    def _log_exception(self, exception: DetailedWuWaException, operation: str):
        """记录异常日志"""
        if self.logger:
            self.logger.error(f"操作 '{operation}' 发生异常:")
            self.logger.error(exception.get_detailed_message())
    
    def _add_to_history(self, exception: DetailedWuWaException):
        """添加到错误历史"""
        self.error_history.append(exception)
        if len(self.error_history) > self.max_history:
            self.error_history.pop(0)
    
    def _get_default_suggestions(self, exception: WuWaException) -> list:
        """根据异常类型获取默认建议"""
        suggestions_map = {
            WuWaConfigException: [
                "检查配置文件格式是否正确",
                "验证配置参数是否完整",
                "重新生成配置文件"
            ],
            WuWaFileException: [
                "检查文件路径是否存在",
                "验证文件权限",
                "确保磁盘空间充足"
            ],
            WuWaProcessException: [
                "检查进程是否已启动",
                "验证端口是否被占用",
                "重启相关服务"
            ],
            WuWaNetworkException: [
                "检查网络连接",
                "验证防火墙设置",
                "确认端口配置"
            ],
            WuWaServerException: [
                "检查服务端文件完整性",
                "验证服务端配置",
                "重新启动服务端"
            ],
            WuWaEnvironmentException: [
                "检查系统环境",
                "验证依赖项安装",
                "更新系统组件"
            ],
            WuWaVersionException: [
                "检查版本兼容性",
                "更新到最新版本",
                "回退到稳定版本"
            ],
            WuWaClientException: [
                "检查客户端文件完整性",
                "重新应用客户端补丁",
                "验证客户端配置"
            ],
            WuWaPathException: [
                "检查路径是否存在",
                "验证路径权限",
                "使用绝对路径"
            ]
        }
        
        return suggestions_map.get(type(exception), ["查看详细日志", "重试操作", "联系技术支持"])
    
    def _is_recoverable(self, exception: WuWaException) -> bool:
        """判断异常是否可恢复"""
        recoverable_types = {
            WuWaNetworkException,
            WuWaProcessException,
            WuWaFileException
        }
        return type(exception) in recoverable_types
    
    def get_error_summary(self) -> dict:
        """获取错误统计摘要"""
        if not self.error_history:
            return {"total": 0, "by_code": {}, "recent": []}
        
        by_code = {}
        for error in self.error_history:
            code = error.error_code
            by_code[code] = by_code.get(code, 0) + 1
        
        recent = [error.to_dict() for error in self.error_history[-5:]]
        
        return {
            "total": len(self.error_history),
            "by_code": by_code,
            "recent": recent
        }
    
    def clear_history(self):
        """清空错误历史"""
        self.error_history.clear()


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


# ==================== 日志管理器 ====================
class WuWaLogger:
    """鸣潮工具日志管理器 - 提供灵活的日志记录功能"""
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        """单例模式"""
        if cls._instance is None:
            cls._instance = super(WuWaLogger, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        """初始化日志管理器"""
        if self._initialized:
            return
        
        self.config = WuWaConfig.LOG_CONFIG.copy()
        self.loggers = {}
        self.handlers = {}
        self.operation_loggers = {}  # 操作特定的日志器
        self.stdout_captured = False
        self.stderr_captured = False
        self.original_stdout = None
        self.original_stderr = None
        self._setup_root_logger()
        self._initialized = True
    
    def _setup_root_logger(self):
        """设置根日志器"""
        root_logger = logging.getLogger("WuWa")
        root_logger.setLevel(self.config["level"])
        
        # 清除现有处理器
        root_logger.handlers.clear()
        
        # 设置控制台处理器
        if self.config.get("enable_console_logging", True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(self._get_formatter())
            console_handler.setLevel(self.config["level"])
            root_logger.addHandler(console_handler)
            self.handlers["console"] = console_handler
        
        # 设置文件处理器
        if self.config.get("enable_file_logging", False):
            self._setup_file_handler(root_logger)
    
    def _setup_file_handler(self, logger):
        """设置文件日志处理器（增强版）"""
        try:
            from logging.handlers import RotatingFileHandler
            import os
            
            log_file_path = self.config["log_file_path"]
            
            # 确保使用绝对路径
            if not os.path.isabs(log_file_path):
                log_file_path = os.path.abspath(log_file_path)
                self.config["log_file_path"] = log_file_path
            
            log_dir = os.path.dirname(log_file_path)
            
            # 创建日志目录（增强错误处理）
            if log_dir:
                self._ensure_log_directory(log_dir)
            
            # 检查文件权限
            self._check_log_file_permissions(log_file_path)
            
            # 创建旋转文件处理器
            file_handler = RotatingFileHandler(
                log_file_path,
                maxBytes=self.config.get("max_file_size", 10 * 1024 * 1024),
                backupCount=self.config.get("backup_count", 5),
                encoding='utf-8',
                delay=True  # 延迟创建文件直到第一次写入
            )
            
            file_handler.setFormatter(self._get_formatter())
            file_handler.setLevel(self.config["level"])
            logger.addHandler(file_handler)
            self.handlers["file"] = file_handler
            
            # 记录文件日志启用信息
            console_logger = logging.getLogger("WuWa.Logger")
            console_logger.info(f"文件日志已启用: {log_file_path}")
            
        except Exception as e:
            # 如果文件日志设置失败，记录到控制台
            console_logger = logging.getLogger("WuWa.Logger")
            console_logger.error(f"文件日志设置失败: {e}")
            console_logger.info("将继续使用控制台日志")
            # 不抛出异常，允许程序继续运行
    
    def _ensure_log_directory(self, log_dir: str) -> None:
        """确保日志目录存在"""
        try:
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
                # 设置目录权限（如果是Unix系统）
                if hasattr(os, 'chmod'):
                    try:
                        os.chmod(log_dir, 0o755)
                    except (OSError, PermissionError):
                        pass  # 权限设置失败不影响功能
        except (OSError, PermissionError) as e:
            raise Exception(f"无法创建日志目录 {log_dir}: {e}")
    
    def _check_log_file_permissions(self, log_file_path: str) -> None:
        """检查日志文件权限"""
        log_dir = os.path.dirname(log_file_path)
        
        # 检查目录写权限
        if not os.access(log_dir, os.W_OK):
            raise Exception(f"日志目录没有写权限: {log_dir}")
        
        # 如果文件已存在，检查文件写权限
        if os.path.exists(log_file_path) and not os.access(log_file_path, os.W_OK):
            raise Exception(f"日志文件没有写权限: {log_file_path}")
        
        # 检查磁盘空间（简单检查）
        try:
            import shutil
            free_space = shutil.disk_usage(log_dir).free
            min_space = 100 * 1024 * 1024  # 100MB
            if free_space < min_space:
                raise Exception(f"磁盘空间不足，剩余: {free_space / 1024 / 1024:.1f}MB")
        except Exception:
            # 磁盘空间检查失败不影响日志功能
            pass
    
    def _get_formatter(self):
        """获取日志格式器"""
        return logging.Formatter(
            self.config["format"],
            self.config["date_format"]
        )
    
    def get_logger(self, component_name: str):
        """获取指定组件的日志器"""
        logger_name = f"WuWa.{component_name}"
        
        if logger_name not in self.loggers:
            logger = logging.getLogger(logger_name)
            
            # 设置组件特定的日志级别
            component_level = self.config.get("log_levels", {}).get(
                component_name.lower(), 
                self.config["level"]
            )
            logger.setLevel(component_level)
            
            self.loggers[logger_name] = logger
        
        return self.loggers[logger_name]
    
    def enable_file_logging(self, log_file_path: str = None):
        """动态启用文件日志记录"""
        if log_file_path:
            self.config["log_file_path"] = log_file_path
        
        self.config["enable_file_logging"] = True
        
        # 重新设置根日志器
        root_logger = logging.getLogger("WuWa")
        if "file" not in self.handlers:
            self._setup_file_handler(root_logger)
    
    def disable_file_logging(self):
        """动态禁用文件日志记录"""
        self.config["enable_file_logging"] = False
        
        if "file" in self.handlers:
            root_logger = logging.getLogger("WuWa")
            file_handler = self.handlers["file"]
            root_logger.removeHandler(file_handler)
            try:
                file_handler.close()
            except Exception:
                pass  # 忽略关闭错误
            del self.handlers["file"]
    
    def cleanup_handlers(self):
        """清理所有处理器"""
        try:
            # 清理文件处理器
            if "file" in self.handlers:
                self.handlers["file"].close()
            
            # 清理所有日志器的处理器
            for logger_name in list(self.loggers.keys()):
                logger = self.loggers[logger_name]
                for handler in logger.handlers[:]:
                    logger.removeHandler(handler)
                    try:
                        handler.close()
                    except Exception:
                        pass
            
            # 清理操作日志器的处理器
            for logger_name in list(self.operation_loggers.keys()):
                logger = self.operation_loggers[logger_name]
                for handler in logger.handlers[:]:
                    logger.removeHandler(handler)
                    try:
                        handler.close()
                    except Exception:
                        pass
            
            # 清理根日志器的处理器
            root_logger = logging.getLogger("WuWa")
            for handler in root_logger.handlers[:]:
                root_logger.removeHandler(handler)
                try:
                    handler.close()
                except Exception:
                    pass
                    
        except Exception:
            pass  # 忽略清理错误
    
    def set_log_level(self, component_name: str, level):
        """设置指定组件的日志级别"""
        self.config["log_levels"][component_name.lower()] = level
        
        logger_name = f"WuWa.{component_name}"
        if logger_name in self.loggers:
            self.loggers[logger_name].setLevel(level)
    
    def get_log_status(self):
        """获取日志系统状态"""
        return {
            "file_logging_enabled": self.config.get("enable_file_logging", False),
            "console_logging_enabled": self.config.get("enable_console_logging", True),
            "log_file_path": self.config.get("log_file_path", ""),
            "active_loggers": list(self.loggers.keys()),
            "operation_loggers": list(self.operation_loggers.keys()),
            "log_levels": self.config.get("log_levels", {}),
            "handlers": list(self.handlers.keys()),
            "stdout_captured": self.stdout_captured,
            "stderr_captured": self.stderr_captured
        }
    
    def setup_file_logging(self, log_file_path: str = None) -> bool:
        """设置文件日志记录（公共接口）"""
        try:
            if log_file_path:
                self.config["log_file_path"] = log_file_path
            
            # 先清理现有的文件处理器
            if "file" in self.handlers:
                self.disable_file_logging()
            
            self.config["enable_file_logging"] = True
            
            # 重新设置根日志器
            root_logger = logging.getLogger("WuWa")
            self._setup_file_handler(root_logger)
            
            # 检查是否成功创建了文件处理器
            return "file" in self.handlers
            
        except Exception as e:
            console_logger = logging.getLogger("WuWa.Logger")
            console_logger.error(f"设置文件日志失败: {e}")
            self.config["enable_file_logging"] = False
            return False
    
    def capture_stdout_stderr(self) -> None:
        """捕获stdout和stderr到日志系统"""
        if not self.stdout_captured:
            self.original_stdout = sys.stdout
            sys.stdout = LoggingStreamWrapper(
                self.get_logger("STDOUT"), 
                logging.INFO, 
                self.original_stdout
            )
            self.stdout_captured = True
        
        if not self.stderr_captured:
            self.original_stderr = sys.stderr
            sys.stderr = LoggingStreamWrapper(
                self.get_logger("STDERR"), 
                logging.ERROR, 
                self.original_stderr
            )
            self.stderr_captured = True
    
    def restore_stdout_stderr(self) -> None:
        """恢复原始的stdout和stderr"""
        if self.stdout_captured and self.original_stdout:
            sys.stdout = self.original_stdout
            self.stdout_captured = False
        
        if self.stderr_captured and self.original_stderr:
            sys.stderr = self.original_stderr
            self.stderr_captured = False
    
    def create_operation_logger(self, operation_name: str) -> logging.Logger:
        """创建操作特定的日志器"""
        logger_name = f"WuWa.Operation.{operation_name}"
        
        if logger_name not in self.operation_loggers:
            logger = logging.getLogger(logger_name)
            logger.setLevel(self.config["level"])
            
            # 如果启用了文件日志，为操作日志创建单独的文件
            if self.config.get("enable_file_logging", False):
                self._setup_operation_file_handler(logger, operation_name)
            
            self.operation_loggers[logger_name] = logger
        
        return self.operation_loggers[logger_name]
    
    def _setup_operation_file_handler(self, logger: logging.Logger, operation_name: str) -> None:
        """为操作日志设置单独的文件处理器"""
        try:
            from logging.handlers import RotatingFileHandler
            import os
            
            # 构建操作日志文件路径
            base_log_path = self.config["log_file_path"]
            log_dir = os.path.dirname(base_log_path)
            base_name = os.path.splitext(os.path.basename(base_log_path))[0]
            operation_log_path = os.path.join(log_dir, f"{base_name}_{operation_name}.log")
            
            # 创建操作特定的文件处理器
            operation_handler = RotatingFileHandler(
                operation_log_path,
                maxBytes=self.config.get("max_file_size", 10 * 1024 * 1024),
                backupCount=self.config.get("backup_count", 3),  # 操作日志保留较少备份
                encoding='utf-8',
                delay=True
            )
            
            # 使用特殊格式器，包含操作名称
            operation_formatter = logging.Formatter(
                f"[%(asctime)s] [%(levelname)s] [{operation_name}] %(message)s",
                self.config["date_format"]
            )
            operation_handler.setFormatter(operation_formatter)
            operation_handler.setLevel(self.config["level"])
            
            logger.addHandler(operation_handler)
            
        except Exception as e:
            console_logger = logging.getLogger("WuWa.Logger")
            console_logger.warning(f"设置操作日志文件失败 ({operation_name}): {e}")
    
    def cleanup_old_logs(self, days_to_keep: int = 7) -> int:
        """清理旧的日志文件"""
        try:
            import os
            import time
            
            log_file_path = self.config.get("log_file_path", "")
            if not log_file_path:
                return 0
            
            log_dir = os.path.dirname(log_file_path)
            if not os.path.exists(log_dir):
                return 0
            
            current_time = time.time()
            cutoff_time = current_time - (days_to_keep * 24 * 60 * 60)
            cleaned_count = 0
            
            for filename in os.listdir(log_dir):
                if filename.endswith('.log') or filename.endswith('.log.1'):
                    file_path = os.path.join(log_dir, filename)
                    try:
                        if os.path.getmtime(file_path) < cutoff_time:
                            os.remove(file_path)
                            cleaned_count += 1
                    except (OSError, PermissionError):
                        continue
            
            if cleaned_count > 0:
                console_logger = logging.getLogger("WuWa.Logger")
                console_logger.info(f"清理了 {cleaned_count} 个旧日志文件")
            
            return cleaned_count
            
        except Exception as e:
            console_logger = logging.getLogger("WuWa.Logger")
            console_logger.warning(f"清理旧日志文件失败: {e}")
            return 0


class LoggingStreamWrapper:
    """日志流包装器 - 用于捕获stdout/stderr到日志系统"""
    
    def __init__(self, logger: logging.Logger, level: int, original_stream):
        self.logger = logger
        self.level = level
        self.original_stream = original_stream
        self.buffer = ""
    
    def write(self, message: str) -> int:
        """写入消息到日志和原始流"""
        result = len(message)
        
        # 首先写入到原始流（保持控制台输出）
        try:
            if self.original_stream:
                result = self.original_stream.write(message)
        except Exception:
            pass  # 忽略原始流写入错误
        
        # 然后尝试写入日志
        try:
            # 处理消息并写入日志
            self.buffer += message
            
            # 当遇到换行符时，记录完整的行
            while '\n' in self.buffer:
                line, self.buffer = self.buffer.split('\n', 1)
                if line.strip():  # 只记录非空行
                    self.logger.log(self.level, line.strip())
        except Exception:
            # 忽略日志记录错误
            pass
        
        return result
    
    def flush(self):
        """刷新缓冲区"""
        try:
            if self.original_stream:
                self.original_stream.flush()
            
            # 记录缓冲区中剩余的内容
            if self.buffer.strip():
                self.logger.log(self.level, self.buffer.strip())
                self.buffer = ""
        except Exception:
            pass
    
    def isatty(self) -> bool:
        """检查是否为终端"""
        if self.original_stream:
            return getattr(self.original_stream, 'isatty', lambda: False)()
        return False
    
    def __getattr__(self, name):
        """代理其他属性到原始流"""
        if self.original_stream:
            return getattr(self.original_stream, name)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")


# ==================== 公共基类 ====================
class BaseWuWaComponent:
    """鸣潮工具组件基类 - 提供公共功能"""
    
    def __init__(self, project_root: Path, component_name: str):
        self.project_root = project_root
        self.component_name = component_name
        
        # 初始化缓存系统
        self._cache = {}
        self._cache_timestamps = {}
        
        # 初始化日志系统
        self._setup_logger()
        
    def _setup_logger(self) -> None:
        """设置组件专用日志器 - 使用WuWaLogger管理器"""
        # 获取全局日志管理器实例
        logger_manager = WuWaLogger()
        
        # 获取组件专用日志器
        self.logger = logger_manager.get_logger(self.component_name)
        
        # 保存日志管理器引用，便于动态配置
        self.logger_manager = logger_manager
    
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
    
    def enable_file_logging(self, log_file_path: str = None) -> bool:
        """启用文件日志记录"""
        if hasattr(self, 'logger_manager'):
            success = self.logger_manager.setup_file_logging(log_file_path)
            if success:
                self.log_message(f"已启用文件日志记录: {log_file_path or self.logger_manager.config.get('log_file_path', 'wuwa.log')}", "INFO")
            else:
                self.log_message("启用文件日志记录失败", "ERROR")
            return success
        return False
    
    def disable_file_logging(self) -> None:
        """禁用文件日志记录"""
        if hasattr(self, 'logger_manager'):
            self.logger_manager.disable_file_logging()
            self.log_message("已禁用文件日志记录", "INFO")
    
    def set_log_level(self, level: str) -> None:
        """设置日志级别"""
        if hasattr(self, 'logger_manager'):
            # 转换字符串级别到logging常量
            level_map = {
                "DEBUG": logging.DEBUG,
                "INFO": logging.INFO,
                "WARNING": logging.WARNING,
                "ERROR": logging.ERROR,
                "CRITICAL": logging.CRITICAL
            }
            log_level = level_map.get(level.upper(), logging.INFO)
            self.logger_manager.set_log_level(self.component_name, log_level)
            self.log_message(f"日志级别已设置为: {level}", "INFO")
    
    def start_operation_logging(self, operation_name: str) -> logging.Logger:
        """开始操作特定的日志记录"""
        if hasattr(self, 'logger_manager'):
            operation_logger = self.logger_manager.create_operation_logger(operation_name)
            operation_logger.info(f"开始操作: {operation_name}")
            return operation_logger
        return self.logger
    
    def end_operation_logging(self, operation_logger: logging.Logger, operation_name: str, success: bool = True) -> None:
        """结束操作特定的日志记录"""
        if success:
            operation_logger.info(f"操作完成: {operation_name}")
        else:
            operation_logger.error(f"操作失败: {operation_name}")
    
    def capture_output_to_logs(self) -> None:
        """开始捕获stdout/stderr到日志"""
        if hasattr(self, 'logger_manager'):
            self.logger_manager.capture_stdout_stderr()
            self.log_message("已开始捕获程序输出到日志", "INFO")
    
    def restore_output_streams(self) -> None:
        """恢复原始的输出流"""
        if hasattr(self, 'logger_manager'):
            self.logger_manager.restore_stdout_stderr()
            self.log_message("已恢复原始输出流", "INFO")
    
    def get_logging_status(self) -> dict:
        """获取日志系统状态"""
        if hasattr(self, 'logger_manager'):
            return self.logger_manager.get_log_status()
        return {}
    
    def cleanup_old_logs(self, days_to_keep: int = 7) -> int:
        """清理旧日志文件"""
        if hasattr(self, 'logger_manager'):
            return self.logger_manager.cleanup_old_logs(days_to_keep)
        return 0
    
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
    
    def get_script_directory(self) -> Path:
        """获取脚本所在目录"""
        return Path(__file__).parent.absolute()
    
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
        
        # 特别处理：如果脚本在Server目录，则检查同级的Client目录
        if base_path.name.lower() == "server":
            # 检查同级目录中的Client目录
            sibling_client_path = base_path.parent / client_binary_path
            possible_paths.insert(0, sibling_client_path)  # 优先检查同级Client目录
            self.log_message(f"检测到Server目录，优先搜索同级Client目录: {sibling_client_path}")
        
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
        # 集成PathResolver和ErrorHandler
        self.path_resolver = PathResolver(project_root)
        self.error_handler = ErrorHandler(self.logger)
    def get_script_directory(self) -> Path:
        """获取脚本所在目录"""
        return Path(__file__).parent.absolute()
    
    def patch_client(self, version: str) -> bool:
        """应用客户端补丁 - 使用PathResolver和ErrorHandler重构"""
        operation = f"应用客户端补丁 (版本: {version})"
        
        try:
            self.log_message(f"开始{operation}")
            
            # 使用PathResolver获取路径
            source_dir = self.path_resolver.get_version_path(version)
            client_bin_dir = self.path_resolver.get_client_binary_path()
            client_content_dir = self.path_resolver.get_client_content_path()
            
            # 验证源目录存在
            if not source_dir.exists():
                raise WuWaPathException(f"版本目录不存在: {source_dir}")
            
            # 确保目标目录存在
            client_bin_dir.mkdir(parents=True, exist_ok=True)
            client_content_dir.mkdir(parents=True, exist_ok=True)
            
            # 获取需要复制的文件列表
            files_to_copy = self._get_files_to_copy(source_dir, client_bin_dir, client_content_dir)
            
            if not files_to_copy:
                raise WuWaFileException("没有找到需要复制的文件")
            
            # 执行文件复制
            copied_count = self._copy_files(files_to_copy)
            
            if copied_count > 0:
                self.log_message(f"客户端补丁应用完成，共复制 {copied_count} 个文件")
                return True
            else:
                raise WuWaFileException("没有文件被成功复制")
                
        except Exception as e:
            detailed_exception = self.error_handler.handle_exception(
                e, operation,
                context={
                    "version": version,
                    "source_dir": str(source_dir) if 'source_dir' in locals() else "未知",
                    "client_bin_dir": str(client_bin_dir) if 'client_bin_dir' in locals() else "未知"
                },
                suggestions=[
                    "检查版本目录是否存在",
                    "验证客户端目录权限",
                    "确保磁盘空间充足",
                    "重新下载版本文件"
                ]
            )
            self.log_message(detailed_exception.get_detailed_message(), "ERROR")
            return False
    
    def _get_files_to_copy(self, source_dir: Path, client_bin_dir: Path, client_content_dir: Path) -> list:
        """获取需要复制的文件列表"""
        files_to_copy = []
        
        try:
            # 1. 自动查找所有.dll文件
            dll_files = list(source_dir.glob("*.dll"))
            for dll_file in dll_files:
                files_to_copy.append({
                    "source_file": dll_file,
                    "target_dir": client_bin_dir,
                    "description": f"DLL文件 ({dll_file.name})"
                })
            
            # 2. 使用PathResolver获取文件映射（包含config.toml文件）
            file_mappings = [
                (WuWaConfig.PATHS["pak_file"], client_content_dir, "PAK文件"),
                (WuWaConfig.PATHS["launcher_exe"], client_bin_dir, "启动器"),
                (WuWaConfig.PATHS["config_file"], client_bin_dir, "配置文件")
            ]
            
            for filename, target_dir, description in file_mappings:
                source_file = source_dir / filename
                if source_file.exists():
                    files_to_copy.append({
                        "source_file": source_file,
                        "target_dir": target_dir,
                        "description": description
                    })
            
            return files_to_copy
            
        except Exception as e:
            raise WuWaFileException(f"获取文件列表失败: {str(e)}")
    
    def _copy_files(self, files_to_copy: list) -> int:
        """执行文件复制操作"""
        copied_count = 0
        
        for file_info in files_to_copy:
            source_file = file_info["source_file"]
            target_dir = file_info["target_dir"]
            description = file_info["description"]
            
            try:
                target_file = target_dir / source_file.name
                
                # 使用安全的文件操作
                self.safe_file_operation(shutil.copy2, source_file, target_file)
                
                self.log_message(f"[成功] 复制{description}: {source_file.name}")
                copied_count += 1
                
            except Exception as e:
                detailed_exception = self.error_handler.handle_exception(
                    e, f"复制文件 {source_file.name}",
                    context={
                        "source_file": str(source_file),
                        "target_file": str(target_dir / source_file.name),
                        "description": description
                    },
                    suggestions=[
                        "检查源文件是否存在",
                        "验证目标目录权限",
                        "确保文件未被占用"
                    ]
                )
                self.log_message(f"[错误] 复制{description}失败: {detailed_exception.message}", "ERROR")
        
        return copied_count


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
        client_bin_path = self._find_client_directory(script_dir)
        
        if not client_bin_path:
            self.log_message("[错误] 客户端目录不存在，无法检查文件", "ERROR")
            if version:
                self.log_message(f"[提示] 请执行命令修补客户端: python wuwa_server.py --patchclient --version {version}", "INFO")
            else:
                self.log_message("[提示] 请执行命令修补客户端: python wuwa_server.py --patchclient --version <版本号>", "INFO")
            return False
        
        # client_bin_path 已经是 Client/Client/Binaries/Win64 路径
        # 需要获取 Client/Client 根目录来构建其他路径
        client_root_path = client_bin_path.parent.parent  # 从 Win64 -> Binaries -> Client
        client_content_path = client_root_path / "Content" / "Paks"
        
        # 检查必需文件列表，根据文件类型指定不同的检查路径
        required_files = [
            ("rr_fixes_100_p.pak", "补丁文件", client_content_path),
            ("launcher.exe", "启动器", client_bin_path),
            ("config.toml", "配置文件", client_bin_path)
        ]
        
        missing_files = []
        found_files = []
        
        for filename, description, check_path in required_files:
            file_path = check_path / filename
            if file_path.exists():
                self.log_message(f"[成功] {description}: {filename} (位于: {check_path.name})")
                found_files.append(filename)
            else:
                self.log_message(f"[错误] {description}缺失: {filename} (应位于: {check_path})", "ERROR")
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
        
        # 特别处理：如果脚本在Server目录，则检查同级的Client目录
        if base_path.name.lower() == "server":
            # 检查同级目录中的Client目录
            sibling_client_path = base_path.parent / client_binary_path
            possible_paths.insert(0, sibling_client_path)  # 优先检查同级Client目录
        
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
        
        # 初始化日志目录
        self.logs_dir = project_root / "logs"
        self.logs_dir.mkdir(exist_ok=True)
        
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
        """启动服务端（已移除延迟功能）"""
        # 直接启动服务端，不再添加延迟
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


class WuWaBuildManager(BaseWuWaComponent):
    """构建管理类 - 负责Cargo构建自动化"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "BuildManager")
        self.config = WuWaConfig.BUILD_CONFIG.copy()
        self.build_results = {}
        self.build_environment = None
        
        # 初始化构建目录
        self.build_dir = project_root
        self.target_dir = project_root / self.config["target_dir"]
        self.release_dir = project_root / "release"
        
        # 服务器组件配置
        self.server_components = [
            {
                "name": "wicked-waifus-config-server",
                "binary_name": "wicked-waifus-config-server",
                "description": "配置服务器"
            },
            {
                "name": "wicked-waifus-login-server", 
                "binary_name": "wicked-waifus-login-server",
                "description": "登录服务器"
            },
            {
                "name": "wicked-waifus-gateway-server",
                "binary_name": "wicked-waifus-gateway-server", 
                "description": "网关服务器"
            },
            {
                "name": "wicked-waifus-game-server",
                "binary_name": "wicked-waifus-game-server",
                "description": "游戏服务器"
            },
            {
                "name": "wicked-waifus-hotpatch-server",
                "binary_name": "wicked-waifus-hotpatch-server",
                "description": "热更新服务器"
            }
        ]
    
    def validate_build_environment(self) -> BuildEnvironment:
        """验证Rust/Cargo构建环境"""
        self.log_message("=== 验证构建环境 ===")
        
        build_env = BuildEnvironment()
        missing_tools = []
        
        try:
            # 检查Cargo
            cargo_result = self._check_tool_version("cargo", ["--version"])
            if cargo_result:
                build_env.cargo_version = cargo_result
                self.log_message(f"[成功] Cargo: {cargo_result}")
            else:
                missing_tools.append("cargo")
                self.log_message("[错误] Cargo未安装或不可用", "ERROR")
            
            # 检查Rustc
            rustc_result = self._check_tool_version("rustc", ["--version"])
            if rustc_result:
                build_env.rustc_version = rustc_result
                self.log_message(f"[成功] Rustc: {rustc_result}")
            else:
                missing_tools.append("rustc")
                self.log_message("[错误] Rustc未安装或不可用", "ERROR")
            
            # 获取目标三元组
            target_result = self._check_tool_version("rustc", ["--print", "target-list"])
            if target_result:
                # 获取默认目标
                default_target = self._check_tool_version("rustc", ["-vV"])
                if default_target and "host:" in default_target:
                    for line in default_target.split('\n'):
                        if line.startswith('host:'):
                            build_env.target_triple = line.split(':', 1)[1].strip()
                            break
            
            # 检查构建环境是否完整
            build_env.missing_tools = missing_tools
            build_env.environment_valid = len(missing_tools) == 0
            
            if build_env.environment_valid:
                self.log_message("[成功] 构建环境验证通过")
            else:
                build_env.error_message = f"缺少必需工具: {', '.join(missing_tools)}"
                self.log_message(f"[错误] 构建环境验证失败: {build_env.error_message}", "ERROR")
            
        except Exception as e:
            build_env.environment_valid = False
            build_env.error_message = f"环境验证过程中发生错误: {str(e)}"
            self.log_message(f"[错误] 环境验证异常: {e}", "ERROR")
        
        self.build_environment = build_env
        return build_env
    
    def _check_tool_version(self, tool: str, args: List[str]) -> Optional[str]:
        """检查工具版本"""
        try:
            result = subprocess.run(
                [tool] + args,
                capture_output=True,
                text=True,
                timeout=10,
                check=True
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return None
    
    def build_all_servers(self, version: str = None) -> Dict[str, BuildResult]:
        """构建所有服务器组件"""
        self.log_message("=== 开始构建所有服务器组件 ===")
        
        # 验证构建环境
        if not self.build_environment or not self.build_environment.environment_valid:
            env_result = self.validate_build_environment()
            if not env_result.environment_valid:
                error_msg = f"构建环境无效: {env_result.error_message}"
                self.log_message(f"[错误] {error_msg}", "ERROR")
                return {comp["name"]: BuildResult(
                    component_name=comp["name"],
                    success=False,
                    build_time=0.0,
                    error_message=error_msg
                ) for comp in self.server_components}
        
        # 开始操作日志记录
        build_logger = self.start_operation_logging("build_all_servers")
        
        results = {}
        start_time = time.time()
        
        try:
            # 并行或串行构建
            if self.config.get("parallel_builds", True):
                results = self._build_parallel()
            else:
                results = self._build_sequential()
            
            # 构建完成后提取产物
            if version:
                self._extract_build_artifacts(version, results)
            
            total_time = time.time() - start_time
            successful_builds = sum(1 for result in results.values() if result.success)
            total_builds = len(results)
            
            self.log_message(f"=== 构建完成 ===")
            self.log_message(f"成功: {successful_builds}/{total_builds}")
            self.log_message(f"总耗时: {total_time:.2f}秒")
            
            # 结束操作日志记录
            self.end_operation_logging(build_logger, "build_all_servers", successful_builds == total_builds)
            
        except Exception as e:
            self.log_message(f"[错误] 构建过程中发生异常: {e}", "ERROR")
            self.end_operation_logging(build_logger, "build_all_servers", False)
            raise
        
        self.build_results = results
        return results
    
    def _build_sequential(self) -> Dict[str, BuildResult]:
        """串行构建所有组件"""
        results = {}
        
        for component in self.server_components:
            self.log_message(f"开始构建: {component['description']}")
            result = self.build_server_component(component["name"])
            results[component["name"]] = result
            
            if not result.success:
                self.log_message(f"[错误] {component['description']} 构建失败", "ERROR")
            else:
                self.log_message(f"[成功] {component['description']} 构建完成")
        
        return results
    
    def _build_parallel(self) -> Dict[str, BuildResult]:
        """并行构建所有组件"""
        results = {}
        max_workers = min(len(self.server_components), self.config.get("max_parallel_jobs", 4))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有构建任务
            future_to_component = {
                executor.submit(self.build_server_component, comp["name"]): comp
                for comp in self.server_components
            }
            
            # 收集结果
            for future in as_completed(future_to_component):
                component = future_to_component[future]
                try:
                    result = future.result()
                    results[component["name"]] = result
                    
                    if result.success:
                        self.log_message(f"[成功] {component['description']} 并行构建完成")
                    else:
                        self.log_message(f"[错误] {component['description']} 并行构建失败", "ERROR")
                        
                except Exception as e:
                    error_result = BuildResult(
                        component_name=component["name"],
                        success=False,
                        build_time=0.0,
                        error_message=f"构建任务异常: {str(e)}"
                    )
                    results[component["name"]] = error_result
                    self.log_message(f"[错误] {component['description']} 构建任务异常: {e}", "ERROR")
        
        return results
    
    def build_server_component(self, component_name: str) -> BuildResult:
        """构建单个服务器组件"""
        start_time = time.time()
        
        try:
            self.log_message(f"构建组件: {component_name}")
            
            # 构建Cargo命令
            cmd = [
                self.config["cargo_command"],
                "build",
                "--bin", component_name
            ] + self.config.get("build_args", [])
            
            # 设置环境变量
            env = os.environ.copy()
            env.update(self.config.get("environment_vars", {}))
            
            # 执行构建
            result = subprocess.run(
                cmd,
                cwd=str(self.build_dir),
                capture_output=True,
                text=True,
                timeout=self.config.get("build_timeout", 600),
                env=env
            )
            
            build_time = time.time() - start_time
            
            if result.returncode == 0:
                # 构建成功，查找输出文件
                output_path = self._find_build_output(component_name)
                
                return BuildResult(
                    component_name=component_name,
                    success=True,
                    build_time=build_time,
                    output_path=output_path,
                    stdout=result.stdout,
                    stderr=result.stderr
                )
            else:
                # 构建失败
                return BuildResult(
                    component_name=component_name,
                    success=False,
                    build_time=build_time,
                    error_message=f"构建失败 (退出码: {result.returncode})",
                    stdout=result.stdout,
                    stderr=result.stderr
                )
                
        except subprocess.TimeoutExpired:
            return BuildResult(
                component_name=component_name,
                success=False,
                build_time=time.time() - start_time,
                error_message="构建超时"
            )
        except Exception as e:
            return BuildResult(
                component_name=component_name,
                success=False,
                build_time=time.time() - start_time,
                error_message=f"构建异常: {str(e)}"
            )
    
    def _find_build_output(self, component_name: str) -> Optional[Path]:
        """查找构建输出文件"""
        # 根据构建模式确定输出目录
        build_mode = self.config.get("build_mode", "release")
        output_dir = self.target_dir / build_mode
        
        # 查找可执行文件
        exe_name = f"{component_name}.exe"
        exe_path = output_dir / exe_name
        
        if exe_path.exists():
            return exe_path
        
        # 如果没找到，尝试其他可能的位置
        for pattern in self.config.get("artifact_patterns", ["*.exe"]):
            for file_path in output_dir.glob(pattern):
                if component_name in file_path.name:
                    return file_path
        
        return None
    
    def _extract_build_artifacts(self, version: str, build_results: Dict[str, BuildResult]) -> bool:
        """提取构建产物到发布目录"""
        self.log_message(f"=== 提取构建产物到版本 {version} ===")
        
        try:
            # 创建版本发布目录
            version_dir = self.release_dir / version
            version_dir.mkdir(parents=True, exist_ok=True)
            
            extracted_count = 0
            
            for component_name, result in build_results.items():
                if result.success and result.output_path and result.output_path.exists():
                    try:
                        # 复制到发布目录
                        dest_path = version_dir / result.output_path.name
                        shutil.copy2(result.output_path, dest_path)
                        
                        self.log_message(f"[成功] 已提取: {result.output_path.name}")
                        extracted_count += 1
                        
                    except Exception as e:
                        self.log_message(f"[错误] 提取 {component_name} 失败: {e}", "ERROR")
                else:
                    self.log_message(f"[跳过] {component_name} (构建失败或文件不存在)", "WARNING")
            
            self.log_message(f"=== 产物提取完成: {extracted_count}/{len(build_results)} ===")
            return extracted_count > 0
            
        except Exception as e:
            self.log_message(f"[错误] 提取构建产物失败: {e}", "ERROR")
            return False
    
    def create_release_package(self, version: str) -> bool:
        """创建发布包"""
        self.log_message(f"=== 创建发布包 {version} ===")
        
        try:
            version_dir = self.release_dir / version
            if not version_dir.exists():
                self.log_message(f"[错误] 版本目录不存在: {version_dir}", "ERROR")
                return False
            
            # 检查必需文件
            required_files = [f"{comp['binary_name']}.exe" for comp in self.server_components]
            missing_files = []
            
            for file_name in required_files:
                file_path = version_dir / file_name
                if not file_path.exists():
                    missing_files.append(file_name)
            
            if missing_files:
                self.log_message(f"[错误] 缺少必需文件: {', '.join(missing_files)}", "ERROR")
                return False
            
            # 创建版本信息文件
            version_info = {
                "version": version,
                "build_time": datetime.now().isoformat(),
                "components": [comp["name"] for comp in self.server_components],
                "build_environment": {
                    "cargo_version": self.build_environment.cargo_version if self.build_environment else None,
                    "rustc_version": self.build_environment.rustc_version if self.build_environment else None,
                    "target_triple": self.build_environment.target_triple if self.build_environment else None
                }
            }
            
            version_info_path = version_dir / "build_info.json"
            with open(version_info_path, 'w', encoding='utf-8') as f:
                import json
                json.dump(version_info, f, indent=2, ensure_ascii=False)
            
            self.log_message(f"[成功] 发布包创建完成: {version_dir}")
            return True
            
        except Exception as e:
            self.log_message(f"[错误] 创建发布包失败: {e}", "ERROR")
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
        """检查端口状态（增强异常处理）"""
        # 默认返回值
        default_result = {
            "listening": False,
            "pid": None,
            "address": None,
            "error": None
        }
        
        try:
            # 方法1: 使用psutil检查网络连接
            result = self._check_port_with_psutil(port)
            if result["listening"]:
                return result
                
        except (psutil.AccessDenied, AttributeError, psutil.NoSuchProcess) as e:
            self.log_message(f"使用psutil检查端口 {port} 时权限不足: {e}", "DEBUG")
        except Exception as e:
            self.log_message(f"使用psutil检查端口 {port} 时发生错误: {e}", "DEBUG")
        
        try:
            # 方法2: 使用socket连接测试
            result = self._check_port_with_socket(port)
            if result["listening"]:
                return result
                
        except Exception as e:
            self.log_message(f"使用socket检查端口 {port} 时发生错误: {e}", "DEBUG")
            default_result["error"] = str(e)
        
        return default_result
    
    def _check_port_with_psutil(self, port: int) -> Dict[str, Any]:
        """使用psutil检查端口状态"""
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if (hasattr(conn, 'laddr') and conn.laddr and 
                    conn.laddr.port == port and 
                    conn.status == psutil.CONN_LISTEN):
                    
                    return {
                        "listening": True,
                        "pid": getattr(conn, 'pid', None),
                        "address": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "error": None
                    }
        except Exception as e:
            raise e
            
        return {
            "listening": False,
            "pid": None,
            "address": None,
            "error": None
        }
    
    def _check_port_with_socket(self, port: int) -> Dict[str, Any]:
        """使用socket检查端口状态"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # 设置超时时间
                result = s.connect_ex(('127.0.0.1', port))
                if result == 0:
                    return {
                        "listening": True,
                        "pid": None,
                        "address": f"127.0.0.1:{port}",
                        "error": None
                    }
        except Exception as e:
            raise e
            
        return {
            "listening": False,
            "pid": None,
            "address": None,
            "error": None
        }
    
    def find_server_processes(self) -> Dict[str, Dict[str, Any]]:
        """查找服务端进程（增强异常处理）"""
        processes = {}
        
        try:
            # 构建服务器名称映射
            server_names = self._build_server_name_mapping()
            
            # 获取所有进程信息
            all_processes = self._get_all_processes_safely()
            
            # 处理每个进程
            for proc in all_processes:
                try:
                    server_key = self._match_process_to_server(proc, server_names)
                    if server_key:
                        proc_info = self._extract_process_info(proc)
                        if proc_info:
                            processes[server_key] = proc_info
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # 进程可能在检查过程中消失，这是正常的
                    continue
                except Exception as e:
                    # 记录单个进程处理错误，但继续处理其他进程
                    self.log_message(f"处理进程时发生错误: {e}", "DEBUG")
                    continue
                    
        except Exception as e:
            self.log_message(f"查找服务端进程时发生严重错误: {e}", "ERROR")
            # 返回空字典而不是抛出异常
            
        return processes
    
    def _build_server_name_mapping(self) -> Dict[str, List[str]]:
        """构建服务器名称映射"""
        try:
            return {
                server_key: [server['name'].lower(), f"{server['name']}.exe".lower()]
                for server_key, server in self.servers.items()
            }
        except Exception as e:
            self.log_message(f"构建服务器名称映射时发生错误: {e}", "ERROR")
            return {}
    
    def _get_all_processes_safely(self) -> List[psutil.Process]:
        """安全地获取所有进程信息"""
        try:
            return list(psutil.process_iter([
                'pid', 'name', 'cmdline', 'create_time', 
                'cpu_percent', 'memory_info'
            ]))
        except Exception as e:
            self.log_message(f"获取进程列表时发生错误: {e}", "ERROR")
            # 尝试使用更简单的方法
            try:
                return list(psutil.process_iter(['pid', 'name']))
            except Exception as e2:
                self.log_message(f"获取简化进程列表也失败: {e2}", "ERROR")
                return []
    
    def _match_process_to_server(self, proc: psutil.Process, server_names: Dict[str, List[str]]) -> Optional[str]:
        """匹配进程到服务器"""
        try:
            proc_info = proc.info
            proc_name = proc_info.get('name', '').lower() if proc_info.get('name') else ''
            cmdline = ' '.join(proc_info.get('cmdline', [])).lower() if proc_info.get('cmdline') else ''
            
            for server_key, names in server_names.items():
                if any(name in proc_name or name in cmdline for name in names):
                    return server_key
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            self.log_message(f"匹配进程到服务器时发生错误: {e}", "DEBUG")
            
        return None
    
    def _extract_process_info(self, proc: psutil.Process) -> Optional[Dict[str, Any]]:
        """提取进程信息"""
        try:
            proc_info = proc.info
            
            # 获取基本信息
            basic_info = {
                'pid': proc_info.get('pid', 0),
                'name': proc_info.get('name', '未知'),
                'cmdline': ' '.join(proc_info.get('cmdline', [])) if proc_info.get('cmdline') else '',
                'create_time': proc_info.get('create_time', 0),
                'cpu_percent': 0,
                'memory_mb': 0,
                'uptime': 0
            }
            
            # 尝试获取CPU使用率（可能失败）
            try:
                basic_info['cpu_percent'] = proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                basic_info['cpu_percent'] = 0
            
            # 尝试获取内存信息（可能失败）
            try:
                memory_info = proc_info.get('memory_info')
                if memory_info:
                    basic_info['memory_mb'] = memory_info.rss / 1024 / 1024
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                basic_info['memory_mb'] = 0
            
            # 计算运行时间
            if basic_info['create_time']:
                basic_info['uptime'] = time.time() - basic_info['create_time']
            
            return basic_info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            self.log_message(f"提取进程信息时发生错误: {e}", "DEBUG")
            return None
    
    def get_system_info(self) -> Optional[Dict[str, Any]]:
        """获取系统信息（增强异常处理）"""
        system_info = {
            "cpu": {"percent": 0, "count": 0},
            "memory": {"total_gb": 0, "used_gb": 0, "percent": 0},
            "disk": {"total_gb": 0, "used_gb": 0, "percent": 0}
        }
        
        # 获取CPU信息
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)  # 短暂间隔获取更准确的数据
            cpu_count = psutil.cpu_count()
            system_info["cpu"] = {
                "percent": cpu_percent if cpu_percent is not None else 0,
                "count": cpu_count if cpu_count is not None else 0
            }
        except Exception as e:
            self.log_message(f"获取CPU信息时发生错误: {e}", "DEBUG")
        
        # 获取内存信息
        try:
            memory = psutil.virtual_memory()
            system_info["memory"] = {
                "total_gb": memory.total / 1024 / 1024 / 1024,
                "used_gb": memory.used / 1024 / 1024 / 1024,
                "percent": memory.percent
            }
        except Exception as e:
            self.log_message(f"获取内存信息时发生错误: {e}", "DEBUG")
        
        # 获取磁盘信息
        try:
            # 尝试多个路径来获取磁盘使用情况
            disk_paths = [str(self.project_root), '/', 'C:\\']
            disk_info = None
            
            for path in disk_paths:
                try:
                    if os.path.exists(path):
                        disk_info = psutil.disk_usage(path)
                        break
                except Exception:
                    continue
            
            if disk_info:
                system_info["disk"] = {
                    "total_gb": disk_info.total / 1024 / 1024 / 1024,
                    "used_gb": disk_info.used / 1024 / 1024 / 1024,
                    "percent": (disk_info.used / disk_info.total) * 100 if disk_info.total > 0 else 0
                }
        except Exception as e:
            self.log_message(f"获取磁盘信息时发生错误: {e}", "DEBUG")
        
        # 检查是否获取到了任何有效信息
        has_valid_info = (
            system_info["cpu"]["count"] > 0 or 
            system_info["memory"]["total_gb"] > 0 or 
            system_info["disk"]["total_gb"] > 0
        )
        
        if has_valid_info:
            return system_info
        else:
            self.log_message("无法获取任何系统信息", "WARNING")
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
        """显示服务端状态（带缓存优化和异常处理）"""
        try:
            # 检查缓存
            cache_key = f"server_status_{detailed}"
            cached_status = self.get_cached_data(cache_key)
            if cached_status:
                self.log_message("从缓存中获取服务端状态信息", "DEBUG")
                self._output_status_lines(cached_status)
                return
            
            # 收集状态信息
            status_lines = self._collect_status_information(detailed)
            
            # 输出状态信息（确保总是有输出）
            self._output_status_lines(status_lines)
            
            # 缓存状态信息
            self.set_cached_data(cache_key, status_lines)
            
        except Exception as e:
            # 确保即使发生异常也有输出
            try:
                error_status = self._generate_error_status(e, detailed)
                self._output_status_lines(error_status)
            except Exception as output_error:
                # 如果连错误输出都失败，使用最基本的输出
                try:
                    self.log_message("=" * 80, "ERROR")
                    self.log_message("鸣潮服务端状态监控 (错误模式)", "ERROR")
                    self.log_message("=" * 80, "ERROR")
                    self.log_message(f"状态检查失败: {str(e)}", "ERROR")
                    self.log_message(f"输出错误: {str(output_error)}", "ERROR")
                    self.log_message("=" * 80, "ERROR")
                except:
                    # 最后的回退：直接打印
                    print("=" * 80)
                    print("鸣潮服务端状态监控 (严重错误)")
                    print("=" * 80)
                    print(f"状态检查失败: {str(e)}")
                    print("=" * 80)
            
            self.handle_exception(e, "显示服务端状态")
    
    def _collect_status_information(self, detailed: bool = True) -> List[str]:
        """收集状态信息（带异常处理）"""
        status_lines = []
        
        try:
            # 添加标题
            status_lines.append("=" * 80)
            status_lines.append("                        鸣潮服务端状态监控")
            status_lines.append("=" * 80)
            
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status_lines.append(f"检查时间: {current_time}")
            
            # 获取进程信息（带异常处理）
            processes = self._safe_find_server_processes()
            
            status_lines.append("[服务端状态]")
            status_lines.append("-" * 80)
            
            # 处理每个服务器的状态
            running_count = self._process_server_status(status_lines, processes, detailed)
            
            # 添加总计信息
            status_lines.append(f"\n总计运行数量: {running_count}/{len(self.servers)}")
            
            # 添加系统资源信息（如果是详细模式）
            if detailed:
                self._add_system_resource_info(status_lines)
            
            status_lines.append("=" * 80)
            
        except Exception as e:
            # 如果收集信息失败，至少提供基本状态
            self.log_message(f"收集状态信息时发生错误: {e}", "ERROR")
            status_lines.extend(self._generate_minimal_status())
        
        return status_lines
    
    def _safe_find_server_processes(self) -> Dict[str, Dict[str, Any]]:
        """安全地查找服务端进程"""
        try:
            return self.find_server_processes()
        except Exception as e:
            self.log_message(f"查找服务端进程时发生错误: {e}", "ERROR")
            return {}
    
    def _process_server_status(self, status_lines: List[str], processes: Dict[str, Dict[str, Any]], detailed: bool) -> int:
        """处理服务器状态信息"""
        running_count = 0
        
        for server_key, server in self.servers.items():
            try:
                port = server['port']
                description = server['description']
                
                # 安全地检查端口状态
                port_status = self._safe_check_port_status(port)
                
                if server_key in processes:
                    proc_info = processes[server_key]
                    status = "[运行中]"
                    running_count += 1
                    
                    if detailed:
                        status_lines.append(f"\n{description} (端口 {port}):")
                        status_lines.append(f"  状态: {status}")
                        status_lines.append(f"  进程ID: {proc_info.get('pid', '未知')}")
                        status_lines.append(f"  运行时间: {self.format_uptime(proc_info.get('uptime', 0))}")
                        status_lines.append(f"  CPU使用率: {proc_info.get('cpu_percent', 0):.1f}%")
                        status_lines.append(f"  内存使用: {proc_info.get('memory_mb', 0):.1f} MB")
                        if port_status.get('listening', False):
                            status_lines.append(f"  监听地址: {port_status.get('address', '未知')}")
                    else:
                        status_line = (
                            f"{description:15} | 端口 {port:4} | {status} | "
                            f"PID {proc_info.get('pid', 0):6} | {self.format_uptime(proc_info.get('uptime', 0))}"
                        )
                        status_lines.append(status_line)
                else:
                    status = "[未运行]"
                    if detailed:
                        status_lines.append(f"\n{description} (端口 {port}):")
                        status_lines.append(f"  状态: {status}")
                        if port_status.get('listening', False):
                            status_lines.append(f"  端口状态: 被其他进程占用 ({port_status.get('address', '未知')})")
                        else:
                            status_lines.append(f"  端口状态: 空闲")
                    else:
                        status_line = f"{description:15} | 端口 {port:4} | {status}"
                        status_lines.append(status_line)
                        
            except Exception as e:
                # 单个服务器状态检查失败不影响其他服务器
                self.log_message(f"检查服务器 {server_key} 状态时发生错误: {e}", "ERROR")
                status_lines.append(f"{server.get('description', server_key):15} | 状态检查失败: {str(e)}")
        
        return running_count
    
    def _safe_check_port_status(self, port: int) -> Dict[str, Any]:
        """安全地检查端口状态"""
        try:
            return self.check_port_status(port)
        except Exception as e:
            self.log_message(f"检查端口 {port} 状态时发生错误: {e}", "ERROR")
            return {"listening": False, "pid": None, "address": None, "error": str(e)}
    
    def _add_system_resource_info(self, status_lines: List[str]) -> None:
        """添加系统资源信息（带异常处理）"""
        try:
            status_lines.append("\n[系统资源]")
            status_lines.append("-" * 80)
            
            system_info = self.get_system_info()
            if system_info:
                cpu_info = system_info.get('cpu', {})
                memory_info = system_info.get('memory', {})
                disk_info = system_info.get('disk', {})
                
                status_lines.append(f"CPU使用率: {cpu_info.get('percent', 0):.1f}% (核心数: {cpu_info.get('count', '未知')})")
                status_lines.append(f"内存使用: {memory_info.get('used_gb', 0):.1f} GB / {memory_info.get('total_gb', 0):.1f} GB ({memory_info.get('percent', 0):.1f}%)")
                status_lines.append(f"磁盘使用: {disk_info.get('used_gb', 0):.1f} GB / {disk_info.get('total_gb', 0):.1f} GB ({disk_info.get('percent', 0):.1f}%)")
            else:
                status_lines.append("系统资源信息获取失败")
                
        except Exception as e:
            self.log_message(f"获取系统资源信息时发生错误: {e}", "ERROR")
            status_lines.append(f"系统资源信息获取失败: {str(e)}")
    
    def _output_status_lines(self, status_lines: List[str]) -> None:
        """输出状态信息（确保总是有输出）"""
        try:
            for line in status_lines:
                self.log_message(line, "INFO")
        except Exception as e:
            # 如果日志系统失败，直接打印到控制台
            print("日志系统失败，直接输出状态信息:")
            for line in status_lines:
                print(line)
            print(f"日志系统错误: {e}")
    
    def _generate_error_status(self, error: Exception, detailed: bool = True) -> List[str]:
        """生成错误状态信息"""
        error_lines = [
            "=" * 80,
            "                        鸣潮服务端状态监控 (错误模式)",
            "=" * 80,
            f"检查时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "[错误信息]",
            f"状态检查失败: {str(error)}",
            "",
            "[基本信息]"
        ]
        
        # 尝试提供基本的服务器信息
        try:
            for server_key, server in self.servers.items():
                error_lines.append(f"{server['description']:15} | 端口 {server['port']:4} | [状态未知]")
        except:
            error_lines.append("无法获取服务器配置信息")
        
        error_lines.extend([
            "",
            "建议: 请检查系统环境和权限设置",
            "=" * 80
        ])
        
        return error_lines
    
    def _generate_minimal_status(self) -> List[str]:
        """生成最小状态信息"""
        return [
            "",
            "[最小状态信息]",
            f"配置的服务器数量: {len(self.servers)}",
            "详细状态信息获取失败，请检查系统环境",
            ""
        ]
    
    def get_server_status(self) -> StatusSummary:
        """获取结构化的服务器状态数据"""
        try:
            # 获取进程信息
            processes = self._safe_find_server_processes()
            
            # 构建服务器状态信息列表
            servers_status = []
            running_count = 0
            errors = []
            
            for server_key, server in self.servers.items():
                try:
                    port = server['port']
                    description = server['description']
                    
                    # 检查端口状态
                    port_status = self._safe_check_port_status(port)
                    
                    if server_key in processes:
                        proc_info = processes[server_key]
                        server_status = ServerStatusInfo(
                            name=description,
                            port=port,
                            process_id=proc_info.get('pid'),
                            is_running=True,
                            uptime=proc_info.get('uptime'),
                            memory_usage=proc_info.get('memory_mb'),
                            cpu_usage=proc_info.get('cpu_percent'),
                            listening_address=port_status.get('address')
                        )
                        running_count += 1
                    else:
                        server_status = ServerStatusInfo(
                            name=description,
                            port=port,
                            is_running=False,
                            listening_address=port_status.get('address') if port_status.get('listening') else None
                        )
                    
                    servers_status.append(server_status)
                    
                except Exception as e:
                    error_msg = f"检查服务器 {server_key} 状态失败: {str(e)}"
                    errors.append(error_msg)
                    # 添加错误状态的服务器信息
                    servers_status.append(ServerStatusInfo(
                        name=server.get('description', server_key),
                        port=server.get('port', 0),
                        is_running=False,
                        error_message=str(e)
                    ))
            
            # 获取系统资源信息
            system_resources = None
            try:
                system_info = self.get_system_info()
                if system_info:
                    system_resources = SystemResourceInfo(
                        cpu_percent=system_info['cpu']['percent'],
                        cpu_count=system_info['cpu']['count'],
                        memory_total_gb=system_info['memory']['total_gb'],
                        memory_used_gb=system_info['memory']['used_gb'],
                        memory_percent=system_info['memory']['percent'],
                        disk_total_gb=system_info['disk']['total_gb'],
                        disk_used_gb=system_info['disk']['used_gb'],
                        disk_percent=system_info['disk']['percent']
                    )
            except Exception as e:
                errors.append(f"获取系统资源信息失败: {str(e)}")
            
            # 构建状态摘要
            status_summary = StatusSummary(
                total_servers=len(self.servers),
                running_servers=running_count,
                check_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                servers=servers_status,
                system_resources=system_resources,
                errors=errors if errors else None
            )
            
            return status_summary
            
        except Exception as e:
            # 返回错误状态摘要
            self.handle_exception(e, "获取服务器状态数据")
            return StatusSummary(
                total_servers=len(self.servers) if hasattr(self, 'servers') else 0,
                running_servers=0,
                check_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                servers=[],
                errors=[f"获取状态数据时发生严重错误: {str(e)}"]
            )
    
    def validate_server_ports(self) -> Dict[str, bool]:
        """验证所有服务器端口的可用性"""
        port_status = {}
        
        try:
            for server_key, server in self.servers.items():
                port = server['port']
                try:
                    port_info = self._safe_check_port_status(port)
                    port_status[server_key] = {
                        'port': port,
                        'available': not port_info.get('listening', False),
                        'listening': port_info.get('listening', False),
                        'address': port_info.get('address'),
                        'pid': port_info.get('pid'),
                        'error': port_info.get('error')
                    }
                except Exception as e:
                    port_status[server_key] = {
                        'port': port,
                        'available': False,
                        'listening': False,
                        'error': str(e)
                    }
                    
        except Exception as e:
            self.log_message(f"验证服务器端口时发生错误: {e}", "ERROR")
            
        return port_status
    
    def check_server_processes(self) -> List[Dict[str, Any]]:
        """检查所有服务器进程的详细信息"""
        try:
            processes = self._safe_find_server_processes()
            process_list = []
            
            for server_key, server in self.servers.items():
                if server_key in processes:
                    proc_info = processes[server_key]
                    process_info = {
                        'server_key': server_key,
                        'server_name': server['description'],
                        'port': server['port'],
                        'pid': proc_info.get('pid'),
                        'name': proc_info.get('name'),
                        'cmdline': proc_info.get('cmdline'),
                        'uptime': proc_info.get('uptime'),
                        'cpu_percent': proc_info.get('cpu_percent'),
                        'memory_mb': proc_info.get('memory_mb'),
                        'status': 'running'
                    }
                else:
                    process_info = {
                        'server_key': server_key,
                        'server_name': server['description'],
                        'port': server['port'],
                        'status': 'not_running'
                    }
                
                process_list.append(process_info)
            
            return process_list
            
        except Exception as e:
            self.handle_exception(e, "检查服务器进程")
            return []


class ArgumentValidator:
    """参数验证器 - 实现新的参数验证规则"""
    
    # 基础参数定义（必须且仅选一个）
    BASE_PARAMS = ['run', 'patch', 'status', 'stop', 'check', 'ddsr', 'build']
    
    # 可叠加参数定义
    STACKABLE_PARAMS = {
        'first_level': ['serveronly', 'clientonly', 'all'],  # 一次叠加且互斥
        'second_level': ['version']  # 二次叠加
    }
    
    # 各基参的叠加规则
    STACKING_RULES = {
        'run': {
            'default': 'serveronly',
            'allowed': ['serveronly', 'clientonly', 'all'],
            'forbidden': []
        },
        'patch': {
            'default': None,
            'allowed': ['version'],
            'forbidden': ['serveronly', 'clientonly', 'all'],
            'required': ['version']
        },
        'status': {
            'default': 'serveronly',
            'allowed': ['serveronly', 'clientonly', 'all'],
            'forbidden': ['version']
        },
        'stop': {
            'default': 'serveronly',
            'allowed': ['serveronly'],
            'forbidden': ['clientonly', 'all', 'version']
        },
        'check': {
            'default': 'all',
            'allowed': ['serveronly', 'clientonly', 'all'],
            'forbidden': ['version']
        },
        'ddsr': {
            'default': None,
            'allowed': ['version'],
            'forbidden': ['serveronly', 'clientonly', 'all'],
            'required': ['version']
        },
        'build': {
            'default': None,
            'allowed': ['version'],
            'forbidden': ['serveronly', 'clientonly', 'all'],
            'required': []  # version是可选的，如果不提供则使用当前时间戳
        }
    }
    
    def __init__(self):
        self.error_handler = ErrorHandler()
    
    def validate_arguments(self, args: dict) -> dict:
        """
        验证参数组合的有效性
        
        Args:
            args: 解析后的参数字典
            
        Returns:
            dict: 验证并处理后的参数字典
            
        Raises:
            WuWaException: 参数验证失败时抛出异常
        """
        try:
            # 1. 检查基础参数
            base_param = self._validate_base_params(args)
            
            # 2. 检查参数重复使用
            self._check_duplicate_params(args)
            
            # 3. 验证叠加参数
            validated_args = self._validate_stacking_params(base_param, args)
            
            # 4. 应用默认叠加参数
            validated_args = self._apply_default_stacking(base_param, validated_args)
            
            return validated_args
            
        except Exception as e:
            if isinstance(e, WuWaException):
                raise e
            else:
                raise WuWaException(f"参数验证过程中发生未知错误: {str(e)}")
    
    def _validate_base_params(self, args: dict) -> str:
        """验证基础参数（必须且仅选一个）"""
        found_base_params = []
        
        for param in self.BASE_PARAMS:
            if args.get(param, False):
                found_base_params.append(param)
        
        if len(found_base_params) == 0:
            raise WuWaException(
                "错误：必须指定一个基础参数。\n"
                f"可用的基础参数：{', '.join(['--' + p for p in self.BASE_PARAMS])}"
            )
        
        if len(found_base_params) > 1:
            raise WuWaException(
                f"错误：只能指定一个基础参数，但发现了多个：{', '.join(['--' + p for p in found_base_params])}\n"
                f"可用的基础参数：{', '.join(['--' + p for p in self.BASE_PARAMS])}"
            )
        
        return found_base_params[0]
    
    def _check_duplicate_params(self, args: dict):
        """检查参数重复使用（这里主要是逻辑检查，实际重复由argparse处理）"""
        # 由于argparse已经处理了重复参数，这里主要做逻辑验证
        # 如果需要更严格的重复检查，可以在这里实现
        pass
    
    def _validate_stacking_params(self, base_param: str, args: dict) -> dict:
        """验证叠加参数的有效性"""
        rules = self.STACKING_RULES[base_param]
        validated_args = args.copy()
        
        # 检查禁止的参数
        for forbidden_param in rules.get('forbidden', []):
            if args.get(forbidden_param):
                raise WuWaException(
                    f"错误：基础参数 --{base_param} 不能与 --{forbidden_param} 参数叠加使用"
                )
        
        # 检查必需的参数
        for required_param in rules.get('required', []):
            if not args.get(required_param):
                raise WuWaException(
                    f"错误：基础参数 --{base_param} 必须与 --{required_param} 参数叠加使用"
                )
        
        # 检查一次叠加参数的互斥性
        first_level_params = []
        for param in self.STACKABLE_PARAMS['first_level']:
            if args.get(param):
                first_level_params.append(param)
        
        if len(first_level_params) > 1:
            raise WuWaException(
                f"错误：一次叠加参数互斥，不能同时使用：{', '.join(['--' + p for p in first_level_params])}"
            )
        
        # 验证允许的参数
        allowed_params = rules.get('allowed', [])
        for param in self.STACKABLE_PARAMS['first_level'] + self.STACKABLE_PARAMS['second_level']:
            if args.get(param) and param not in allowed_params:
                raise WuWaException(
                    f"错误：基础参数 --{base_param} 不支持与 --{param} 参数叠加使用\n"
                    f"支持的叠加参数：{', '.join(['--' + p for p in allowed_params]) if allowed_params else '无'}"
                )
        
        return validated_args
    
    def _apply_default_stacking(self, base_param: str, args: dict) -> dict:
        """应用默认叠加参数"""
        rules = self.STACKING_RULES[base_param]
        default_param = rules.get('default')
        
        if default_param:
            # 检查是否已经有一次叠加参数
            has_first_level = any(args.get(param) for param in self.STACKABLE_PARAMS['first_level'])
            
            if not has_first_level:
                args[default_param] = True
        
        return args
    
    def get_help_text(self) -> str:
        """获取参数使用帮助文本"""
        help_text = """
参数使用说明：

基础参数（必须且仅选一个）：
  --run         启动服务端
  --patch       应用补丁
  --status      查看状态
  --stop        停止服务端
  --check       环境检查
  --ddsr        下载服务端发行版

可叠加参数：
  --serveronly  仅服务端模式
  --clientonly  仅客户端模式
  --all         全部模式
  --version     指定版本 (格式: x.y)

参数叠加规则：
  --run:
    默认: --serveronly
    可叠加: --serveronly, --clientonly, --all
    
  --patch:
    必须叠加: --version x.y
    不可叠加其他参数
    
  --status:
    默认: --serveronly
    可叠加: --serveronly, --clientonly, --all
    不可叠加: --version
    
  --stop:
    默认: --serveronly
    仅可叠加: --serveronly
    
  --check:
    默认: --all
    可叠加: --serveronly, --clientonly, --all
    不可叠加: --version
    
  --ddsr:
    必须叠加: --version x.y
    不可叠加其他参数
    
  --build:
    可选叠加: --version x.y (如果不提供版本，将使用时间戳)
    不可叠加其他参数
    说明: 编译所有服务器组件并创建发布包

使用示例：
  python wuwa_server.py --run
  python wuwa_server.py --run --clientonly
  python wuwa_server.py --patch --version 1.0
  python wuwa_server.py --status --all
  python wuwa_server.py --stop
  python wuwa_server.py --check --serveronly
  python wuwa_server.py --ddsr --version 2.7
  python wuwa_server.py --build
  python wuwa_server.py --build --version 2.8
"""
        return help_text


class WuWaNetworkTester(BaseWuWaComponent):
    """网络延迟检测类 - 用于选择最优下载源"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "NetworkTester")
        self.timeout = 10  # 网络测试超时时间（秒）
        
    def test_source_latency(self, url: str) -> float:
        """
        测试指定URL的网络延迟
        
        Args:
            url: 要测试的URL
            
        Returns:
            float: 延迟时间（毫秒），失败时返回float('inf')
        """
        import urllib.request
        import time
        
        try:
            self.log_message(f"正在测试网络延迟: {url}", "INFO")
            start_time = time.time()
            
            # 创建请求对象，只获取头部信息以减少数据传输
            req = urllib.request.Request(url, method='HEAD')
            req.add_header('User-Agent', 'WuWa-Server-Downloader/1.0')
            
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                end_time = time.time()
                latency = (end_time - start_time) * 1000  # 转换为毫秒
                
                self.log_message(f"网络延迟测试完成: {url} - {latency:.2f}ms", "INFO")
                return latency
                
        except Exception as e:
            self.log_message(f"网络延迟测试失败: {url} - {str(e)}", "ERROR")
            return float('inf')
    
    def select_best_source(self, sources: list) -> str:
        """
        从多个下载源中选择延迟最低的源
        
        Args:
            sources: 下载源URL列表
            
        Returns:
            str: 最优下载源URL
        """
        if not sources:
            raise WuWaNetworkException("没有可用的下载源")
        
        if len(sources) == 1:
            return sources[0]
        
        self.log_message("开始网络延迟检测，选择最优下载源...", "INFO")
        
        best_source = None
        best_latency = float('inf')
        
        for source in sources:
            latency = self.test_source_latency(source)
            if latency < best_latency:
                best_latency = latency
                best_source = source
        
        if best_source is None:
            raise WuWaNetworkException("所有下载源都无法访问")
        
        self.log_message(f"选择最优下载源: {best_source} (延迟: {best_latency:.2f}ms)", "INFO")
        return best_source


class WuWaDownloader(BaseWuWaComponent):
    """文件下载类 - 处理服务端发行版下载"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "Downloader")
        self.chunk_size = 8192  # 下载块大小
        
    def download_file(self, url: str, target_path: Path, show_progress: bool = True) -> bool:
        """
        下载文件到指定路径
        
        Args:
            url: 下载URL
            target_path: 目标文件路径
            show_progress: 是否显示下载进度
            
        Returns:
            bool: 下载是否成功
        """
        import urllib.request
        import urllib.error
        
        try:
            self.log_message(f"开始下载文件: {url}", "INFO")
            self.log_message(f"目标路径: {target_path}", "INFO")
            
            # 确保目标目录存在
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 创建请求对象
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'WuWa-Server-Downloader/1.0')
            
            with urllib.request.urlopen(req) as response:
                # 获取文件大小
                total_size = int(response.headers.get('Content-Length', 0))
                downloaded_size = 0
                
                self.log_message(f"文件大小: {self._format_size(total_size)}", "INFO")
                
                with open(target_path, 'wb') as f:
                    while True:
                        chunk = response.read(self.chunk_size)
                        if not chunk:
                            break
                        
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        
                        if show_progress and total_size > 0:
                            progress = (downloaded_size / total_size) * 100
                            print(f"\r下载进度: {progress:.1f}% ({self._format_size(downloaded_size)}/{self._format_size(total_size)})", end='', flush=True)
                
                if show_progress:
                    print()  # 换行
                
                self.log_message(f"文件下载完成: {target_path}", "INFO")
                return True
                
        except urllib.error.URLError as e:
            self.log_message(f"下载失败 - 网络错误: {str(e)}", "ERROR")
            return False
        except Exception as e:
            self.log_message(f"下载失败: {str(e)}", "ERROR")
            return False
    
    def _format_size(self, size_bytes: int) -> str:
        """格式化文件大小显示"""
        if size_bytes == 0:
            return "0B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f}{size_names[i]}"


class WuWaExtractor(BaseWuWaComponent):
    """解压缩类 - 处理下载文件的解压"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "Extractor")
        
    def extract_zip(self, zip_path: Path, extract_to: Path) -> bool:
        """
        解压ZIP文件到指定目录
        
        Args:
            zip_path: ZIP文件路径
            extract_to: 解压目标目录
            
        Returns:
            bool: 解压是否成功
        """
        import zipfile
        
        try:
            self.log_message(f"开始解压文件: {zip_path}", "INFO")
            self.log_message(f"解压目标: {extract_to}", "INFO")
            
            # 确保目标目录存在
            extract_to.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # 获取压缩包内文件列表
                file_list = zip_ref.namelist()
                total_files = len(file_list)
                
                self.log_message(f"压缩包包含 {total_files} 个文件", "INFO")
                
                # 解压所有文件
                for i, file_name in enumerate(file_list, 1):
                    try:
                        zip_ref.extract(file_name, extract_to)
                        print(f"\r解压进度: {i}/{total_files} ({(i/total_files)*100:.1f}%)", end='', flush=True)
                    except Exception as e:
                        self.log_message(f"解压文件失败: {file_name} - {str(e)}", "WARNING")
                        continue
                
                print()  # 换行
                self.log_message(f"解压完成: {extract_to}", "INFO")
                return True
                
        except zipfile.BadZipFile:
            self.log_message(f"无效的ZIP文件: {zip_path}", "ERROR")
            return False
        except Exception as e:
            self.log_message(f"解压失败: {str(e)}", "ERROR")
            return False
    
    def cleanup_zip_file(self, zip_path: Path) -> bool:
        """
        清理下载的ZIP文件
        
        Args:
            zip_path: 要删除的ZIP文件路径
            
        Returns:
            bool: 清理是否成功
        """
        try:
            if zip_path.exists():
                zip_path.unlink()
                self.log_message(f"已清理下载文件: {zip_path}", "INFO")
                return True
            return True
        except Exception as e:
            self.log_message(f"清理文件失败: {zip_path} - {str(e)}", "WARNING")
            return False


class WuWaManager(BaseWuWaComponent):
    """主管理类 - 整合所有功能模块"""
    
    def __init__(self):
        project_root = Path(__file__).parent
        super().__init__(project_root, "Manager")
        
        # 初始化路径解析器
        self.path_resolver = PathResolver(self.project_root)
        
        # 初始化各个组件
        self.checker = WuWaEnvironmentChecker(self.project_root)
        self.runner = WuWaRun(self.project_root)
        self.status = WuWaStatus(self.project_root)
        self.config_manager = WuWaConfigManager(self.project_root)
        self.client_patcher = WuWaClientPatcher(self.project_root)
        
        # 初始化ddsr功能组件
        self.network_tester = WuWaNetworkTester(self.project_root)
        self.downloader = WuWaDownloader(self.project_root)
        self.extractor = WuWaExtractor(self.project_root)
        
        # 初始化构建管理器
        self.build_manager = WuWaBuildManager(self.project_root)
        
        # 版本设置
        self.selected_version = None
        
        # 自动启用文件日志记录
        self._setup_file_logging()
    
    def set_version(self, version: str) -> None:
        """设置版本"""
        self.selected_version = version
        self.runner.set_release_version(version)
        self.log_message(f"已设置版本: {version}")
    
    def _setup_file_logging(self) -> None:
        """设置文件日志记录"""
        try:
            # 确保日志目录存在
            logs_dir = self.project_root / "logs"
            logs_dir.mkdir(exist_ok=True)
            
            # 启用文件日志记录
            log_file_path = logs_dir / "wuwa_server.log"
            success = self.enable_file_logging(str(log_file_path))
            
            if success:
                self.log_message("=== 鸣潮服务端管理工具启动 ===", "INFO")
                self.log_message(f"日志文件: {log_file_path}", "INFO")
                self.log_message(f"启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "INFO")
            else:
                self.log_message("文件日志启用失败，将仅使用控制台日志", "WARNING")
                
        except Exception as e:
            self.log_message(f"设置文件日志时发生错误: {e}", "WARNING")
    
    def show_help(self) -> None:
        """显示帮助信息"""
        validator = ArgumentValidator()
        help_text = validator.get_help_text()
        self.log_message(help_text, "INFO")
    
    def run(self) -> None:
        """主运行方法"""
        try:
            args = self._parse_arguments()
            if not args:
                self.log_message("=== 程序结束 ===", "INFO")
                return
                
            self._execute_command(args)
            self.log_message("=== 命令执行完成 ===", "INFO")
            
        except WuWaException as e:
            self.handle_exception(e, "运行失败")
            self.log_message("=== 程序异常结束 ===", "ERROR")
        except Exception as e:
            self.handle_exception(e, "运行时发生未知错误")
            self.log_message("=== 程序异常结束 ===", "ERROR")
        finally:
            self.log_message(f"程序结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "INFO")
    
    def _parse_arguments(self) -> Optional[dict]:
        """解析命令行参数"""
        args = sys.argv[1:]
        
        if not args or "--help" in args:
            self.show_help()
            return None
        
        # 将命令行参数转换为字典格式
        raw_args = {}
        i = 0
        while i < len(args):
            arg = args[i]
            if arg.startswith('--'):
                param_name = arg[2:]  # 移除 '--' 前缀
                
                # 检查是否是需要值的参数（如 --version）
                if param_name == 'version' and i + 1 < len(args) and not args[i + 1].startswith('--'):
                    raw_args[param_name] = args[i + 1]
                    i += 2  # 跳过参数值
                else:
                    raw_args[param_name] = True
                    i += 1
            else:
                i += 1
        
        # 使用ArgumentValidator验证参数
        validator = ArgumentValidator()
        try:
            validated_args = validator.validate_arguments(raw_args)
        except WuWaConfigException as e:
            self.log_message(f"参数验证失败: {str(e)}", "ERROR")
            raise e
        
        # 设置版本（如果提供）
        if validated_args.get('version'):
            self.set_version(validated_args['version'])
        
        return validated_args
    
    def _execute_command(self, args: dict) -> None:
        """执行具体命令"""
        # 记录命令执行开始
        self.log_message(f"=== 开始执行命令 ===", "INFO")
        self.log_message(f"命令参数: {args}", "INFO")
        
        # 查找基础命令
        base_command = None
        for param in ArgumentValidator.BASE_PARAMS:
            if args.get(param):
                base_command = param
                break
        
        if not base_command:
            raise WuWaException("未找到有效的基础命令", ErrorCodes.UNKNOWN_ERROR)
        
        version = args.get('version')
        
        # 根据叠加参数确定执行类型
        execution_type = 'server'  # 默认值
        if args.get('serveronly'):
            execution_type = 'server'
        elif args.get('clientonly'):
            execution_type = 'client'
        elif args.get('all'):
            execution_type = 'all'
        
        self.log_message(f"执行命令: {base_command}, 类型: {execution_type}, 版本: {version or '未指定'}", "INFO")
        
        if base_command == "check":
            self._handle_check_command(version, execution_type)
        elif base_command == "run":
            self._handle_run_command(version, execution_type)
        elif base_command == "stop":
            self._handle_stop_command()
        elif base_command == "status":
            self._handle_status_command(execution_type)
        elif base_command == "patch":
            self._handle_patch_command(version)
        elif base_command == "ddsr":
            self._handle_ddsr_command(version)
        elif base_command == "build":
            self._handle_build_command(version)
    
    def _handle_check_command(self, version: Optional[str], check_type: str = 'server') -> None:
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
    
    def _handle_run_command(self, version: Optional[str], execution_type: str = 'server') -> None:
        """处理启动命令"""
        target_version = version or self.selected_version
        
        if execution_type == 'client':
            # 客户端模式：只启动客户端，不启动服务端
            self.log_message("开始启动客户端...")
            self._handle_client_run(target_version)
        elif execution_type == 'server':
            # 服务端模式：启动服务端
            self.log_message("开始启动服务端...")
            self._handle_server_run(target_version)
        elif execution_type == 'all':
            # 全部模式：先启动服务端，再启动客户端
            self.log_message("开始启动服务端和客户端...")
            
            # 先启动服务端
            self.log_message("正在启动服务端...")
            self._handle_server_run(target_version)
            
            # 直接启动客户端，不再等待
            self.log_message("正在启动客户端...")
            self._handle_client_run(target_version)
        else:
            self.log_message(f"未知的执行类型: {execution_type}", "ERROR")
    
    def _handle_server_run(self, target_version: str) -> None:
        """处理服务端启动"""
        # 设置runner的版本目录
        self.runner.set_release_version(target_version)
        
        # 移除config.toml自动更新功能 - 根据用户需求，不再修改配置文件
        
        # 先进行环境检查（仅检查服务端环境）
        if self.checker.run_all_checks(target_version, check_client=False):
            processes = self.runner.start_all_servers()
            if processes:
                self.log_message(f"已启动 {len(processes)} 个服务端", "INFO")
                self.log_message("使用 --status 查看运行状态", "INFO")
                self.log_message("使用 --stop 停止所有服务端", "INFO")
            else:
                self.log_message("服务端启动失败", "ERROR")
        else:
            self.log_message("环境检查未通过，无法启动服务端", "ERROR")
    
    def _handle_client_run(self, target_version: str) -> None:
        """处理客户端启动"""
        # 进行客户端环境检查
        if self.checker.run_client_checks(target_version):
            self.log_message("客户端环境检查通过", "INFO")
            
            # 生成config.toml配置文件
            success = self._generate_client_config()
            if success:
                self.log_message("客户端配置文件生成完成", "INFO")
                
                # 启动客户端launcher.exe
                launcher_success = self._launch_client()
                if launcher_success:
                    self.log_message("客户端启动成功", "INFO")
                else:
                    self.log_message("客户端启动失败", "ERROR")
            else:
                self.log_message("客户端配置文件生成失败", "ERROR")
        else:
            self.log_message("客户端环境检查未通过，无法启动客户端", "ERROR")
    
    def _generate_client_config(self) -> bool:
        """生成客户端config.toml配置文件"""
        try:
            # 获取客户端二进制目录路径
            client_binary_path = self.path_resolver.get_client_binary_path()
            config_file_path = client_binary_path / "config.toml"
            
            # 查找DLL文件，只保留包含"wicked-waifus"关键词的DLL文件
            dll_files = []
            all_dll_files = []
            for dll_file in client_binary_path.glob("*.dll"):
                dll_path = str(dll_file).replace("\\", "/")
                all_dll_files.append(dll_file.name)
                # 只保留包含"wicked-waifus"关键词的DLL文件
                if "wicked-waifus" in dll_file.name.lower():
                    dll_files.append(dll_path)
            
            if not dll_files:
                self.log_message("未找到包含'wicked-waifus'关键词的DLL文件，将使用空的dll_list", "WARNING")
                if all_dll_files:
                    self.log_message(f"发现的所有DLL文件: {', '.join(all_dll_files)}", "INFO")
            else:
                filtered_count = len(all_dll_files) - len(dll_files)
                if filtered_count > 0:
                    self.log_message(f"已过滤掉 {filtered_count} 个不相关的DLL文件", "INFO")
            
            # 生成配置内容
            config_content = f"""[launcher]
executable_file = 'Client-Win64-Shipping.exe'
cmd_line_args = '-fileopenlog'
current_dir = '{str(client_binary_path).replace(chr(92), "/")}'
dll_list = {dll_files}

[environment]
#vars = ['TESTVAR1=AAAAAA', 'TESTVAR2=AAAAAA']
#use_system_env = true
#environment_append = false
"""
            
            # 写入配置文件
            with open(config_file_path, 'w', encoding='utf-8') as f:
                f.write(config_content)
            
            self.log_message(f"配置文件已生成: {config_file_path}", "INFO")
            self.log_message(f"当前目录: {client_binary_path}", "INFO")
            self.log_message(f"找到 {len(dll_files)} 个DLL文件", "INFO")
            
            return True
            
        except Exception as e:
            self.log_message(f"生成配置文件失败: {str(e)}", "ERROR")
            return False
    
    def _launch_client(self) -> bool:
        """启动客户端launcher.exe（以管理员权限）"""
        try:
            # 获取客户端二进制目录路径
            client_binary_path = self.path_resolver.get_client_binary_path()
            launcher_path = client_binary_path / "launcher.exe"
            
            # 检查launcher.exe是否存在
            if not launcher_path.exists():
                self.log_message(f"未找到launcher.exe: {launcher_path}", "ERROR")
                return False
            
            # 启动launcher.exe（以管理员权限）
            self.log_message(f"正在以管理员权限启动客户端: {launcher_path}", "INFO")
            
            # 使用PowerShell的Start-Process命令以管理员权限启动
            powershell_cmd = [
                "powershell.exe",
                "-Command",
                f"Start-Process -FilePath '{launcher_path}' -WorkingDirectory '{client_binary_path}' -Verb RunAs"
            ]
            
            process = subprocess.Popen(
                powershell_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # 等待PowerShell命令执行完成
            process.wait()
            
            if process.returncode == 0:
                self.log_message("客户端已以管理员权限启动", "INFO")
                return True
            else:
                self.log_message("启动客户端失败，可能用户拒绝了管理员权限请求", "ERROR")
                return False
            
        except Exception as e:
            self.log_message(f"启动客户端失败: {str(e)}", "ERROR")
            return False

    def _handle_stop_command(self, execution_type: str = 'server') -> None:
        """处理停止服务端命令"""
        self.log_message("开始停止服务端...", "INFO")
        success = self.runner.stop_all_servers()
        if success:
            self.log_message("服务端已停止", "INFO")
        else:
            self.log_message("没有运行中的服务端", "INFO")
    
    def _handle_status_command(self, execution_type: str = 'server') -> None:
        """处理状态查看命令"""
        self.status.show_status()
    

    
    def _handle_patch_command(self, version: str, execution_type: str = 'client') -> None:
        """处理客户端补丁命令"""
        self.log_message(f"开始应用客户端补丁 (版本: {version})...")
        success = self.client_patcher.patch_client(version)
        if success:
            self.log_message(f"客户端补丁应用完成 (版本: {version})", "INFO")
            self.log_message("可以启动客户端了", "INFO")
        else:
            self.log_message(f"客户端补丁应用失败 (版本: {version})", "ERROR")
        if success:
            self.log_message("客户端补丁应用完成", "INFO")
        else:
            self.log_message("客户端补丁应用失败，但服务端已启动", "ERROR")
            return
    
    def _handle_ddsr_command(self, version: str, execution_type: str = 'server') -> None:
        """处理服务端发行版下载命令"""
        try:
            self.log_message(f"开始下载服务端发行版 (版本: {version})...", "INFO")
            
            # 定义下载源
            sources = [
                f"https://gitee.com/GamblerIX/Server/releases/download/v{version}/{version}.zip",
                f"https://github.com/GamblerIX/Server/releases/download/v{version}/{version}.zip"
            ]
            
            # 选择最优下载源
            self.log_message("正在检测网络延迟，选择最优下载源...", "INFO")
            best_source = self.network_tester.select_best_source(sources)
            self.log_message(f"已选择下载源: {best_source}", "INFO")
            
            # 准备下载路径 - 使用版本号创建子目录
            release_dir = self.path_resolver.get_server_release_path(version)
            if not release_dir.exists():
                release_dir.mkdir(parents=True, exist_ok=True)
                self.log_message(f"创建发行版目录: {release_dir}", "INFO")
            
            zip_file_path = release_dir / f"{version}.zip"
            
            # 下载文件
            self.log_message(f"开始下载文件到: {zip_file_path}", "INFO")
            download_success = self.downloader.download_file(best_source, zip_file_path)
            
            if not download_success:
                raise WuWaNetworkException(f"下载失败: {best_source}")
            
            self.log_message("文件下载完成", "INFO")
            
            # 解压文件
            self.log_message("开始解压文件...", "INFO")
            extract_success = self.extractor.extract_zip(zip_file_path, release_dir)
            
            if not extract_success:
                raise WuWaFileException(f"解压失败: {zip_file_path}")
            
            self.log_message("文件解压完成", "INFO")
            
            # 清理下载的压缩包
            self.log_message("清理临时文件...", "INFO")
            cleanup_success = self.extractor.cleanup_zip_file(zip_file_path)
            
            if cleanup_success:
                self.log_message("临时文件清理完成", "INFO")
            else:
                self.log_message("临时文件清理失败，但不影响功能", "WARNING")
            
            self.log_message(f"服务端发行版下载完成 (版本: {version})", "INFO")
            self.log_message(f"文件已解压到: {release_dir}", "INFO")
            
        except WuWaException as e:
            self.log_message(f"服务端发行版下载失败: {str(e)}", "ERROR")
            raise
        except Exception as e:
            error_msg = f"服务端发行版下载过程中发生未知错误: {str(e)}"
            self.log_message(error_msg, "ERROR")
            raise WuWaException(error_msg)
    
    def _handle_build_command(self, version: Optional[str] = None) -> None:
        """处理构建命令"""
        try:
            # 如果没有提供版本，使用时间戳生成版本号
            if not version:
                from datetime import datetime
                version = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.log_message(f"未指定版本，使用时间戳版本: {version}", "INFO")
            
            self.log_message(f"=== 开始构建服务器组件 (版本: {version}) ===", "INFO")
            
            # 验证构建环境
            self.log_message("验证构建环境...", "INFO")
            build_env = self.build_manager.validate_build_environment()
            
            if not build_env.environment_valid:
                self.log_message(f"[错误] 构建环境无效: {build_env.error_message}", "ERROR")
                self.log_message("请确保已安装Rust和Cargo工具链", "ERROR")
                self.log_message("安装指南: https://rustup.rs/", "INFO")
                return
            
            self.log_message("[成功] 构建环境验证通过", "INFO")
            self.log_message(f"Cargo版本: {build_env.cargo_version}", "INFO")
            self.log_message(f"Rustc版本: {build_env.rustc_version}", "INFO")
            
            # 开始构建所有服务器组件
            self.log_message("开始编译所有服务器组件...", "INFO")
            build_results = self.build_manager.build_all_servers(version)
            
            # 统计构建结果
            successful_builds = [name for name, result in build_results.items() if result.success]
            failed_builds = [name for name, result in build_results.items() if not result.success]
            
            self.log_message(f"=== 构建结果摘要 ===", "INFO")
            self.log_message(f"成功: {len(successful_builds)}/{len(build_results)}", "INFO")
            
            if successful_builds:
                self.log_message("成功构建的组件:", "INFO")
                for component in successful_builds:
                    result = build_results[component]
                    self.log_message(f"  - {component} (耗时: {result.build_time:.2f}秒)", "INFO")
            
            if failed_builds:
                self.log_message("构建失败的组件:", "ERROR")
                for component in failed_builds:
                    result = build_results[component]
                    self.log_message(f"  - {component}: {result.error_message}", "ERROR")
            
            # 如果有成功的构建，创建发布包
            if successful_builds:
                self.log_message("创建发布包...", "INFO")
                package_success = self.build_manager.create_release_package(version)
                
                if package_success:
                    release_path = self.project_root / "release" / version
                    self.log_message(f"[成功] 发布包已创建: {release_path}", "INFO")
                    self.log_message("可以使用以下命令启动服务器:", "INFO")
                    self.log_message(f"  python wuwa_server.py --run --version {version}", "INFO")
                else:
                    self.log_message("[错误] 发布包创建失败", "ERROR")
            else:
                self.log_message("[错误] 没有成功构建的组件，跳过发布包创建", "ERROR")
            
            # 构建完成总结
            if len(successful_builds) == len(build_results):
                self.log_message(f"=== 构建完成 - 全部成功 ===", "INFO")
            elif successful_builds:
                self.log_message(f"=== 构建完成 - 部分成功 ===", "WARNING")
            else:
                self.log_message(f"=== 构建失败 - 请检查错误信息 ===", "ERROR")
                
        except Exception as e:
            self.log_message(f"[错误] 构建过程中发生异常: {str(e)}", "ERROR")
            self.handle_exception(e, "构建命令处理")
    
def main():
    """主入口函数"""
    manager = WuWaManager()
    manager.run()


if __name__ == "__main__":
    main()