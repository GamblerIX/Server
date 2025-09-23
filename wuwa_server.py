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

class WuWaConfig:
    """统一配置管理类 - 消除硬编码"""
    
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
    
    PATHS = {
        "client_binary": "Client/Client/Binaries/Win64",
        "client_content": "Client/Client/Content/Paks",
        "server_version": "Server/version",
        "launcher_exe": "launcher.exe",
        "pak_file": "rr_fixes_100_p.pak",
        "config_file": "config.toml",

        "release_dir": "release"
    }
    
    FILE_TARGET_MAPPING = {
        "pak": "client_content",
        "dll": "client_binary",
        "exe": "client_binary",
        "toml": "client_binary",
        "default": "client_binary"
    }
    
    FILE_EXTENSIONS = {
        "dll": "*.dll",
        "exe": "*.exe",
        "log": "*.log",
        "toml": "*.toml"
    }
    
    LOG_CONFIG = {
        "format": "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        "date_format": "%Y-%m-%d %H:%M:%S",
        "level": logging.INFO,
        "enable_file_logging": False,  # 是否启用文件日志记录
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
    
    PERFORMANCE = {
        "max_concurrent_servers": 5,  # 最大并发启动服务端数量
        "cache_enabled": True,  # 启用缓存机制
        "cache_ttl": 300,  # 缓存生存时间（秒）
        "thread_pool_size": 4  # 线程池大小
    }

class PathResolver:
    """路径解析器 - 统一管理和解析所有路径配置"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.server_dir = project_root
        self.client_dir = project_root.parent / "Client"  # 上级目录的Client
        
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
        
        file_ext = Path(filename).suffix.lower()
        if file_ext in file_mappings:
            target_type = file_mappings[file_ext]
        else:
            if filename in file_mappings:
                target_type = file_mappings[filename]
            else:
                target_type = "binary"
        
        if target_type == "content":
            return self.get_client_content_path()
        else:
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
        
        if isinstance(exception, DetailedWuWaException):
            self._log_exception(exception, operation)
            self._add_to_history(exception)
            return exception
        
        if isinstance(exception, WuWaException):
            detailed_exception = DetailedWuWaException(
                message=exception.message,
                error_code=exception.error_code,
                context=context or {"operation": operation},
                suggestions=suggestions or self._get_default_suggestions(exception),
                recoverable=self._is_recoverable(exception)
            )
        else:
            detailed_exception = DetailedWuWaException(
                message=str(exception),
                error_code=9999,
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

class ErrorCodes:
    """错误码定义"""
    UNKNOWN_ERROR = 1000
    
    CONFIG_FILE_NOT_FOUND = 1101
    CONFIG_PARSE_ERROR = 1102
    CONFIG_VALIDATION_ERROR = 1103
    
    FILE_NOT_FOUND = 1201
    FILE_PERMISSION_ERROR = 1202
    FILE_IO_ERROR = 1203
    DIRECTORY_NOT_FOUND = 1204
    
    PROCESS_START_ERROR = 1301
    PROCESS_STOP_ERROR = 1302
    PROCESS_NOT_FOUND = 1303
    PROCESS_ACCESS_DENIED = 1304
    
    PORT_IN_USE = 1401
    PORT_NOT_ACCESSIBLE = 1402
    NETWORK_CONNECTION_ERROR = 1403
    
    SERVER_START_ERROR = 1501
    SERVER_STOP_ERROR = 1502
    SERVER_CONFIG_ERROR = 1503
    
    OS_NOT_SUPPORTED = 1601
    DEPENDENCY_MISSING = 1602
    ENVIRONMENT_SETUP_ERROR = 1603
    
    VERSION_NOT_FOUND = 1701
    VERSION_INVALID = 1702
    VERSION_CONFLICT = 1703
    
    CLIENT_NOT_FOUND = 1801
    CLIENT_PATCH_ERROR = 1802
    CLIENT_VERSION_MISMATCH = 1803

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
        
        self.config = WuWaConfig.LOG_CONFIG
        self.loggers = {}
        self.handlers = {}
        self._setup_root_logger()
        self._initialized = True
    
    def _setup_root_logger(self):
        """设置根日志器"""
        root_logger = logging.getLogger("WuWa")
        root_logger.setLevel(self.config["level"])
        
        root_logger.handlers.clear()
        
        if self.config.get("enable_console_logging", True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(self._get_formatter())
            console_handler.setLevel(self.config["level"])
            root_logger.addHandler(console_handler)
            self.handlers["console"] = console_handler
        
        if self.config.get("enable_file_logging", False):
            self._setup_file_handler(root_logger)
    
    def _setup_file_handler(self, logger):
        """设置文件日志处理器"""
        try:
            from logging.handlers import RotatingFileHandler
            import os
            
            log_file_path = self.config["log_file_path"]
            log_dir = os.path.dirname(log_file_path)
            
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            file_handler = RotatingFileHandler(
                log_file_path,
                maxBytes=self.config.get("max_file_size", 10 * 1024 * 1024),
                backupCount=self.config.get("backup_count", 5),
                encoding='utf-8'
            )
            
            file_handler.setFormatter(self._get_formatter())
            file_handler.setLevel(self.config["level"])
            logger.addHandler(file_handler)
            self.handlers["file"] = file_handler
            
        except Exception as e:
            console_logger = logging.getLogger("WuWa.Logger")
            console_logger.warning(f"文件日志设置失败: {e}")
    
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
        
        root_logger = logging.getLogger("WuWa")
        if "file" not in self.handlers:
            self._setup_file_handler(root_logger)
    
    def disable_file_logging(self):
        """动态禁用文件日志记录"""
        self.config["enable_file_logging"] = False
        
        if "file" in self.handlers:
            root_logger = logging.getLogger("WuWa")
            root_logger.removeHandler(self.handlers["file"])
            self.handlers["file"].close()
            del self.handlers["file"]
    
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
            "log_levels": self.config.get("log_levels", {}),
            "handlers": list(self.handlers.keys())
        }

class BaseWuWaComponent:
    """鸣潮工具组件基类 - 提供公共功能"""
    
    def __init__(self, project_root: Path, component_name: str):
        self.project_root = project_root
        self.component_name = component_name
        
        self._cache = {}
        self._cache_timestamps = {}
        
        self._setup_logger()
        
    def _setup_logger(self) -> None:
        """设置组件专用日志器 - 使用WuWaLogger管理器"""
        logger_manager = WuWaLogger()
        
        self.logger = logger_manager.get_logger(self.component_name)
        
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
    
    def enable_file_logging(self, log_file_path: str = None) -> None:
        """启用文件日志记录"""
        if hasattr(self, 'logger_manager'):
            self.logger_manager.enable_file_logging(log_file_path)
            self.log_message(f"已启用文件日志记录: {log_file_path or 'wuwa.log'}", "INFO")
    
    def disable_file_logging(self) -> None:
        """禁用文件日志记录"""
        if hasattr(self, 'logger_manager'):
            self.logger_manager.disable_file_logging()
            self.log_message("已禁用文件日志记录", "INFO")
    
    def set_log_level(self, level: str) -> None:
        """设置日志级别"""
        if hasattr(self, 'logger_manager'):
            self.logger_manager.set_log_level(self.component_name, level)
            self.log_message(f"日志级别已设置为: {level}", "INFO")
    
    def handle_exception(self, e: Exception, context: str = "") -> None:
        """统一的异常处理方法"""
        if isinstance(e, WuWaException):
            self.log_message(f"{context}: {e.message} (错误码: {e.error_code})", "ERROR")
        else:
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
                if path.is_file():
                    raise WuWaFileException(f"文件不存在: {path}")
                else:
                    raise WuWaFileException(f"目录不存在: {path}")
            return True
        except WuWaException:
            raise
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
        
        client_binary_path = WuWaConfig.PATHS["client_binary"]
        
        possible_paths = [
            base_path / client_binary_path,
            base_path.parent / client_binary_path,
            base_path.parent.parent / client_binary_path
        ]
        
        if base_path.name.lower() == "server":
            sibling_client_path = base_path.parent / client_binary_path
            possible_paths.insert(0, sibling_client_path)
            self.log_message(f"检测到Server目录，优先搜索同级Client目录: {sibling_client_path}")
        
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
            backup_path = config_path.with_suffix('.toml.backup')
            if config_path.exists():
                shutil.copy2(config_path, backup_path)
                self.log_message(f"已备份配置文件到: {backup_path}")
            
            script_dir = self.get_script_directory()
            project_root = script_dir.parent
            
            drive_letter = str(project_root).split(':')[0]  # 获取盘符
            path_without_drive = str(project_root).replace(f'{drive_letter}:', '').replace('\\', '/')
            
            client_bin_path = f"{drive_letter}:{path_without_drive}/Client/Client/Binaries/Win64"
            
            dll_list = []
            if dll_files:
                for dll_file in dll_files:
                    dll_name = Path(dll_file).name
                    dll_path = f"{client_bin_path}/{dll_name}"
                    dll_list.append(dll_path)
            
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
            version_dir = release_dir / version
            config_path = version_dir / "config.toml"
            if config_path.exists():
                if self.update_config_paths(config_path, client_path, dll_files):
                    updated_count += 1
        else:
            for version_dir in release_dir.iterdir():
                if version_dir.is_dir():
                    config_path = version_dir / "config.toml"
                    if config_path.exists():
                        if self.update_config_paths(config_path, client_path, dll_files):
                            updated_count += 1
            
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
            
            source_dir = self.path_resolver.get_version_path(version)
            client_bin_dir = self.path_resolver.get_client_binary_path()
            client_content_dir = self.path_resolver.get_client_content_path()
            
            if not source_dir.exists():
                raise WuWaPathException(f"版本目录不存在: {source_dir}")
            
            client_bin_dir.mkdir(parents=True, exist_ok=True)
            client_content_dir.mkdir(parents=True, exist_ok=True)
            
            files_to_copy = self._get_files_to_copy(source_dir, client_bin_dir, client_content_dir)
            
            if not files_to_copy:
                raise WuWaFileException("没有找到需要复制的文件")
            
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
            dll_files = list(source_dir.glob("*.dll"))
            for dll_file in dll_files:
                files_to_copy.append({
                    "source_file": dll_file,
                    "target_dir": client_bin_dir,
                    "description": f"DLL文件 ({dll_file.name})"
                })
            
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
        
        if version:
            version_dir = release_dir / version
            if version_dir.exists():
                release_dir = version_dir
                self.log_message(f"[信息] 使用指定版本目录: {release_dir}")
            else:
                self.log_message(f"[错误] 指定版本目录不存在: {version_dir}", "ERROR")
                return False
        else:
            if release_dir.exists():
                version_dirs = [d for d in release_dir.iterdir() if d.is_dir() and d.name.replace('.', '').isdigit()]
                if version_dirs:
                    latest_version = max(version_dirs, key=lambda x: tuple(map(int, x.name.split('.'))))
                    release_dir = latest_version
                    self.log_message(f"[信息] 自动选择最新版本目录: {release_dir}")
                else:
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
                s.settimeout(0.1)
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
        
        self.log_message("=== 服务端环境检查结果摘要 ===")
        passed_count = sum(results.values())
        total_count = len(results)
        
        for check_name, result in results.items():
            status = "[通过]" if result else "[失败]"
            self.log_message(f"{status} {check_name}")
        
        self.log_message(f"服务端检查完成: {passed_count}/{total_count} 项通过")
        
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
        
        client_root_path = client_bin_path.parent.parent
        client_content_path = client_root_path / "Content" / "Paks"
        
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
        client_binary_path = WuWaConfig.PATHS["client_binary"]
        
        possible_paths = [
            base_path / client_binary_path,
            base_path.parent / client_binary_path,
            base_path.parent.parent / client_binary_path
        ]
        
        if base_path.name.lower() == "server":
            sibling_client_path = base_path.parent / client_binary_path
            possible_paths.insert(0, sibling_client_path)
        
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
        
        directory_result = self.check_client_directory()
        files_result = self.check_client_files(version)
        
        results = {
            "客户端目录": directory_result,
            "客户端必需文件": files_result
        }
        
        self.log_message("=== 客户端环境检查结果摘要 ===")
        passed_count = sum(results.values())
        total_count = len(results)
        
        for check_name, result in results.items():
            status = "[通过]" if result else "[失败]"
            self.log_message(f"{status} {check_name}")
        
        self.log_message(f"客户端检查完成: {passed_count}/{total_count} 项通过")
        
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
        
        server_result = self.run_server_checks(version)
        
        client_result = True
        if check_client:
            client_result = self.run_client_checks(version)
        else:
            self.log_message("[信息] 跳过客户端环境检查")
        
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
        
        self.logs_dir = project_root / "logs"
        self.logs_dir.mkdir(exist_ok=True)
        
        self.servers = WuWaConfig.SERVERS
    
    def set_release_version(self, version: str) -> None:
        """设置release版本目录"""
        try:
            if not version:
                base_release_dir = self.project_root / "release"
                if base_release_dir.exists():
                    version_dirs = [d for d in base_release_dir.iterdir() if d.is_dir() and d.name.replace('.', '').isdigit()]
                    if version_dirs:
                        latest_version = max(version_dirs, key=lambda x: tuple(map(int, x.name.split('.'))))
                        self.release_dir = latest_version
                        self.selected_version = latest_version.name
                        self.log_message(f"自动选择最新版本目录: {self.release_dir}")
                    else:
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
        
        cache_key = "running_processes"
        cached_processes = self.get_cached_data(cache_key)
        if cached_processes:
            self.log_message("从缓存中获取到运行中的进程信息")
            return cached_processes
        
        processes = []
        
        max_workers = min(len(self.servers), WuWaConfig.PERFORMANCE["max_concurrent_servers"])
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_server = {
                executor.submit(self._start_server_with_delay, i): (i, server) 
                for i, server in enumerate(self.servers)
            }
            
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
            self.set_cached_data(cache_key, processes)
        else:
            self.log_message("[错误] 没有成功启动任何服务端", "ERROR")
        
        self.log_message("=== 并发服务端启动完成 ===")
        return processes
    
    def _start_server_with_delay(self, server_index: int) -> Optional[subprocess.Popen]:
        """启动服务端（已移除延迟功能）"""
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
            
            process.terminate()
            
            try:
                if process.is_running():
                    process.kill()
            except psutil.NoSuchProcess:
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
        cache_key = f"server_status_{detailed}"
        cached_status = self.get_cached_data(cache_key)
        if cached_status:
            self.log_message("从缓存中获取服务端状态信息", "DEBUG")
            for line in cached_status:
                self.log_message(line, "INFO")
            return
        
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
        
        status_lines.append(f"\n总计运行数量: {running_count}/{len(self.servers)}")
        
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
        
        self.set_cached_data(cache_key, status_lines)

class ArgumentValidator:
    """参数验证器 - 实现新的参数验证规则"""
    
    BASE_PARAMS = ['run', 'patch', 'status', 'stop', 'check', 'ddsr']
    
    STACKABLE_PARAMS = {
        'first_level': ['serveronly', 'clientonly', 'all'],  # 一次叠加且互斥
        'second_level': ['version']  # 二次叠加
    }
    
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
            base_param = self._validate_base_params(args)
            
            self._check_duplicate_params(args)
            
            validated_args = self._validate_stacking_params(base_param, args)
            
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
        pass
    
    def _validate_stacking_params(self, base_param: str, args: dict) -> dict:
        """验证叠加参数的有效性"""
        rules = self.STACKING_RULES[base_param]
        validated_args = args.copy()
        
        for forbidden_param in rules.get('forbidden', []):
            if args.get(forbidden_param):
                raise WuWaException(
                    f"错误：基础参数 --{base_param} 不能与 --{forbidden_param} 参数叠加使用"
                )
        
        for required_param in rules.get('required', []):
            if not args.get(required_param):
                raise WuWaException(
                    f"错误：基础参数 --{base_param} 必须与 --{required_param} 参数叠加使用"
                )
        
        first_level_params = []
        for param in self.STACKABLE_PARAMS['first_level']:
            if args.get(param):
                first_level_params.append(param)
        
        if len(first_level_params) > 1:
            raise WuWaException(
                f"错误：一次叠加参数互斥，不能同时使用：{', '.join(['--' + p for p in first_level_params])}"
            )
        
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
    可叠加: --serveronly, --clientonly, --all, --version x.y
    
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

使用示例：
  python wuwa_server.py --run
  python wuwa_server.py --run --clientonly
  python wuwa_server.py --patch --version 1.0
  python wuwa_server.py --status --all
  python wuwa_server.py --stop
  python wuwa_server.py --check --serveronly
  python wuwa_server.py --ddsr --version 2.7
"""
        return help_text

class WuWaNetworkTester(BaseWuWaComponent):
    """网络延迟检测类 - 用于选择最优下载源"""
    
    def __init__(self, project_root: Path):
        super().__init__(project_root, "NetworkTester")
        self.timeout = 10
        
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
            
            req = urllib.request.Request(url, method='HEAD')
            req.add_header('User-Agent', 'WuWa-Server-Downloader/1.0')
            
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                end_time = time.time()
                latency = (end_time - start_time) * 1000
                
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
        self.chunk_size = 8192
        
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
            
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'WuWa-Server-Downloader/1.0')
            
            with urllib.request.urlopen(req) as response:
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
                    print()
                
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
            
            extract_to.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                total_files = len(file_list)
                
                self.log_message(f"压缩包包含 {total_files} 个文件", "INFO")
                
                for i, file_name in enumerate(file_list, 1):
                    try:
                        zip_ref.extract(file_name, extract_to)
                        print(f"\r解压进度: {i}/{total_files} ({(i/total_files)*100:.1f}%)", end='', flush=True)
                    except Exception as e:
                        self.log_message(f"解压文件失败: {file_name} - {str(e)}", "WARNING")
                        continue
                
                print()
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
        
        self.path_resolver = PathResolver(self.project_root)
        
        self.checker = WuWaEnvironmentChecker(self.project_root)
        self.runner = WuWaRun(self.project_root)
        self.status = WuWaStatus(self.project_root)
        self.config_manager = WuWaConfigManager(self.project_root)
        self.client_patcher = WuWaClientPatcher(self.project_root)
        
        self.network_tester = WuWaNetworkTester(self.project_root)
        self.downloader = WuWaDownloader(self.project_root)
        self.extractor = WuWaExtractor(self.project_root)
        
        self.selected_version = None
    
    def set_version(self, version: str) -> None:
        """设置版本"""
        self.selected_version = version
        self.runner.set_release_version(version)
        self.log_message(f"已设置版本: {version}")
    
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
        
        raw_args = {}
        i = 0
        while i < len(args):
            arg = args[i]
            if arg.startswith('--'):
                param_name = arg[2:]
                
                if param_name == 'version' and i + 1 < len(args) and not args[i + 1].startswith('--'):
                    raw_args[param_name] = args[i + 1]
                    i += 2
                else:
                    raw_args[param_name] = True
                    i += 1
            else:
                i += 1
        
        validator = ArgumentValidator()
        try:
            validated_args = validator.validate_arguments(raw_args)
        except WuWaConfigException as e:
            self.log_message(f"参数验证失败: {str(e)}", "ERROR")
            raise e
        
        if validated_args.get('version'):
            self.set_version(validated_args['version'])
        
        return validated_args
    
    def _execute_command(self, args: dict) -> None:
        """执行具体命令"""
        base_command = None
        for param in ArgumentValidator.BASE_PARAMS:
            if args.get(param):
                base_command = param
                break
        
        if not base_command:
            raise WuWaException("未找到有效的基础命令", ErrorCodes.UNKNOWN_ERROR)
        
        version = args.get('version')
        
        execution_type = 'server'  # 默认值
        if args.get('serveronly'):
            execution_type = 'server'
        elif args.get('clientonly'):
            execution_type = 'client'
        elif args.get('all'):
            execution_type = 'all'
        
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
        else:
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
            self.log_message("开始启动客户端...")
            self._handle_client_run(target_version)
        elif execution_type == 'server':
            self.log_message("开始启动服务端...")
            self._handle_server_run(target_version)
        elif execution_type == 'all':
            self.log_message("开始启动服务端和客户端...")
            
            self.log_message("正在启动服务端...")
            self._handle_server_run(target_version)
            
            self.log_message("正在启动客户端...")
            self._handle_client_run(target_version)
        else:
            self.log_message(f"未知的执行类型: {execution_type}", "ERROR")
    
    def _handle_server_run(self, target_version: str) -> None:
        """处理服务端启动"""
        self.runner.set_release_version(target_version)
        
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
        if self.checker.run_client_checks(target_version):
            self.log_message("客户端环境检查通过", "INFO")
            
            success = self._generate_client_config()
            if success:
                self.log_message("客户端配置文件生成完成", "INFO")
                
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
            client_binary_path = self.path_resolver.get_client_binary_path()
            config_file_path = client_binary_path / "config.toml"
            
            dll_files = []
            all_dll_files = []
            for dll_file in client_binary_path.glob("*.dll"):
                dll_path = str(dll_file).replace("\\", "/")
                all_dll_files.append(dll_file.name)
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
            
            config_content = f"""[launcher]
executable_file = 'Client-Win64-Shipping.exe'
cmd_line_args = '-fileopenlog'
current_dir = '{str(client_binary_path).replace(chr(92), "/")}'
dll_list = {dll_files}

[environment]
"""
            
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
            client_binary_path = self.path_resolver.get_client_binary_path()
            launcher_path = client_binary_path / "launcher.exe"
            
            if not launcher_path.exists():
                self.log_message(f"未找到launcher.exe: {launcher_path}", "ERROR")
                return False
            
            self.log_message(f"正在以管理员权限启动客户端: {launcher_path}", "INFO")
            
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
            
            sources = [
                f"https://gitee.com/GamblerIX/Server/releases/download/v{version}/{version}.zip",
                f"https://github.com/GamblerIX/Server/releases/download/v{version}/{version}.zip"
            ]
            
            self.log_message("正在检测网络延迟，选择最优下载源...", "INFO")
            best_source = self.network_tester.select_best_source(sources)
            self.log_message(f"已选择下载源: {best_source}", "INFO")
            
            release_dir = self.path_resolver.get_server_release_path(version)
            if not release_dir.exists():
                release_dir.mkdir(parents=True, exist_ok=True)
                self.log_message(f"创建发行版目录: {release_dir}", "INFO")
            
            zip_file_path = release_dir / f"{version}.zip"
            
            self.log_message(f"开始下载文件到: {zip_file_path}", "INFO")
            download_success = self.downloader.download_file(best_source, zip_file_path)
            
            if not download_success:
                raise WuWaNetworkException(f"下载失败: {best_source}")
            
            self.log_message("文件下载完成", "INFO")
            
            self.log_message("开始解压文件...", "INFO")
            extract_success = self.extractor.extract_zip(zip_file_path, release_dir)
            
            if not extract_success:
                raise WuWaFileException(f"解压失败: {zip_file_path}")
            
            self.log_message("文件解压完成", "INFO")
            
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
    
def main():
    """主入口函数"""
    manager = WuWaManager()
    manager.run()

if __name__ == "__main__":
    main()