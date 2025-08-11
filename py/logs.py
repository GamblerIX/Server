#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
鸣潮服务端日志管理脚本

功能：
- 日志文件查看和分析
- 日志文件管理（清理、归档）
- 实时日志监控
- 错误日志过滤
- 日志统计分析
"""

import os
import re
import sys
import time
import gzip
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from threading import Thread, Event
from collections import defaultdict, Counter

class WuWaLogs:
    """鸣潮服务端日志管理类"""
    
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.logs_dir = self.project_root / "logs"
        
        # 确保目录存在
        self.logs_dir.mkdir(exist_ok=True)
        
        # 日志文件配置
        self.log_files = {
            "run": "run.log",
            "status": "status.log",
            "config": "config-server.log",
            "hotpatch": "hotpatch-server.log",
            "login": "login-server.log",
            "gateway": "gateway-server.log",
            "game": "game-server.log"
        }
        
        # 日志级别颜色
        self.log_colors = {
            "ERROR": "\033[91m",    # 红色
            "WARN": "\033[93m",     # 黄色
            "WARNING": "\033[93m",  # 黄色
            "INFO": "\033[92m",     # 绿色
            "DEBUG": "\033[94m",    # 蓝色
            "RESET": "\033[0m"      # 重置
        }
        
        # 监控标志
        self.monitoring = False
        self.monitor_event = Event()
        
    def log_message(self, message, log_type="INFO"):
        """记录日志消息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{log_type}] {message}"
        
        # 输出到控制台
        print(log_entry)
        
        # 写入日志文件
        log_file = self.logs_dir / "logs.log"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
            
    def get_log_files_info(self):
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
        
    def show_log_files_list(self):
        """显示日志文件列表"""
        print("\n" + "=" * 80)
        print("                        鸣潮服务端日志文件")
        print("=" * 80)
        
        files_info = self.get_log_files_info()
        
        print(f"{'序号':<4} {'类型':<12} {'文件名':<25} {'大小':<10} {'最后修改时间':<20} {'状态':<8}")
        print("-" * 80)
        
        for i, (log_key, info) in enumerate(files_info.items(), 1):
            if info['exists']:
                size_str = f"{info['size_mb']:.1f} MB"
                mtime_str = info['modified_time'].strftime("%Y-%m-%d %H:%M:%S")
                status = "存在"
            else:
                size_str = "0 MB"
                mtime_str = "-"
                status = "不存在"
                
            print(f"{i:<4} {log_key:<12} {info['filename']:<25} {size_str:<10} {mtime_str:<20} {status:<8}")
            
        print("\n" + "=" * 80)
        
    def read_log_file(self, log_key, lines=50, follow=False):
        """读取日志文件"""
        if log_key not in self.log_files:
            print(f"错误: 未知的日志类型 '{log_key}'")
            return
            
        log_path = self.logs_dir / self.log_files[log_key]
        
        if not log_path.exists():
            print(f"日志文件不存在: {log_path}")
            return
            
        try:
            if follow:
                self._follow_log_file(log_path)
            else:
                self._read_log_lines(log_path, lines)
        except Exception as e:
            self.log_message(f"读取日志文件时发生错误: {e}", "ERROR")
            
    def _read_log_lines(self, log_path, lines):
        """读取日志文件的最后几行"""
        print(f"\n[文件] 日志文件: {log_path.name}")
        print(f"[内容] 最后 {lines} 行内容:")
        print("-" * 80)
        
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                # 读取所有行
                all_lines = f.readlines()
                
                # 获取最后几行
                last_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
                
                for line in last_lines:
                    colored_line = self._colorize_log_line(line.rstrip())
                    print(colored_line)
                    
        except UnicodeDecodeError:
            # 尝试其他编码
            try:
                with open(log_path, "r", encoding="gbk") as f:
                    all_lines = f.readlines()
                    last_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
                    
                    for line in last_lines:
                        colored_line = self._colorize_log_line(line.rstrip())
                        print(colored_line)
            except Exception as e:
                print(f"无法读取文件 (编码错误): {e}")
                
        print("-" * 80)
        
    def _follow_log_file(self, log_path):
        """实时跟踪日志文件"""
        print(f"\n[监控] 实时监控日志文件: {log_path.name}")
        print("按 Ctrl+C 停止监控")
        print("-" * 80)
        
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                # 移动到文件末尾
                f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if line:
                        colored_line = self._colorize_log_line(line.rstrip())
                        print(colored_line)
                    else:
                        time.sleep(0.1)
                        
        except KeyboardInterrupt:
            print("\n监控已停止")
        except Exception as e:
            print(f"监控日志时发生错误: {e}")
            
    def _colorize_log_line(self, line):
        """为日志行添加颜色"""
        # 检查日志级别
        for level, color in self.log_colors.items():
            if level == "RESET":
                continue
                
            if f"[{level}]" in line or f" {level} " in line:
                return f"{color}{line}{self.log_colors['RESET']}"
                
        return line
        
    def search_logs(self, pattern, log_keys=None, case_sensitive=False):
        """搜索日志内容"""
        if log_keys is None:
            log_keys = list(self.log_files.keys())
        elif isinstance(log_keys, str):
            log_keys = [log_keys]
            
        print(f"\n[搜索] 搜索模式: '{pattern}'")
        print(f"[范围] 搜索范围: {', '.join(log_keys)}")
        print("-" * 80)
        
        total_matches = 0
        flags = 0 if case_sensitive else re.IGNORECASE
        
        try:
            regex = re.compile(pattern, flags)
        except re.error as e:
            print(f"正则表达式错误: {e}")
            return
            
        for log_key in log_keys:
            if log_key not in self.log_files:
                continue
                
            log_path = self.logs_dir / self.log_files[log_key]
            if not log_path.exists():
                continue
                
            matches = self._search_in_file(log_path, regex)
            if matches:
                print(f"\n[文件] {log_path.name} ({len(matches)} 个匹配):")
                for line_num, line in matches:
                    colored_line = self._colorize_log_line(line)
                    print(f"  {line_num:4}: {colored_line}")
                total_matches += len(matches)
                
        print(f"\n[结果] 总共找到 {total_matches} 个匹配项")
        
    def _search_in_file(self, file_path, regex, max_matches=100):
        """在文件中搜索匹配项"""
        matches = []
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    if regex.search(line):
                        matches.append((line_num, line.rstrip()))
                        if len(matches) >= max_matches:
                            break
        except UnicodeDecodeError:
            try:
                with open(file_path, "r", encoding="gbk") as f:
                    for line_num, line in enumerate(f, 1):
                        if regex.search(line):
                            matches.append((line_num, line.rstrip()))
                            if len(matches) >= max_matches:
                                break
            except Exception:
                pass
        except Exception:
            pass
            
        return matches
        
    def analyze_logs(self, log_keys=None, hours=24):
        """分析日志统计信息"""
        if log_keys is None:
            log_keys = list(self.log_files.keys())
        elif isinstance(log_keys, str):
            log_keys = [log_keys]
            
        print(f"\n[分析] 日志分析 (最近 {hours} 小时)")
        print("=" * 80)
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        total_stats = {
            "total_lines": 0,
            "error_count": 0,
            "warning_count": 0,
            "info_count": 0,
            "debug_count": 0,
            "hourly_distribution": defaultdict(int),
            "error_messages": Counter()
        }
        
        for log_key in log_keys:
            if log_key not in self.log_files:
                continue
                
            log_path = self.logs_dir / self.log_files[log_key]
            if not log_path.exists():
                continue
                
            print(f"\n[文件] 分析 {log_path.name}:")
            file_stats = self._analyze_log_file(log_path, cutoff_time)
            
            if file_stats:
                print(f"  总行数: {file_stats['total_lines']}")
                print(f"  错误: {file_stats['error_count']}")
                print(f"  警告: {file_stats['warning_count']}")
                print(f"  信息: {file_stats['info_count']}")
                print(f"  调试: {file_stats['debug_count']}")
                
                # 合并统计
                for key in ['total_lines', 'error_count', 'warning_count', 'info_count', 'debug_count']:
                    total_stats[key] += file_stats[key]
                    
                for hour, count in file_stats['hourly_distribution'].items():
                    total_stats['hourly_distribution'][hour] += count
                    
                total_stats['error_messages'].update(file_stats['error_messages'])
            else:
                print("  无数据或文件为空")
                
        # 显示总体统计
        print(f"\n[统计] 总体统计:")
        print("-" * 40)
        print(f"总行数: {total_stats['total_lines']}")
        print(f"错误: {total_stats['error_count']}")
        print(f"警告: {total_stats['warning_count']}")
        print(f"信息: {total_stats['info_count']}")
        print(f"调试: {total_stats['debug_count']}")
        
        # 显示每小时分布
        if total_stats['hourly_distribution']:
            print(f"\n[时间] 每小时日志分布:")
            print("-" * 40)
            sorted_hours = sorted(total_stats['hourly_distribution'].items())
            for hour, count in sorted_hours[-12:]:  # 显示最近12小时
                bar = "█" * min(count // 10, 50)  # 简单的条形图
                print(f"  {hour:2}时: {count:4} {bar}")
                
        # 显示常见错误
        if total_stats['error_messages']:
            print(f"\n[错误] 常见错误 (前5个):")
            print("-" * 40)
            for error, count in total_stats['error_messages'].most_common(5):
                print(f"  {count:3}x {error[:60]}..." if len(error) > 60 else f"  {count:3}x {error}")
                
        print("\n" + "=" * 80)
        
    def _analyze_log_file(self, file_path, cutoff_time):
        """分析单个日志文件"""
        stats = {
            "total_lines": 0,
            "error_count": 0,
            "warning_count": 0,
            "info_count": 0,
            "debug_count": 0,
            "hourly_distribution": defaultdict(int),
            "error_messages": Counter()
        }
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    stats['total_lines'] += 1
                    
                    # 提取时间戳
                    timestamp = self._extract_timestamp(line)
                    if timestamp and timestamp >= cutoff_time:
                        hour = timestamp.hour
                        stats['hourly_distribution'][hour] += 1
                        
                        # 统计日志级别
                        if '[ERROR]' in line or ' ERROR ' in line:
                            stats['error_count'] += 1
                            # 提取错误消息
                            error_msg = self._extract_error_message(line)
                            if error_msg:
                                stats['error_messages'][error_msg] += 1
                        elif '[WARN]' in line or '[WARNING]' in line or ' WARN ' in line:
                            stats['warning_count'] += 1
                        elif '[INFO]' in line or ' INFO ' in line:
                            stats['info_count'] += 1
                        elif '[DEBUG]' in line or ' DEBUG ' in line:
                            stats['debug_count'] += 1
                            
        except UnicodeDecodeError:
            try:
                with open(file_path, "r", encoding="gbk") as f:
                    # 重复相同的逻辑
                    for line in f:
                        stats['total_lines'] += 1
                        # ... (相同的处理逻辑)
            except Exception:
                return None
        except Exception:
            return None
            
        return stats
        
    def _extract_timestamp(self, line):
        """从日志行中提取时间戳"""
        # 常见的时间戳格式
        patterns = [
            r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]',
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
            r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    timestamp_str = match.group(1)
                    # 尝试不同的时间格式
                    for fmt in ['%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S']:
                        try:
                            return datetime.strptime(timestamp_str, fmt)
                        except ValueError:
                            continue
                except Exception:
                    pass
                    
        return None
        
    def _extract_error_message(self, line):
        """从错误日志行中提取错误消息"""
        # 尝试提取错误消息的主要部分
        patterns = [
            r'\[ERROR\]\s*(.+)',
            r'ERROR:\s*(.+)',
            r'Error:\s*(.+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                error_msg = match.group(1).strip()
                # 截取前100个字符
                return error_msg[:100] if len(error_msg) > 100 else error_msg
                
        return None
        
    def clean_logs(self, days_to_keep=7, compress_old=True):
        """清理旧日志文件"""
        print(f"\n[清理] 清理日志文件 (保留最近 {days_to_keep} 天)")
        print("=" * 60)
        
        cutoff_time = datetime.now() - timedelta(days=days_to_keep)
        cleaned_files = []
        compressed_files = []
        
        # 清理主日志文件
        for log_key, log_filename in self.log_files.items():
            log_path = self.logs_dir / log_filename
            
            if log_path.exists():
                stat = log_path.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime)
                
                if mtime < cutoff_time:
                    if compress_old:
                        # 压缩旧文件
                        compressed_path = self._compress_log_file(log_path)
                        if compressed_path:
                            compressed_files.append(compressed_path)
                            log_path.unlink()  # 删除原文件
                            cleaned_files.append(log_filename)
                    else:
                        # 直接删除
                        log_path.unlink()
                        cleaned_files.append(log_filename)
                        
        # 清理状态报告文件
        report_pattern = "status_report_*.txt"
        for report_file in self.logs_dir.glob(report_pattern):
            stat = report_file.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime)
            
            if mtime < cutoff_time:
                report_file.unlink()
                cleaned_files.append(report_file.name)
                
        # 显示结果
        if cleaned_files:
            print(f"[成功] 已清理 {len(cleaned_files)} 个文件:")
            for filename in cleaned_files:
                print(f"  - {filename}")
        else:
            print("[信息] 没有需要清理的文件")
            
        if compressed_files:
            print(f"\n[压缩] 已压缩 {len(compressed_files)} 个文件:")
            for filepath in compressed_files:
                print(f"  - {filepath.name}")
                
        print("\n" + "=" * 60)
        
    def _compress_log_file(self, log_path):
        """压缩日志文件"""
        try:
            compressed_path = log_path.with_suffix(log_path.suffix + '.gz')
            
            with open(log_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                    
            return compressed_path
        except Exception as e:
            self.log_message(f"压缩文件失败 {log_path}: {e}", "ERROR")
            return None
            
    def export_logs(self, output_dir, log_keys=None, date_range=None):
        """导出日志文件"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        if log_keys is None:
            log_keys = list(self.log_files.keys())
        elif isinstance(log_keys, str):
            log_keys = [log_keys]
            
        print(f"\n[导出] 导出日志到: {output_path}")
        print("=" * 60)
        
        exported_files = []
        
        for log_key in log_keys:
            if log_key not in self.log_files:
                continue
                
            log_path = self.logs_dir / self.log_files[log_key]
            if not log_path.exists():
                continue
                
            # 生成导出文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_filename = f"{log_key}_{timestamp}.log"
            export_path = output_path / export_filename
            
            try:
                if date_range:
                    # 按日期范围过滤
                    self._export_filtered_log(log_path, export_path, date_range)
                else:
                    # 直接复制
                    shutil.copy2(log_path, export_path)
                    
                exported_files.append(export_filename)
                print(f"[成功] {log_key}: {export_filename}")
                
            except Exception as e:
                print(f"[失败] {log_key}: 导出失败 - {e}")
                
        print(f"\n[统计] 总计导出 {len(exported_files)} 个文件")
        print("\n" + "=" * 60)
        
    def _export_filtered_log(self, source_path, target_path, date_range):
        """按日期范围导出日志"""
        start_date, end_date = date_range
        
        with open(source_path, "r", encoding="utf-8") as f_in:
            with open(target_path, "w", encoding="utf-8") as f_out:
                for line in f_in:
                    timestamp = self._extract_timestamp(line)
                    if timestamp and start_date <= timestamp <= end_date:
                        f_out.write(line)

def main():
    """测试函数"""
    project_root = Path(__file__).parent.parent
    log_manager = WuWaLogs(project_root)
    
    print("日志管理测试...")
    
    # 显示日志文件列表
    log_manager.show_log_files_list()
    
    # 分析日志
    log_manager.analyze_logs(hours=24)

if __name__ == "__main__":
    main()