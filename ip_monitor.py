#!/usr/bin/env python3
"""
IP监控脚本 - 增强日志可读性版本
功能：
1. 使用人类可读的日志格式
2. 保留时间戳和IP变化信息
3. 添加日志文件自动轮转功能
4. 更清晰的输出格式
"""

import os
import sys
import argparse
import platform
import socket
from pathlib import Path
from datetime import datetime

# 默认设置
DEFAULT_LOG_DIR = "/root/.ip_monitor"
DEFAULT_LOG_FILE = os.path.join(DEFAULT_LOG_DIR, "ip_history.log")
MAX_LOG_SIZE = 1 * 1024 * 1024  # 1MB
MAX_LOG_BACKUPS = 5

def get_public_ip():
    """获取公网IP地址（兼容多种方法）"""
    # 方法1：使用DNS查询（最可靠）
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google DNS
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    
    # 方法2：尝试解析主机名
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        pass
    
    # 方法3：使用网络接口信息
    try:
        import netifaces
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            if interface.startswith('lo'):
                continue
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    ip = addr_info['addr']
                    if ip != '127.0.0.1':
                        return ip
    except ImportError:
        pass
    
    return "未知"

def setup_logging(log_path):
    """创建日志目录和文件"""
    try:
        # 创建日志目录
        log_dir = os.path.dirname(log_path)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            print(f"已创建日志目录: {log_dir}")
        
        # 确保日志文件存在
        if not os.path.exists(log_path):
            with open(log_path, 'w') as f:
                f.write("# IP监控日志 - 格式: [时间] [状态] [IP地址] [变化详情]\n")
                f.write("# 状态: INIT=初始, CHANGED=变更, UNCHANGED=未变\n")
                f.write("#" * 80 + "\n")
            os.chmod(log_path, 0o644)
            print(f"已创建日志文件: {log_path}")
        
        return True
    except Exception as e:
        print(f"日志设置失败: {str(e)}")
        return False

def rotate_logs(log_path):
    """日志文件轮转"""
    if not os.path.exists(log_path):
        return
    
    try:
        # 检查文件大小
        if os.path.getsize(log_path) < MAX_LOG_SIZE:
            return
        
        print("检测到日志文件过大，执行轮转...")
        base_name = os.path.basename(log_path)
        log_dir = os.path.dirname(log_path)
        
        # 删除最旧的备份
        oldest_backup = os.path.join(log_dir, f"{base_name}.{MAX_LOG_BACKUPS}")
        if os.path.exists(oldest_backup):
            os.remove(oldest_backup)
        
        # 重命名现有备份
        for i in range(MAX_LOG_BACKUPS - 1, 0, -1):
            src = os.path.join(log_dir, f"{base_name}.{i}")
            dest = os.path.join(log_dir, f"{base_name}.{i+1}")
            if os.path.exists(src):
                os.rename(src, dest)
        
        # 重命名当前日志
        os.rename(log_path, os.path.join(log_dir, f"{base_name}.1"))
        
        # 创建新日志文件
        with open(log_path, 'w') as f:
            f.write("# IP监控日志 - 格式: [时间] [状态] [IP地址] [变化详情]\n")
            f.write("# 状态: INIT=初始, CHANGED=变更, UNCHANGED=未变\n")
            f.write("#" * 80 + "\n")
        
        print(f"日志已轮转: 保留了 {MAX_LOG_BACKUPS} 个备份")
    except Exception as e:
        print(f"日志轮转失败: {str(e)}")

def write_log_entry(log_path, timestamp, status, ip, previous_ip=None):
    """写入人类可读的日志条目"""
    try:
        with open(log_path, 'a') as f:
            if status == "INIT":
                f.write(f"[{timestamp}] INIT   {ip} (首次记录)\n")
            elif status == "CHANGED":
                f.write(f"[{timestamp}] CHANGED {previous_ip} → {ip}\n")
            else:  # UNCHANGED
                f.write(f"[{timestamp}] UNCHANGED {ip} (与上次相同)\n")
        return True
    except Exception as e:
        print(f"日志写入失败: {str(e)}")
        return False

def main():
    # 显示脚本信息
    print("=" * 60)
    print(f"IP监控脚本启动 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"操作系统: {platform.system()} {platform.release()}")
    print(f"Python版本: {platform.python_version()}")
    print("=" * 60)
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description='公网IP监控工具 - 增强日志可读性版',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--log', default=DEFAULT_LOG_FILE,
                        help=f'日志文件路径（默认: {DEFAULT_LOG_FILE}）')
    parser.add_argument('--verbose', action='store_true',
                        help='显示详细输出')
    args = parser.parse_args()
    
    # 处理日志文件路径
    log_path = Path(args.log).resolve()
    
    # 创建日志目录和文件
    if not setup_logging(log_path):
        print("错误: 日志设置失败，退出程序")
        sys.exit(1)
    
    # 日志轮转
    rotate_logs(log_path)
    
    # 获取当前时间和公网IP
    start_time = datetime.now()
    timestamp = start_time.strftime('%Y-%m-%d %H:%M:%S')
    
    if args.verbose:
        print("正在获取公网IP...")
    
    current_ip = get_public_ip()
    
    if not current_ip or current_ip == "未知":
        error_msg = f"[{timestamp}] 错误: 无法确定公网IP"
        print(error_msg)
        
        # 记录错误到日志
        try:
            with open(log_path, 'a') as f:
                f.write(f"[{timestamp}] ERROR 无法获取公网IP\n")
        except Exception:
            pass
            
        sys.exit(1)
    
    # 读取上次记录的IP（简化方法）
    last_ip = None
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                # 从后向前扫描找到最后一个IP记录
                for line in reversed(lines):
                    if 'UNCHANGED' in line or 'CHANGED' in line or 'INIT' in line:
                        parts = line.split()
                        # 尝试找到IP地址（格式为 xxx.xxx.xxx.xxx）
                        for part in parts:
                            if '.' in part and part.count('.') == 3 and len(part) > 6:
                                last_ip = part
                                break
                        if last_ip:
                            break
        except Exception:
            pass
    
    # 确定状态
    if last_ip is None:
        status = "INIT"
    elif current_ip != last_ip:
        status = "CHANGED"
    else:
        status = "UNCHANGED"
    
    # 写入日志文件
    write_log_entry(log_path, timestamp, status, current_ip, last_ip)
    
    # 控制台输出
    exec_time = (datetime.now() - start_time).total_seconds()
    print("\nIP监控结果:")
    print(f"  - 当前公网IP: {current_ip}")
    
    if status == "INIT":
        print(f"  - 状态: 首次记录")
    elif status == "CHANGED":
        print(f"  - 状态: IP变更 ({last_ip} → {current_ip})")
    else:
        print(f"  - 状态: IP未变化")
    
    print(f"  - 日志文件: {log_path}")
    print(f"  - 执行耗时: {exec_time:.2f}秒")
    print("-" * 60)
    print(f"IP监控完成 - {datetime.now().strftime('%H:%M:%S')}")

if __name__ == "__main__":
    main()
