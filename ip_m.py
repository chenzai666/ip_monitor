#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IP监控脚本 - 公网IP跨平台增强版

默认路径：
    Windows Administrator:
        Log:   C:\\Users\\Administrator\\.ip_monitor\\ip_history.log
        State: C:\\Users\\Administrator\\.ip_monitor\\state.json

功能：
1. 准确获取公网 IP 地址
2. 支持 IPv4 / IPv6 / auto 模式
3. 使用人类可读日志格式
4. 使用 state.json 保存上一次 IP，避免从日志反解析导致错误
5. 使用 ipaddress 标准库判断公网 IP
6. 支持代理
7. 默认启用 SSL 校验，可通过 --insecure 关闭
8. 支持 Windows / Linux / macOS
"""

import os
import sys
import json
import ssl
import argparse
import platform
import ipaddress
from pathlib import Path
from datetime import datetime
from urllib.request import (
    Request,
    urlopen,
    build_opener,
    ProxyHandler,
    HTTPSHandler,
)
from urllib.error import URLError, HTTPError


APP_NAME = "ip_monitor"


def get_default_app_dir():
    """
    获取默认数据目录。

    按你的要求，默认统一放在当前用户家目录下：

        Windows Administrator:
            C:\\Users\\Administrator\\.ip_monitor

        Linux root:
            /root/.ip_monitor

        普通 Linux 用户:
            /home/username/.ip_monitor

        macOS:
            /Users/username/.ip_monitor
    """
    return Path.home() / ".ip_monitor"


DEFAULT_APP_DIR = get_default_app_dir()
DEFAULT_LOG_FILE = DEFAULT_APP_DIR / "ip_history.log"
DEFAULT_STATE_FILE = DEFAULT_APP_DIR / "state.json"


IPV4_API_SERVICES = [
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip",
    "https://ipinfo.io/ip",
]

IPV6_API_SERVICES = [
    "https://api6.ipify.org",
    "https://ipv6.icanhazip.com",
]

AUTO_API_SERVICES = [
    "https://api.ipify.org",
    "https://api64.ipify.org",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip",
    "https://ipinfo.io/ip",
]


def now_str():
    """返回当前时间字符串"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def is_windows():
    """判断是否为 Windows 系统"""
    return platform.system().lower() == "windows"


def safe_chmod(path, mode):
    """
    跨平台 chmod。

    Unix-like 系统下尝试 chmod。
    Windows 下跳过，因为 Windows 权限模型不同。
    """
    if is_windows():
        return

    try:
        os.chmod(path, mode)
    except Exception:
        pass


def ensure_console_utf8():
    """
    尽量修复 Windows PowerShell / CMD 中文乱码问题。

    处理内容：
    1. 设置 Python stdout/stderr 为 UTF-8
    2. Windows 下调用系统 API 设置控制台输入/输出代码页为 UTF-8
    3. 设置 PYTHONUTF8 环境变量
    """
    try:
        os.environ.setdefault("PYTHONUTF8", "1")
    except Exception:
        pass

    if is_windows():
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32

            # 65001 = UTF-8
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
        except Exception:
            pass

    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def validate_public_ip(ip_text, ip_version="ipv4"):
    """
    验证是否为公网 IP。

    ip_version:
        ipv4  -> 只接受 IPv4 公网地址
        ipv6  -> 只接受 IPv6 公网地址
        auto  -> IPv4 / IPv6 公网地址都接受
    """
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return False

    if ip_version == "ipv4" and ip_obj.version != 4:
        return False

    if ip_version == "ipv6" and ip_obj.version != 6:
        return False

    return ip_obj.is_global


def normalize_ip(ip_text):
    """清理 IP 查询服务返回内容"""
    if not ip_text:
        return ""

    ip_text = ip_text.strip()

    # 某些服务理论上只返回一个 IP，这里防御性处理多行情况
    if "\n" in ip_text:
        ip_text = ip_text.splitlines()[0].strip()

    return ip_text


def get_services_by_version(ip_version):
    """根据 IP 类型返回查询服务列表"""
    if ip_version == "ipv4":
        return IPV4_API_SERVICES

    if ip_version == "ipv6":
        return IPV6_API_SERVICES

    return AUTO_API_SERVICES


def build_url_opener(proxy=None, insecure=False):
    """
    构建 urllib opener。

    proxy:
        例如:
            http://127.0.0.1:7890
            http://user:pass@host:port

    insecure:
        True 时跳过 SSL 证书校验
    """
    handlers = []

    if proxy:
        handlers.append(
            ProxyHandler(
                {
                    "http": proxy,
                    "https": proxy,
                }
            )
        )

    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(HTTPSHandler(context=ctx))

    if handlers:
        return build_opener(*handlers)

    return None


def fetch_url(url, opener=None, timeout=10):
    """请求 URL 并返回文本"""
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0 Safari/537.36"
    )

    req = Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/plain,*/*",
        },
    )

    if opener:
        with opener.open(req, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")

    with urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def get_public_ip(proxy=None, ip_version="ipv4", timeout=10, insecure=False, verbose=False):
    """获取公网 IP 地址"""
    services = get_services_by_version(ip_version)
    opener = build_url_opener(proxy=proxy, insecure=insecure)

    for service in services:
        try:
            if verbose:
                print(f"  - 正在尝试服务: {service}")

            body = fetch_url(service, opener=opener, timeout=timeout)
            ip = normalize_ip(body)

            if validate_public_ip(ip, ip_version=ip_version):
                if verbose:
                    print(f"  - 服务成功: {service} -> {ip}")
                return ip

            if verbose:
                print(f"  - 服务返回非公网或格式无效 IP: {service} -> {repr(ip)}")

        except HTTPError as e:
            print(f"  - 服务 {service} HTTP错误: {e.code} {e.reason}")
            continue

        except URLError as e:
            print(f"  - 服务 {service} 网络错误: {e.reason}")
            continue

        except TimeoutError:
            print(f"  - 服务 {service} 超时")
            continue

        except Exception as e:
            print(f"  - 服务 {service} 出错: {str(e)}")
            continue

    return None


def setup_files(log_path, state_path):
    """创建日志目录、状态目录和日志文件"""
    try:
        log_path = Path(log_path)
        state_path = Path(state_path)

        log_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.parent.mkdir(parents=True, exist_ok=True)

        if not log_path.exists():
            with log_path.open("w", encoding="utf-8", newline="\n") as f:
                f.write("# IP监控日志\n")
                f.write("# 格式: [时间] [状态] [详情]\n")
                f.write("# 状态说明:\n")
                f.write("#   INIT      = 首次记录\n")
                f.write("#   CHANGED   = IP发生变化\n")
                f.write("#   UNCHANGED = IP未变化\n")
                f.write("#   ERROR     = 获取或处理失败\n")
                f.write("#" * 80 + "\n")

            safe_chmod(log_path, 0o644)
            print(f"已创建日志文件: {log_path}")

        return True

    except Exception as e:
        print(f"日志或状态文件初始化失败: {str(e)}")
        return False


def write_log_entry(log_path, status, message):
    """写入日志条目"""
    try:
        log_path = Path(log_path)
        timestamp = now_str()

        with log_path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(f"[{timestamp}] {status:<9} {message}\n")

        return True

    except Exception as e:
        print(f"日志写入失败: {str(e)}")
        return False


def read_state(state_path):
    """读取状态文件"""
    state_path = Path(state_path)

    if not state_path.exists():
        return {}

    try:
        with state_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            return data

        return {}

    except json.JSONDecodeError:
        print(f"警告: 状态文件 JSON 格式损坏: {state_path}")
        return {}

    except Exception as e:
        print(f"读取状态文件失败: {str(e)}")
        return {}


def write_state(state_path, state):
    """原子写入状态文件"""
    state_path = Path(state_path)
    tmp_path = state_path.with_name(state_path.name + ".tmp")

    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)

        with tmp_path.open("w", encoding="utf-8", newline="\n") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
            f.write("\n")

        tmp_path.replace(state_path)

        safe_chmod(state_path, 0o600)

        return True

    except Exception as e:
        print(f"写入状态文件失败: {str(e)}")

        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass

        return False


def determine_status(current_ip, previous_ip):
    """判断 IP 状态"""
    if not previous_ip:
        return "INIT"

    if current_ip != previous_ip:
        return "CHANGED"

    return "UNCHANGED"


def print_start_info():
    """打印启动信息"""
    print("=" * 60)
    print(f"IP监控脚本启动 - {now_str()}")
    print(f"操作系统: {platform.system()} {platform.release()}")
    print(f"系统版本: {platform.version()}")
    print(f"机器架构: {platform.machine()}")
    print(f"Python版本: {platform.python_version()}")
    print(f"默认目录: {DEFAULT_APP_DIR}")
    print(f"默认日志: {DEFAULT_LOG_FILE}")
    print(f"默认状态: {DEFAULT_STATE_FILE}")
    print("=" * 60)


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="公网IP监控工具 - 跨平台增强版",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--log",
        default=str(DEFAULT_LOG_FILE),
        help="日志文件路径",
    )

    parser.add_argument(
        "--state",
        default=str(DEFAULT_STATE_FILE),
        help="状态文件路径，用于保存上一次 IP",
    )

    parser.add_argument(
        "--proxy",
        default=None,
        help="代理服务器，例如 http://127.0.0.1:7890",
    )

    parser.add_argument(
        "--ip-version",
        choices=["ipv4", "ipv6", "auto"],
        default="ipv4",
        help="查询 IP 类型",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="单个 IP 查询服务超时时间，单位秒",
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="跳过 HTTPS 证书校验，不推荐，除非你的环境证书有问题",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="显示详细输出",
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="不显示启动横幅，适合定时任务",
    )

    return parser.parse_args()


def resolve_path(path_text):
    """
    解析路径。

    支持：
        ~/xxx
        相对路径
        绝对路径
    """
    return Path(path_text).expanduser().resolve()


def main():
    ensure_console_utf8()

    args = parse_args()

    if not args.no_banner:
        print_start_info()

    log_path = resolve_path(args.log)
    state_path = resolve_path(args.state)

    if not setup_files(log_path, state_path):
        print("错误: 日志或状态文件初始化失败，退出程序")
        sys.exit(1)

    start_time = datetime.now()

    print("正在获取公网IP...")

    if args.verbose:
        print(f"  - IP类型: {args.ip_version}")
        print(f"  - 使用代理: {args.proxy if args.proxy else '无'}")
        print(f"  - 超时时间: {args.timeout} 秒")
        print(f"  - SSL校验: {'关闭' if args.insecure else '开启'}")
        print(f"  - 日志文件: {log_path}")
        print(f"  - 状态文件: {state_path}")
        print(f"  - 查询服务: {', '.join(get_services_by_version(args.ip_version))}")

    current_ip = get_public_ip(
        proxy=args.proxy,
        ip_version=args.ip_version,
        timeout=args.timeout,
        insecure=args.insecure,
        verbose=args.verbose,
    )

    if not current_ip:
        error_msg = f"无法获取公网IP，IP类型={args.ip_version}"
        print(f"错误: {error_msg}")
        write_log_entry(log_path, "ERROR", error_msg)
        sys.exit(1)

    state = read_state(state_path)
    previous_ip = state.get("last_ip")

    status = determine_status(current_ip, previous_ip)

    if status == "INIT":
        log_message = f"{current_ip}, 首次记录"

    elif status == "CHANGED":
        log_message = f"{previous_ip} -> {current_ip}"

    else:
        log_message = f"{current_ip}, 与上次相同"

    write_log_entry(log_path, status, log_message)

    new_state = {
        "last_ip": current_ip,
        "last_status": status,
        "last_checked_at": now_str(),
        "ip_version": args.ip_version,
        "previous_ip": previous_ip,
        "log_file": str(log_path),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
    }

    if not write_state(state_path, new_state):
        write_log_entry(log_path, "ERROR", "公网IP已获取，但状态文件写入失败")
        print("警告: 状态文件写入失败，下次可能无法正确判断 IP 是否变化")

    exec_time = (datetime.now() - start_time).total_seconds()

    print("\n公网IP监控结果:")
    print(f"  - 公网IP地址: {current_ip}")

    if status == "INIT":
        print("  - 状态: 首次记录")

    elif status == "CHANGED":
        print(f"  - 状态: IP变更 ({previous_ip} -> {current_ip})")

    else:
        print("  - 状态: IP未变化")

    print(f"  - IP类型: {args.ip_version}")
    print(f"  - Log: {log_path}")
    print(f"  - State: {state_path}")
    print(f"  - 执行耗时: {exec_time:.2f}秒")
    print("-" * 60)
    print(f"IP监控完成 - {datetime.now().strftime('%H:%M:%S')}")


if __name__ == "__main__":
    main()
