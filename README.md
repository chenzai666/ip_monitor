# ip_monitor

直接看下当前脚本最终版本的用法。
**基本用法**

```bash
# 直接运行，获取公网IP并记录
python ip_monitor.py

# 显示详细输出（会打印尝试的服务列表等）
python ip_monitor.py --verbose

# 指定自定义日志路径
python ip_monitor.py --log D:/logs/my_ip.log

# 通过代理获取公网IP
python ip_monitor.py --proxy http://127.0.0.1:7890

# 组合使用
python ip_monitor.py --verbose --proxy http://127.0.0.1:10808 --log D:/ip.log
```

**参数说明**

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--log` | 日志文件路径 | `~/.ip_monitor/ip_history.log` |
| `--proxy` | 代理地址（格式 `http://ip:port`） | 无 |
| `--verbose` | 显示详细调试信息 | 关闭 |

**运行逻辑**

1. 从 5 个公网 IP 服务依次尝试，获取当前公网 IP
2. 读取日志文件中上次记录的 IP
3. 比对后写入日志，状态分三种：
   - `INIT` — 首次运行，无历史记录
   - `CHANGED` — IP 发生变化（记录 `旧IP → 新IP`）
   - `UNCHANGED` — IP 未变化

**日志文件位置**

- Windows: `C:\Users\Administrator\.ip_monitor\ip_history.log`
- Linux: `~/.ip_monitor/ip_history.log`

**配合定时任务**

如果需要定期监控 IP 变化（比如每 5 分钟），可以设置 cron 或 Windows 计划任务：

```bash
# Linux cron
*/5 * * * * /usr/bin/python3 /path/to/ip_monitor.py
# Windows 计划任务
schtasks /create /tn "IP监控" /tr "python D:\ip_monitor.py" /sc minute /mo 5

# Windows 计划任务
schtasks /create /tn "IP监控" /tr "python D:\ip_monitor.py" /sc minute /mo 5
```
