#!/usr/bin/env python3
import asyncio
import aiohttp
import argparse
from netaddr import IPNetwork
import ssl
import os
from datetime import datetime
from bs4 import BeautifulSoup

# 全局配置
TIMEOUT_CONNECT = 1.5  # 端口连接超时 (秒)
CONCURRENCY = 100      # 并发数量
HTTP_TIMEOUT = 5       # HTTP请求超时 (秒)
SSL_CONTEXT = ssl.create_default_context()  # 禁用SSL验证
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

# 要扫描的端口列表
TARGET_PORTS = [
    10000, 10001, 10002, 10040, 10041, 10086, 10443, 10716, 1080, 
    11000, 11081, 11103, 11104, 11443, 12200, 13000, 13161, 14001, 
    1443, 15666, 1666, 17001, 17080, 18000, 18001, 18002, 18003, 
    18017, 18044, 18045, 18051, 18080, 18081, 18083, 18085, 18086, 
    18088, 18090, 18091, 18182, 18443, 18888, 19002, 1935, 19999, 
    20000, 20001, 20002, 20010, 20018, 20080, 20100, 20443, 20500, 
    21082, 21325, 21326, 21327, 2300, 2301, 2443, 27038, 28002, 
    28004, 28080, 28082, 28083, 28824, 29096, 29803, 29807, 29808, 
    29998, 29999, 3000, 30000, 30001, 30085, 30087, 30088, 30090, 
    30100, 30301, 30302, 30303, 30785, 31321, 31323, 32000, 32443, 
    35100, 38080, 38097, 38099, 41326, 41329, 441, 4410, 443, 4430, 
    4433, 444, 4443, 446, 4567, 48080, 50005, 50080, 50100, 5060, 
    5100, 51234, 5280, 5443, 54430, 58086, 6014, 6065, 6066, 6068, 
    6070, 6071, 6072, 6120, 6443, 6868, 7003, 7083, 7443, 7899, 80, 
    8000, 8001, 8002, 8003, 8008, 8010, 8021, 8043, 8045, 8050, 8051, 
    8069, 8070, 8074, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 
    8088, 8089, 8090, 8091, 8092, 8096, 81, 8102, 8103, 8104, 8130, 
    8173, 8180, 8183, 8188, 82, 8200, 8241, 8441, 8443, 8444, 8445, 
    8446, 8447, 8456, 8551, 8699, 8740, 8750, 8751, 8765, 88, 8803, 
    8843, 888, 8880, 8881, 8885, 8888, 8889, 8890, 8900, 9000, 9001, 
    9002, 9003, 9004, 9010, 9020, 9080, 9081, 9083, 9087, 9090, 9092, 
    9094, 9099, 9102, 9104, 9105, 9200, 9258, 9292, 9295, 9443, 9943, 
    9998, 9999, 110, 111, 123, 135, 137, 139, 161, 177, 389, 427, 
    445, 465, 500, 515, 520, 523, 548, 623, 626, 636, 873, 902, 1099, 
    1433, 1434, 1521, 1604, 1645, 1701, 1883, 1900, 2049, 2181, 2375, 
    2379, 2425, 3128, 3306, 3389, 4730, 5222, 5351, 5353, 5432, 5555, 
    5601, 5672, 5683, 5900, 5938, 5984, 6000, 6379, 7001, 7077, 8545, 
    8686, 9042, 9100, 9418, 11211, 27017, 33848, 37777, 50000, 50070, 61616
]

class ProgressTracker:
    """进度跟踪器"""
    def __init__(self, total_tasks):
        self.total_tasks = total_tasks
        self.completed = 0
        self.start_time = datetime.now()
    
    def update(self):
        """更新进度"""
        self.completed += 1
        elapsed = (datetime.now() - self.start_time).total_seconds()
        percent = (self.completed / self.total_tasks) * 100
        
        # 计算剩余时间
        if self.completed > 0:
            remaining = (elapsed / self.completed) * (self.total_tasks - self.completed)
            remaining_str = f"{remaining:.1f}s"
        else:
            remaining_str = "N/A"
        
        print(f"\r[+] 进度: {percent:.1f}% | 已完成: {self.completed}/{self.total_tasks} | 用时: {elapsed:.1f}s | 剩余: {remaining_str}", end="", flush=True)

async def check_port(ip, port, sem, progress):
    """异步检查单个端口是否开放"""
    async with sem:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT_CONNECT)
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            progress.update()
            return (ip, port)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            progress.update()
            return None
        except Exception as e:
            progress.update()
            return None

async def scan_c_subnet(cidr):
    """C段扫描指定端口"""
    cidr_prefix = '_'.join(cidr.split('/')[0].split('.')[:3]) + '_0'
    output_file = f"{cidr_prefix}_selected_ports.txt"
    
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = []
    ip_list = list(IPNetwork(cidr))
    total_ips = len(ip_list)
    total_ports = len(TARGET_PORTS)
    total_tasks = total_ips * total_ports
    
    progress = ProgressTracker(total_tasks)
    
    print(f"[+] 开始扫描 {cidr}")
    print(f"[+] 总IP数: {total_ips}, 每个IP检查 {total_ports} 个端口")
    print(f"[+] 总任务数: {total_tasks}, 并发数: {CONCURRENCY}")
    print(f"[+] 开始时间: {progress.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    for ip_obj in ip_list:
        ip = str(ip_obj)
        for port in TARGET_PORTS:
            task = check_port(ip, port, sem, progress)
            tasks.append(task)
    
    open_ports = []
    for future in asyncio.as_completed(tasks):
        result = await future
        if result:
            open_ports.append(result)
            print(f"\n[+] 发现开放端口: {result[0]}:{result[1]}")
    
    # 保存结果
    with open(output_file, 'w') as f:
        for ip, port in open_ports:
            f.write(f"{ip}:{port}\n")
    
    print(f"\n[+] 扫描完成，发现 {len(open_ports)} 个开放端口")
    print(f"[+] 结果保存在: {output_file}")
    print(f"[+] 总耗时: {(datetime.now() - progress.start_time).total_seconds():.1f}秒")

async def check_http_service(ip, port, progress):
    """检查HTTP/HTTPS服务 (自动尝试两种协议)"""
    protocols = ['https', 'http']  # 先尝试HTTPS，再尝试HTTP
    session_timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
    
    async with aiohttp.ClientSession(timeout=session_timeout) as session:
        for protocol in protocols:
            url = f"{protocol}://{ip}:{port}"
            try:
                async with session.get(
                    url,
                    ssl=SSL_CONTEXT if protocol == 'https' else None
                ) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        soup = BeautifulSoup(text, 'lxml')
                        title = soup.title.string.strip() if soup.title else "No Title"
                        progress.update()
                        return (url, title, resp.status)
            except aiohttp.ClientError:
                continue
            except Exception as e:
                continue
    
    progress.update()
    return None

async def check_alive_services(input_file):
    """检查存活web服务"""
    if not os.path.exists(input_file):
        print(f"[-] 错误: 文件 {input_file} 不存在")
        return
    
    output_file = input_file.replace('.txt', '_alive.txt')
    
    with open(input_file) as f:
        entries = [line.strip() for line in f if line.strip()]
    
    print(f"[+] 开始检查 {len(entries)} 个服务的HTTP状态...")
    
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = []
    progress = ProgressTracker(len(entries))
    
    for entry in entries:
        try:
            ip, port = entry.split(':')
            task = check_http_service(ip, int(port), progress)
            tasks.append(task)
        except:
            progress.update()
            continue
    
    alive_services = []
    for future in asyncio.as_completed(tasks):
        result = await future
        if result:
            alive_services.append(result)
            print(f"\n[+] 存活服务: {result[0]} - {result[1]}")
    
    with open(output_file, 'w') as f:
        for url, title, status in alive_services:
            f.write(f"{url}|{title}|{status}\n")
    
    print(f"\n[+] 检查完成，发现 {len(alive_services)} 个存活服务")
    print(f"[+] 结果保存在: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="C段扫描工具 - 指定端口扫描")
    parser.add_argument("--scan", help="扫描C段 (示例: 192.168.1.0/24)")
    parser.add_argument("--check", help="检查存活服务 (输入扫描结果文件)")
    
    args = parser.parse_args()
    
    if args.scan:
        asyncio.run(scan_c_subnet(args.scan))
    elif args.check:
        asyncio.run(check_alive_services(args.check))
    else:
        parser.print_help()