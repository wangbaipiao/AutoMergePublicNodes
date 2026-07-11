#!/usr/bin/env python3
"""
test_nodes.py - 对抓取到的节点做连通性测试
过滤掉服务器端口不可达的节点
"""
import base64
import socket
import sys
import re
import time
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 3  # 连接超时（秒）
MAX_WORKERS = 50  # 并发数

def test_tcp(host, port):
    """TCP连接测试"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        # 解析域名（支持IPv4和IPv6）
        try:
            addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        except:
            return False
        sock.connect((addr, port))
        sock.close()
        return True
    except:
        return False

def extract_server(node_url):
    """从节点URL中提取server:port"""
    try:
        # 处理 vmess:// vless:// ss:// trojan:// hysteria2:// tuic://
        parsed = urlparse(node_url)
        host = parsed.hostname
        port = parsed.port
        
        # 有些节点格式特殊
        if not host and '@' in parsed.netloc:
            # vmess://uuid@host:port 格式
            parts = parsed.netloc.split('@')
            if len(parts) > 1:
                host_port = parts[1].split(':')
                host = host_port[0]
                if len(host_port) > 1:
                    port = int(host_port[1].split('?')[0].split('#')[0])
        
        # 处理 ss:// 格式 (base64编码的host:port)
        if not host and parsed.scheme == 'ss':
            # ss://method:password@host:port
            netloc = parsed.netloc
            if '@' in netloc:
                host_port = netloc.split('@')[1].split(':')
                host = host_port[0]
                if len(host_port) > 1:
                    port = int(host_port[1].split('?')[0].split('#')[0])
        
        if host and port:
            return host, port
        return None
    except:
        return None

def main():
    # 读取list.txt
    try:
        with open('list.txt', 'r') as f:
            raw = f.read().strip()
    except:
        print("ERROR: 找不到 list.txt")
        return 1
    
    # 解码base64
    try:
        raw += '=' * (-len(raw) % 4)
        decoded = base64.b64decode(raw).decode('utf-8', errors='replace')
    except:
        print("ERROR: Base64解码失败")
        return 1
    
    nodes = [line.strip() for line in decoded.splitlines() if line.strip() and '://' in line]
    print(f"原始节点数: {len(nodes)}")
    
    # 提取server:port
    node_info = []
    for node in nodes:
        info = extract_server(node)
        if info:
            node_info.append((node, info[0], info[1]))
    
    print(f"可解析server:port的节点: {len(node_info)}")
    
    # 并发测试
    alive = []
    dead = 0
    tested = 0
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        fut_to_node = {
            executor.submit(test_tcp, host, port): (node, host, port)
            for node, host, port in node_info
        }
        
        for future in as_completed(fut_to_node):
            node, host, port = fut_to_node[future]
            tested += 1
            try:
                if future.result():
                    alive.append(node)
                else:
                    dead += 1
            except:
                dead += 1
            
            if tested % 100 == 0:
                print(f"  进度: {tested}/{len(node_info)} 存活: {len(alive)} 死亡: {dead}")
    
    # 未测试的节点（无法提取server:port的）保留
    untested = [n for n in nodes if n not in [x[0] for x in node_info]]
    
    result = alive + untested
    print(f"\n=== 测试结果 ===")
    print(f"  存活: {len(alive)}")
    print(f"  死亡: {dead}")
    print(f"  未测试(保留): {len(untested)}")
    print(f"  最终节点数: {len(result)}")
    
    # 写回list.txt
    encoded = base64.b64encode('\n'.join(result).encode()).decode()
    with open('list.txt', 'w') as f:
        f.write(encoded)
    
    print(f"  已写回 list.txt")
    return 0

if __name__ == '__main__':
    sys.exit(main())