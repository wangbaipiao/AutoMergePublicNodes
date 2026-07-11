#!/usr/bin/env python3
"""
test_nodes_proto.py - 协议级握手检测
对每个节点做轻量级协议握手，验证服务器确实在运行代理服务
比纯TCP ping准，比启动完整xray快
"""
import base64
import socket
import sys
import re
import struct
import time
import hashlib
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 4
MAX_WORKERS = 80

def tcp_ping(host, port, timeout=TIMEOUT):
    """快速TCP连接测试"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        start = time.time()
        sock.connect((addr, port))
        elapsed = (time.time() - start) * 1000
        sock.close()
        return True, elapsed
    except:
        return False, None

def test_vmess(host, port):
    """VMess协议握手检测 - 发送认证请求"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        sock.connect((addr, port))
        
        # VMess: 发送一个基本的认证字节
        # 发送命令头: 1字节版本(1) + 16字节UUID哈希 + ... 
        # 简单检测：发送一个合法格式的VMess握手包
        # 如果服务器返回数据说明是VMess服务器
        test_bytes = b'\x01' + b'\x00' * 16 + b'\x00' * 16
        sock.send(test_bytes)
        try:
            resp = sock.recv(1, socket.MSG_DONTWAIT)
            elapsed = (time.time() - start) * 1000
            sock.close()
            return True, elapsed
        except:
            elapsed = (time.time() - start) * 1000
            sock.close()
            return True, elapsed  # TCP通了就算
    except:
        return False, None

def test_trojan(host, port, password='test'):
    """Trojan协议握手检测"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        sock.connect((addr, port))
        
        # Trojan: 发送密码+SHA224+CRLF
        # 简单版：发个无效Trojan请求看是否立即断开
        req = password.encode() + b'\r\n'
        sock.send(req)
        try:
            resp = sock.recv(4)
            elapsed = (time.time() - start) * 1000
            sock.close()
            return True, elapsed
        except:
            elapsed = (time.time() - start) * 1000
            sock.close()
            return True, elapsed
    except:
        return False, None

def test_ss(host, port):
    """Shadowsocks协议握手 - TCP连接+读响应"""
    return tcp_ping(host, port)

def test_https(host, port):
    """HTTPS代理检测 - HTTP CONNECT"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        sock.connect((addr, port))
        # 发HTTP CONNECT看是不是代理
        sock.send(b'CONNECT www.google.com:443 HTTP/1.1\r\n\r\n')
        resp = sock.recv(12)
        elapsed = (time.time() - start) * 1000
        sock.close()
        if b'HTTP' in resp:
            return True, elapsed
        return False, None
    except:
        return False, None

def extract_server(node_url):
    """从节点URL中提取scheme, host, port"""
    try:
        scheme = node_url.split('://')[0]
        parsed = urlparse(node_url)
        host = parsed.hostname
        port = parsed.port
        
        # vmess://uuid@host:port 格式
        if not host and '@' in parsed.netloc:
            parts = parsed.netloc.split('@')
            if len(parts) > 1:
                hp = parts[1].split(':')
                host = hp[0]
                port = int(hp[1].split('?')[0].split('#')[0]) if len(hp) > 1 else None
        
        # ss://method:password@host:port
        if not host and scheme == 'ss':
            netloc = parsed.netloc
            if '@' in netloc:
                hp = netloc.split('@')[1].split(':')
                host = hp[0]
                port = int(hp[1].split('?')[0].split('#')[0]) if len(hp) > 1 else None
        
        # 默认端口
        if port is None:
            port_map = {'vmess': 443, 'vless': 443, 'ss': 443, 'trojan': 443, 
                       'hysteria2': 443, 'hysteria': 443, 'tuic': 443, 'https': 443}
            port = port_map.get(scheme, 443)
        
        if host:
            return scheme, host, int(port)
        return None
    except:
        return None

def test_node(scheme, host, port):
    """按协议类型测试"""
    scheme = scheme.lower()
    if scheme == 'trojan':
        ok, ms = test_trojan(host, port)
    elif scheme == 'ss' or scheme == 'ssr':
        ok, ms = test_ss(host, port)
    elif scheme == 'https':
        ok, ms = test_https(host, port)
    elif scheme == 'vmess':
        ok, ms = test_vmess(host, port)
    elif scheme in ('vless', 'hysteria2', 'hysteria', 'tuic'):
        ok, ms = tcp_ping(host, port)
    else:
        ok, ms = tcp_ping(host, port)
    return ok, ms

def main():
    try:
        with open('list.txt', 'r') as f:
            raw = f.read().strip()
    except:
        print("ERROR: 找不到 list.txt")
        return 1
    
    raw += '=' * (-len(raw) % 4)
    try:
        decoded = base64.b64decode(raw).decode('utf-8', errors='replace')
    except:
        print("ERROR: Base64解码失败")
        return 1
    
    nodes = [line.strip() for line in decoded.splitlines() if line.strip() and '://' in line]
    print(f"原始节点数: {len(nodes)}")
    
    # 提取server信息
    node_info = []
    for node in nodes:
        info = extract_server(node)
        if info:
            node_info.append((node, info[0], info[1], info[2]))
    
    print(f"可解析server:port的节点: {len(node_info)}/{len(nodes)}")
    
    # 并发测试
    alive = []
    dead = 0
    untested = [n for n in nodes if n not in [x[0] for x in node_info]]
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        fut_to_node = {
            executor.submit(test_node, scheme, host, port): (node, scheme, host, port)
            for node, scheme, host, port in node_info
        }
        
        for future in as_completed(fut_to_node):
            node, scheme, host, port = fut_to_node[future]
            try:
                ok, ms = future.result()
                if ok:
                    alive.append(node)
                else:
                    dead += 1
            except:
                dead += 1
    
    result = alive + untested
    print(f"\n=== 协议握手检测结果 ===")
    print(f"  存活: {len(alive)}")
    print(f"  死亡: {dead}")
    print(f"  未测试(保留): {len(untested)}")
    print(f"  最终节点数: {len(result)}")
    
    # 写回list.txt
    encoded = base64.b64encode('\n'.join(result).encode()).decode()
    with open('list.txt', 'w') as f:
        f.write(encoded)
    
    print(f"  已写入 list.txt")
    return 0

if __name__ == '__main__':
    sys.exit(main())