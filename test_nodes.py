#!/usr/bin/env python3
"""
test_nodes.py - 两级节点连通性测试
阶段1: 协议握手检测（快速过滤）
阶段2: 启动xray做真实代理测试（多线程并发，v2rayN式）
"""
import base64, json, socket, sys, os, time, subprocess, tempfile, uuid as uuid_lib, re
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from pathlib import Path

TIMEOUT_STAGE1 = 3   # 阶段1超时
TIMEOUT_STAGE2 = 5   # 阶段2超时
MAX_WORKERS = 80     # 阶段1并发
XRAY_CONCUR = 15     # 阶段2并发xray实例数
TEST_URL = "https://www.gstatic.com/generate_204"

# ---- 阶段1：协议握手检测 ----

def tcp_test(host, port, timeout=TIMEOUT_STAGE1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        s.connect((addr, port))
        s.close()
        return True
    except: return False

def _proto_handshake(host, port, scheme):
    """各协议握手检测"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT_STAGE1)
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        s.connect((addr, port))
        
        if scheme in ('trojan',):
            s.send(b'test\r\n')
            try: s.recv(4, socket.MSG_DONTWAIT)
            except: pass
        elif scheme == 'https':
            s.send(b'CONNECT www.google.com:443 HTTP/1.1\r\n\r\n')
            try:
                r = s.recv(12)
                if b'HTTP' not in r: s.close(); return False
            except: s.close(); return False
        elif scheme == 'vmess':
            s.send(b'\x01' + b'\x00' * 32)
            try: s.recv(1, socket.MSG_DONTWAIT)
            except: pass
        
        s.close()
        return True
    except: return False

# ---- 节点URL解析 ----

def parse_node(node_url):
    """将节点URL解析为{scheme, host, port, params}"""
    try:
        scheme = node_url.split('://')[0].lower()
        parsed = urlparse(node_url)
        host = parsed.hostname
        port = parsed.port
        params = {}
        
        # 提取query参数
        if parsed.query:
            for k, v in parse_qs(parsed.query).items():
                params[k] = v[0] if v else ''
        
        # 处理vmess://uuid@host:port 格式
        if not host and '@' in parsed.netloc:
            parts = parsed.netloc.split('@')
            if len(parts) > 1:
                hp = parts[1].split(':')
                host = hp[0]
                if len(hp) > 1: port = int(hp[1].split('?')[0].split('#')[0])
        
        # ss://method:password@host:port
        if not host and scheme == 'ss':
            netloc = parsed.netloc
            if '@' in netloc:
                hp = netloc.split('@')[1].split(':')
                host = hp[0]
                if len(hp) > 1: port = int(hp[1].split('?')[0].split('#')[0])
        
        # vmess JSON格式: vmess://base64(JSON)
        if scheme == 'vmess' and parsed.netloc and not host:
            try:
                raw = parsed.netloc.split('#')[0]
                raw += '=' * (-len(raw) % 4)
                j = json.loads(base64.b64decode(raw))
                host = j.get('add', j.get('host'))
                port = int(j.get('port', 443))
                params = j
            except: pass
        
        if not host: return None
        
        # 默认端口
        port = port or {'vmess': 443, 'vless': 443, 'ss': 443, 'trojan': 443,
                       'ssr': 443, 'hysteria2': 443, 'hysteria': 443, 'tuic': 443,
                       'https': 443, 'socks': 1080}.get(scheme, 443)
        
        return {'scheme': scheme, 'host': host, 'port': int(port), 'params': params, 'raw': node_url}
    except: return None

# ---- 阶段2：xray真实代理测试 ----

def find_xray():
    """查找xray二进制"""
    for p in ['/usr/local/bin/xray', '/usr/bin/xray', './xray']:
        if os.path.isfile(p): return p
    # 下载xray
    import urllib.request
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    print("  下载Xray-core...")
    try:
        urllib.request.urlretrieve(url, '/tmp/xray.zip')
        import zipfile
        with zipfile.ZipFile('/tmp/xray.zip') as z:
            z.extract('xray', '/tmp/')
        os.chmod('/tmp/xray', 0o755)
        return '/tmp/xray'
    except:
        # 备选: GitHub proxy
        url2 = "https://ghproxy.cn/https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
        try:
            urllib.request.urlretrieve(url2, '/tmp/xray.zip')
            import zipfile
            with zipfile.ZipFile('/tmp/xray.zip') as z:
                z.extract('xray', '/tmp/')
            os.chmod('/tmp/xray', 0o755)
            return '/tmp/xray'
        except:
            return None

def build_xray_config(node, local_port):
    """从节点信息生成xray JSON配置"""
    s, host, port = node['scheme'], node['host'], node['port']
    p = node['params']
    
    outbound = {'protocol': s, 'settings': {}, 'streamSettings': {}}
    
    if s == 'vmess':
        uid = p.get('id', p.get('ps', str(uuid_lib.uuid4())))
        aid = int(p.get('aid', p.get('alterId', 0)))
        outbound['settings'] = {
            'vnext': [{'address': host, 'port': port,
                       'users': [{'id': uid, 'alterId': aid, 'security': 'auto'}]}]
        }
        # 传输配置
        net = p.get('net', p.get('network', 'tcp'))
        if net == 'ws':
            outbound['streamSettings'] = {
                'network': 'ws',
                'wsSettings': {'path': p.get('path', '/'), 'headers': {'Host': p.get('host', host)}}
            }
        elif net == 'tcp':
            outbound['streamSettings'] = {'network': 'tcp'}
            if p.get('type') == 'http':
                outbound['streamSettings']['tcpSettings'] = {'header': {'type': 'http'}}
        elif net == 'grpc':
            outbound['streamSettings'] = {'network': 'grpc', 'grpcSettings': {'serviceName': p.get('serviceName', '')}}
        elif net == 'kcp':
            outbound['streamSettings'] = {'network': 'kcp'}
        # TLS
        if p.get('tls', '') == 'tls' or p.get('security', '') == 'tls':
            outbound['streamSettings']['security'] = 'tls'
            outbound['streamSettings']['tlsSettings'] = {
                'serverName': p.get('sni', p.get('host', host)),
                'fingerprint': p.get('fp', 'chrome')}
    
    elif s == 'vless':
        uid = p.get('id', parsed_user(node['raw']))
        flow = p.get('flow', '')
        encryption = p.get('encryption', 'none')
        outbound['settings'] = {
            'vnext': [{'address': host, 'port': port,
                       'users': [{'id': uid, 'flow': flow, 'encryption': encryption}]}]
        }
        net = p.get('type', 'tcp')
        if net == 'ws':
            outbound['streamSettings'] = {'network': 'ws', 'wsSettings': {'path': p.get('path', '/')}}
        elif net == 'tcp':
            outbound['streamSettings'] = {'network': 'tcp'}
        else:
            outbound['streamSettings'] = {'network': net}
        if p.get('security', '') in ('tls', 'reality'):
            outbound['streamSettings']['security'] = p.get('security', 'tls')
            outbound['streamSettings']['tlsSettings'] = {
                'serverName': p.get('sni', host),
                'fingerprint': p.get('fp', 'chrome')}
            if p.get('security') == 'reality':
                outbound['streamSettings']['realitySettings'] = {
                    'publicKey': p.get('pbk', ''), 'shortId': p.get('sid', '')}
    
    elif s == 'trojan':
        pw = parsed_user(node['raw']) or p.get('password', '')
        outbound['settings'] = {
            'servers': [{'address': host, 'port': port, 'password': pw}]}
        outbound['streamSettings'] = {'network': 'tcp', 'security': 'tls',
            'tlsSettings': {'serverName': p.get('sni', host), 'fingerprint': p.get('fp', 'chrome')}}
    
    elif s == 'ss':
        mp = parsed_user(node['raw'])
        if mp and ':' in mp:
            method, password = mp.split(':', 1)
        else:
            method = p.get('method', 'chacha20-ietf-poly1305')
            password = p.get('password', '')
        outbound['settings'] = {
            'servers': [{'address': host, 'port': port, 'method': method, 'password': password}]}
        # ss的plugin
        if p.get('plugin'):
            outbound['settings']['servers'][0]['plugin'] = p['plugin']
            outbound['settings']['servers'][0]['pluginOpts'] = p.get('pluginOpts', '')
    
    elif s == 'hysteria2':
        # xray可能不支持hysteria2，改用TCP测试
        return None
    
    config = {
        'log': {'loglevel': 'none'},
        'inbounds': [{'port': local_port, 'listen': '127.0.0.1',
                      'protocol': 'socks', 'settings': {'udp': False}}],
        'outbounds': [outbound, {'protocol': 'freedom', 'tag': 'direct'}]
    }
    return config

def parsed_user(node_url):
    """提取节点URL中的UUID/密码"""
    try:
        # vless://uuid@ 或 trojan://password@ 或 ss://method:password@
        m = re.match(r'^[a-zA-Z]+://([^@]+)@', node_url)
        if m:
            user = m.group(1)
            # ss://格式可能是 method:password
            if ':' in user and node_url.startswith('ss://'):
                return user.split(':', 1)[1] if len(user.split(':', 1)) > 1 else user
            return user
    except: pass
    return ''

def xray_test(xray_bin, node, local_port):
    """用xray做真实代理测试"""
    config = build_xray_config(node, local_port)
    if not config:
        return False, 0
    
    cfg_path = f'/tmp/xray_test_{local_port}.json'
    with open(cfg_path, 'w') as f:
        json.dump(config, f)
    
    start = time.time()
    proc = subprocess.Popen([xray_bin, 'run', '-c', cfg_path], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # 等待xray启动（最多2秒）
        for _ in range(20):
            if proc.poll() is not None: break
            time.sleep(0.1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex(('127.0.0.1', local_port)) == 0:
                s.close()
                break
            s.close()
        
        if proc.poll() is not None:
            return False, 0
        
        # 通过代理请求测试URL
        result = subprocess.run(
            ['curl', '-x', f'socks5://127.0.0.1:{local_port}',
             '-o', '/dev/null', '-s', '-w', '%{time_total}', 
             '--connect-timeout', str(TIMEOUT_STAGE2),
             TEST_URL],
            capture_output=True, text=True, timeout=TIMEOUT_STAGE2+1)
        
        elapsed = (time.time() - start) * 1000
        
        if result.returncode == 0 and result.stdout.strip():
            latency = float(result.stdout.strip()) * 1000
            return True, latency
        
        return False, 0
    except: return False, 0
    finally:
        try: proc.kill(); proc.wait(2)
        except: pass
        try: os.remove(cfg_path)
        except: pass

# ---- 主流程 ----

def main():
    # 读取订阅
    try:
        with open('list.txt', 'r') as f:
            raw = f.read().strip()
    except:
        print("ERROR: 找不到 list.txt"); return 1
    
    raw += '=' * (-len(raw) % 4)
    try:
        decoded = base64.b64decode(raw).decode('utf-8', errors='replace')
    except:
        print("ERROR: Base64解码失败"); return 1
    
    nodes = [l.strip() for l in decoded.splitlines() if l.strip() and '://' in l]
    print(f"原始节点数: {len(nodes)}")
    
    # 解析节点
    parsed = []
    for n in nodes:
        p = parse_node(n)
        if p: parsed.append(p)
    
    print(f"解析成功: {len(parsed)}/{len(nodes)}")
    
    # ============ 阶段1：协议握手检测 ============
    print(f"\n=== 阶段1: 协议握手检测（并发{MAX_WORKERS}） ===")
    stage1_alive = []
    stage1_dead = 0
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        fut_map = {ex.submit(_proto_handshake, p['host'], p['port'], p['scheme']): p for p in parsed}
        for f in as_completed(fut_map):
            p = fut_map[f]
            try:
                if f.result(): stage1_alive.append(p)
                else: stage1_dead += 1
            except: stage1_dead += 1
    
    print(f"  存活: {len(stage1_alive)}  死亡: {stage1_dead}")
    
    # 没解析到的保留
    unparsed = [n for n in nodes if not any(p['raw'] == n for p in parsed)]
    
    # ============ 阶段2：xray真实代理测试 ============
    print(f"\n=== 阶段2: xray真实代理测试（并发{XRAY_CONCUR}） ===")
    xray_bin = find_xray()
    if not xray_bin:
        print("  ⚠️ 无法获取xray，跳过阶段2，直保留阶段1存活节点")
        result = [p['raw'] for p in stage1_alive] + unparsed
        # 写回
        encoded = base64.b64encode('\n'.join(result).encode()).decode()
        with open('list.txt', 'w') as f: f.write(encoded)
        print(f"  最终节点数: {len(result)}")
        return 0
    
    print(f"  使用xray: {xray_bin}")
    stage2_results = {}  # raw_url -> (ok, latency_ms)
    xray_tested = 0
    
    def _xray_test_wrapper(p, port):
        ok, ms = xray_test(xray_bin, p, port)
        return p['raw'], ok, ms
    
    port_base = 10800
    with ThreadPoolExecutor(max_workers=XRAY_CONCUR) as ex:
        fut_map = {}
        for i, p in enumerate(stage1_alive):
            port = port_base + (i % 100) * 10 + 1
            # 确保端口不冲突
            while port in [f[1] for f in fut_map.values()]:
                port += 1
            fut = ex.submit(_xray_test_wrapper, p, port)
            fut_map[fut] = (p['raw'], port)
        
        for f in as_completed(fut_map):
            raw_url, port = fut_map[f]
            xray_tested += 1
            try:
                url, ok, ms = f.result(timeout=TIMEOUT_STAGE2+5)
                stage2_results[url] = (ok, ms)
                status = f"✓ {ms:.0f}ms" if ok else "✗"
                print(f"  [{xray_tested}/{len(stage1_alive)}] {status}  {url[:60]}...")
            except Exception as e:
                stage2_results[raw_url] = (False, 0)
                print(f"  [{xray_tested}/{len(stage1_alive)}] ✗ timeout  {raw_url[:60]}...")
    
    # 统计
    stage2_alive = [u for u, (ok, _) in stage2_results.items() if ok]
    stage2_dead = [u for u, (ok, _) in stage2_results.items() if not ok]
    
    # 带延迟信息的节点列表（按延迟排序）
    alive_with_latency = [(u, ms) for u, (ok, ms) in stage2_results.items() if ok]
    alive_with_latency.sort(key=lambda x: x[1])
    
    print(f"\n  xray测试结果: ")
    print(f"    存活: {len(alive_with_latency)}")
    print(f"    死亡: {len(stage2_dead)}")
    
    if alive_with_latency:
        print(f"    最低延迟: {alive_with_latency[0][1]:.0f}ms")
        print(f"    最高延迟: {alive_with_latency[-1][1]:.0f}ms")
        print(f"    延迟<200ms: {len([x for x in alive_with_latency if x[1] < 200])}")
        print(f"    延迟200-500ms: {len([x for x in alive_with_latency if 200 <= x[1] < 500])}")
        print(f"    延迟500ms+: {len([x for x in alive_with_latency if x[1] >= 500])}")
    
    # 最终列表：存活节点 + 未解析节点
    result = [u for u, _ in alive_with_latency] + unparsed
    
    # 同时生成CSV（带延迟信息）
    csv_lines = ["url,protocol,host,port,alive,latency_ms"]
    for u, (ok, ms) in stage2_results.items():
        p = parse_node(u)
        if p:
            csv_lines.append(f'{u},{p["scheme"]},{p["host"]},{p["port"]},{ok},{ms:.0f}')
    
    # 写回
    encoded = base64.b64encode('\n'.join(result).encode()).decode()
    with open('list.txt', 'w') as f: f.write(encoded)
    with open('list_result.csv', 'w') as f: f.write('\n'.join(csv_lines))
    
    print(f"\n  最终节点数: {len(result)}")
    print(f"  详情已保存至 list_result.csv")
    return 0

if __name__ == '__main__':
    sys.exit(main())