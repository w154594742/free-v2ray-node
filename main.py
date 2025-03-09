import requests
import base64
import yaml
import json
import socket
import socks
import time
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# 订阅链接列表
links = [
    "https://ghproxy.net/https://raw.githubusercontent.com/firefoxmmx2/v2rayshare_subcription/main/subscription/clash_sub.yaml",
    "https://ghproxy.net/https://raw.githubusercontent.com/Roywaller/clash_subscription/refs/heads/main/clash_subscription.txt",
    "https://www.freeclashnode.com/uploads/{Y}/{m}/0-{Ymd}.yaml",
    "https://ghproxy.net/https://raw.githubusercontent.com/aiboboxx/clashfree/refs/heads/main/clash.yml",
    "https://ghproxy.net/https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/LogInfo.txt",
    'https://ghproxy.net/https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2',
    'https://ghproxy.net/https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt',
    'https://ghproxy.net/https://raw.githubusercontent.com/vpnmarket/sub/refs/heads/main/hiddify1.txt',
]

# 支持的协议类型列表
SUPPORTED_PROTOCOLS = [
    'vmess://', 
    'trojan://', 
    'vless://', 
    'ss://', 
    'ssr://', 
    'http://', 
    'https://', 
    'socks://', 
    'socks5://',
    'hysteria://',
    'wireguard://'
]

def format_current_date(url):
    """替换URL中的日期占位符"""
    now = datetime.now()
    return url.format(
        Y=now.strftime('%Y'),
        m=now.strftime('%m'),
        d=now.strftime('%d'),
        Ymd=now.strftime('%Y%m%d')
    )

def fetch_content(url):
    """获取订阅内容"""
    try:
        url = format_current_date(url)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
        }
        response = requests.get(url, headers=headers, timeout=30, stream=True)
        response.raise_for_status()
        
        # 检查Content-Type，如果是二进制类型，直接读取内容
        content_type = response.headers.get('Content-Type', '')
        if 'application/octet-stream' in content_type or 'application/x-yaml' in content_type:
            content = response.content.decode('utf-8')
        else:
            content = response.text
            
        return content
    except Exception as e:
        print(f"Error fetching {url}: {str(e)}")
        return None

def parse_clash_yaml(content):
    """解析Clash配置文件"""
    try:
        data = yaml.safe_load(content)
        if not data or 'proxies' not in data:
            return []
        return data['proxies']
    except Exception as e:
        print(f"Error parsing Clash YAML: {str(e)}")
        return []

def parse_v2ray_base64(content):
    """解析V2Ray Base64编码的配置"""
    try:
        # 处理多行base64
        content = content.strip().replace('\n', '').replace('\r', '')
        # 尝试修复可能的编码问题
        try:
            if isinstance(content, bytes):
                content = content.decode('utf-8')
            # 确保内容是ASCII兼容的
            content = content.encode('ascii', 'ignore').decode('ascii')
        except UnicodeError:
            print("Error: Invalid encoding in base64 content")
            return []
            
        try:
            decoded = base64.b64decode(content + '=' * (-len(content) % 4))
            decoded_str = decoded.decode('utf-8', 'ignore')
        except Exception as e:
            print(f"Error decoding base64 content: {str(e)}")
            return []
            
        nodes = []
        for line in decoded_str.split('\n'):
            if line.startswith('vmess://') or line.startswith('trojan://'):
                node = parse_v2ray_uri(line)
                if node:
                    nodes.append(node)
        return nodes
    except Exception as e:
        print(f"Error parsing V2Ray base64: {str(e)}")
        return []

def parse_v2ray_uri(uri):
    """解析V2Ray URI格式的配置"""
    try:
        # 处理vmess协议
        if uri.startswith('vmess://'):
            b64_config = uri.replace('vmess://', '')
            # 确保base64正确填充
            b64_config = b64_config + '=' * (-len(b64_config) % 4)
            try:
                config = json.loads(base64.b64decode(b64_config).decode())
                return {
                    'type': 'vmess',
                    'name': config.get('ps', 'Unknown'),
                    'server': config.get('add', ''),
                    'port': int(config.get('port', 0)),
                    'uuid': config.get('id', ''),
                    'alterId': int(config.get('aid', 0)),
                    'cipher': config.get('type', 'auto'),
                    'tls': config.get('tls', '') == 'tls',
                    'network': config.get('net', 'tcp')
                }
            except json.JSONDecodeError:
                # 某些情况下vmess可能使用非标准格式
                print(f"Non-standard vmess format: {uri}")
                return None
                
        # 处理trojan协议
        elif uri.startswith('trojan://'):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'trojan',
                'name': query.get('sni', [query.get('peer', ['Unknown'])[0]])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or 443,
                'password': parsed.username or ''
            }
            
        # 处理vless协议
        elif uri.startswith('vless://'):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'vless',
                'name': query.get('remarks', [query.get('sni', ['Unknown'])[0]])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or 443,
                'uuid': parsed.username or '',
                'tls': query.get('security', [''])[0] == 'tls',
                'flow': query.get('flow', [''])[0],
                'network': query.get('type', ['tcp'])[0]
            }
            
        # 处理shadowsocks协议
        elif uri.startswith('ss://'):
            if '@' in uri:
                # 处理 ss://method:password@host:port
                parsed = urlparse(uri)
                server = parsed.hostname
                port = parsed.port
                
                # 提取方法和密码
                userinfo = parsed.username
                if userinfo:
                    try:
                        # 有些实现可能会对userinfo进行base64编码
                        decoded = base64.b64decode(userinfo + '=' * (-len(userinfo) % 4)).decode()
                        if ':' in decoded:
                            method, password = decoded.split(':', 1)
                        else:
                            method, password = 'aes-256-gcm', userinfo
                    except:
                        # 如果不是base64编码，可能是明文
                        if ':' in userinfo:
                            method, password = userinfo.split(':', 1)
                        else:
                            method, password = 'aes-256-gcm', userinfo
                else:
                    method, password = 'aes-256-gcm', ''
                
                # 提取节点名称
                query = parse_qs(parsed.query)
                name = query.get('remarks', ['Unknown'])[0]
                
                return {
                    'type': 'ss',
                    'name': name,
                    'server': server or '',
                    'port': port or 443,
                    'cipher': method,
                    'password': password
                }
            else:
                # 处理 ss://BASE64(method:password@host:port)
                b64_config = uri.replace('ss://', '')
                try:
                    # 确保base64正确填充
                    b64_config = b64_config.split('#')[0]
                    b64_config = b64_config + '=' * (-len(b64_config) % 4)
                    
                    config_str = base64.b64decode(b64_config).decode()
                    # 提取方法和密码
                    if '@' in config_str:
                        method_pwd, server_port = config_str.rsplit('@', 1)
                        method, password = method_pwd.split(':', 1)
                        server, port = server_port.rsplit(':', 1)
                        
                        # 提取节点名称 (可能在#后面)
                        name = 'Unknown'
                        if '#' in uri:
                            name = unquote(uri.split('#', 1)[1])
                            
                        return {
                            'type': 'ss',
                            'name': name,
                            'server': server,
                            'port': int(port),
                            'cipher': method,
                            'password': password
                        }
                except:
                    print(f"Invalid ss URI format: {uri}")
                    return None
                
        # 处理shadowsocksr协议
        elif uri.startswith('ssr://'):
            b64_config = uri.replace('ssr://', '')
            try:
                # 确保base64正确填充
                b64_config = b64_config + '=' * (-len(b64_config) % 4)
                config_str = base64.b64decode(b64_config).decode()
                
                # SSR格式: server:port:protocol:method:obfs:base64pass/?obfsparam=base64param&protoparam=base64param&remarks=base64remarks
                parts = config_str.split(':')
                if len(parts) >= 6:
                    server = parts[0]
                    port = parts[1]
                    protocol = parts[2]
                    method = parts[3]
                    obfs = parts[4]
                    
                    # 处理剩余参数
                    password_and_params = parts[5].split('/?', 1)
                    password_b64 = password_and_params[0]
                    password = base64.b64decode(password_b64 + '=' * (-len(password_b64) % 4)).decode()
                    
                    # 提取参数
                    name = 'Unknown'
                    if len(password_and_params) > 1 and 'remarks=' in password_and_params[1]:
                        remarks_b64 = password_and_params[1].split('remarks=', 1)[1].split('&', 1)[0]
                        try:
                            name = base64.b64decode(remarks_b64 + '=' * (-len(remarks_b64) % 4)).decode()
                        except:
                            pass
                    
                    return {
                        'type': 'ssr',
                        'name': name,
                        'server': server,
                        'port': int(port),
                        'protocol': protocol,
                        'cipher': method,
                        'obfs': obfs,
                        'password': password
                    }
            except Exception as e:
                print(f"Error parsing SSR URI: {str(e)}")
                return None
                
        # 处理HTTP/HTTPS协议
        elif uri.startswith(('http://', 'https://')):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'http' if uri.startswith('http://') else 'https',
                'name': query.get('remarks', ['Unknown'])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or (80 if uri.startswith('http://') else 443),
                'username': parsed.username or '',
                'password': parsed.password or ''
            }
            
        # 处理SOCKS协议
        elif uri.startswith(('socks://', 'socks5://')):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'socks',
                'name': query.get('remarks', ['Unknown'])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or 1080,
                'username': parsed.username or '',
                'password': parsed.password or ''
            }
            
        # 处理hysteria协议
        elif uri.startswith('hysteria://'):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'hysteria',
                'name': query.get('peer', ['Unknown'])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or 443,
                'protocol': query.get('protocol', [''])[0],
                'auth': parsed.username or query.get('auth', [''])[0]
            }
            
        # 处理wireguard协议
        elif uri.startswith('wireguard://'):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'wireguard',
                'name': query.get('remarks', ['Unknown'])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or 51820,
                'private_key': query.get('privateKey', [''])[0],
                'public_key': query.get('publicKey', [''])[0],
                'allowed_ips': query.get('allowedIPs', ['0.0.0.0/0'])[0]
            }

    except Exception as e:
        print(f"Error parsing URI: {str(e)}")
        return None

def extract_nodes(content):
    """级联提取节点，按照Base64 -> YAML -> 正则表达式的顺序尝试"""
    if not content:
        return []
    
    nodes = []
    methods_tried = []
    
    # 1. 尝试Base64解码提取
    try:
        # 处理多行base64，移除所有空白字符和特殊字符
        cleaned_content = re.sub(r'[\s\n\r\t]+', '', content)
        cleaned_content = re.sub(r'[^A-Za-z0-9+/=]', '', cleaned_content)
        
        # 确保base64字符串长度是4的倍数
        padding_length = len(cleaned_content) % 4
        if padding_length:
            cleaned_content += '=' * (4 - padding_length)
        
        # 尝试base64解码
        try:
            decoded_bytes = base64.b64decode(cleaned_content)
            decoded_str = decoded_bytes.decode('utf-8', 'ignore')
            
            # 检查解码后的内容是否包含任何支持的协议节点
            if any(protocol in decoded_str for protocol in SUPPORTED_PROTOCOLS):
                print("使用Base64解码提取节点")
                methods_tried.append("Base64")
                for line in decoded_str.split('\n'):
                    line = line.strip()
                    if any(line.startswith(protocol) for protocol in SUPPORTED_PROTOCOLS):
                        node = parse_v2ray_uri(line)
                        if node:
                            nodes.append(node)
        except Exception as e:
            print(f"Base64解码失败或未找到节点")
    except Exception as e:
        print(f"Base64预处理失败: {str(e)}")
    
    # 如果已经提取到节点，直接返回
    if nodes:
        print(f"通过{', '.join(methods_tried)}方法成功提取到{len(nodes)}个节点")
        return nodes
    
    # 2. 尝试解析YAML格式
    try:
        # 移除HTML标签和特殊标记
        cleaned_content = re.sub(r'<[^>]+>|!&lt;str&gt;', '', content)
        
        # 判断是否是YAML格式
        if cleaned_content.strip().startswith('proxies:') or any(cleaned_content.strip().startswith(prefix) for prefix in ['port:', 'socks-port:', 'mixed-port:']):
            print("尝试解析YAML格式内容")
            methods_tried.append("YAML")
            yaml_nodes = parse_clash_yaml(cleaned_content)
            if yaml_nodes:
                nodes.extend(yaml_nodes)
    except Exception as e:
        print(f"YAML解析失败: {str(e)}")
    
    # 如果已经提取到节点，直接返回
    if nodes:
        print(f"通过{', '.join(methods_tried)}方法成功提取到{len(nodes)}个节点")
        return nodes
    
    # 3. 尝试使用正则表达式直接提取
    try:
        print("尝试使用正则表达式直接提取节点")
        methods_tried.append("正则表达式")
        
        # 为每种支持的协议定义正则表达式并提取
        for protocol in SUPPORTED_PROTOCOLS:
            if protocol == 'vmess://':
                # vmess通常是一个base64编码的字符串
                found_nodes = re.findall(r'vmess://[A-Za-z0-9+/=]+', content)
            elif protocol == 'hysteria://' or protocol == 'wireguard://':
                # 这些协议可能有特殊格式，需要特别处理
                found_nodes = re.findall(f'{protocol}[^"\'<>\\s]+', content)
            else:
                # 对于其他协议，采用通用正则表达式
                found_nodes = re.findall(f'{protocol}[^"\'<>\\s]+', content)
            
            for uri in found_nodes:
                node = parse_v2ray_uri(uri)
                if node:
                    nodes.append(node)
    except Exception as e:
        print(f"正则表达式提取失败: {str(e)}")
    
    print(f"通过{', '.join(methods_tried)}方法成功提取到{len(nodes)}个节点")
    return nodes

def test_latency(node):
    """测试节点延迟"""
    try:
        start_time = time.time()
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # 改进延迟测试，支持所有类型的节点
        success = False
        try:
            sock.connect((node['server'], node['port']))
            success = True
        except Exception as e:
            return -1
            
        if not success:
            return -1
            
        latency = int((time.time() - start_time) * 1000)
        sock.close()
        return latency
    except Exception as e:
        print(f"测试节点 {node['name']} 延迟时出错: {str(e)}")
        return -1

def process_node(node):
    """处理单个节点，添加延迟信息"""
    if not node or 'name' not in node or 'server' not in node:
        return None

    latency = test_latency(node)
    
    # 过滤掉延迟为0ms或连接失败的节点
    if latency <= 0:
        return None
    
    # 更新节点名称，添加延迟信息
    node['name'] = f"{node['name']} [{latency}ms]"
    print(f"节点: {node['name']} ，延迟: {latency}ms")
    return node

def remove_duplicates(nodes):
    """去除重复节点"""
    unique_nodes = {}
    for node in nodes:
        try:
            key = f"{node['server']}:{node['port']}"
            if key not in unique_nodes:
                unique_nodes[key] = node
        except Exception as e:
            print(f"处理节点 {node['name']} 时出错: {str(e)}")
    return list(unique_nodes.values())

def node_to_v2ray_uri(node):
    """将节点信息转换为V2Ray URI格式"""
    if node['type'] == 'vmess':
        config = {
            'v': '2',
            'ps': node['name'],
            'add': node['server'],
            'port': str(node['port']),
            'id': node['uuid'],
            'aid': str(node['alterId']),
            'net': node.get('network', 'tcp'),
            'type': node.get('type', 'none'),
            'tls': 'tls' if node.get('tls', False) else ''
        }
        return f"vmess://{base64.b64encode(json.dumps(config).encode()).decode()}"
    elif node['type'] == 'trojan':
        return f"trojan://{node['password']}@{node['server']}:{node['port']}?sni={node['name']}"
    elif node['type'] == 'vless':
        # 构建vless uri
        query_parts = []
        if node.get('tls'):
            query_parts.append('security=tls')
        if node.get('flow'):
            query_parts.append(f"flow={node['flow']}")
        if node.get('network'):
            query_parts.append(f"type={node['network']}")
        query_string = '&'.join(query_parts)
        return f"vless://{node['uuid']}@{node['server']}:{node['port']}?{query_string}&remarks={node['name']}"
    elif node['type'] == 'ss':
        # 构建ss uri
        userinfo = f"{node['cipher']}:{node['password']}"
        b64_userinfo = base64.b64encode(userinfo.encode()).decode()
        return f"ss://{b64_userinfo}@{node['server']}:{node['port']}#{node['name']}"
    elif node['type'] == 'ssr':
        # 构建ssr uri
        password_b64 = base64.b64encode(node['password'].encode()).decode()
        name_b64 = base64.b64encode(node['name'].encode()).decode()
        ssr_str = f"{node['server']}:{node['port']}:{node['protocol']}:{node['cipher']}:{node['obfs']}:{password_b64}/?remarks={name_b64}"
        return f"ssr://{base64.b64encode(ssr_str.encode()).decode()}"
    elif node['type'] in ['http', 'https']:
        # 构建http/https uri
        proto = 'http' if node['type'] == 'http' else 'https'
        auth = f"{node['username']}:{node['password']}@" if node['username'] else ""
        return f"{proto}://{auth}{node['server']}:{node['port']}?remarks={node['name']}"
    elif node['type'] == 'socks':
        # 构建socks uri
        auth = f"{node['username']}:{node['password']}@" if node['username'] else ""
        return f"socks://{auth}{node['server']}:{node['port']}?remarks={node['name']}"
    elif node['type'] == 'hysteria':
        # 构建hysteria uri
        auth = f"{node['auth']}@" if node.get('auth') else ""
        protocol_part = f"?protocol={node['protocol']}" if node.get('protocol') else ""
        return f"hysteria://{auth}{node['server']}:{node['port']}{protocol_part}&peer={node['name']}"
    elif node['type'] == 'wireguard':
        # 构建wireguard uri
        query_parts = []
        if node.get('private_key'):
            query_parts.append(f"privateKey={node['private_key']}")
        if node.get('public_key'):
            query_parts.append(f"publicKey={node['public_key']}")
        if node.get('allowed_ips'):
            query_parts.append(f"allowedIPs={node['allowed_ips']}")
        query_string = '&'.join(query_parts)
        return f"wireguard://{node['server']}:{node['port']}?{query_string}&remarks={node['name']}"
    return None

def main():
    all_nodes = []
    
    # 获取并解析所有订阅
    print("\n开始获取节点信息...")
    for link in links:
        print(f"\n正在处理订阅链接: {link}")
        content = fetch_content(link)
        if not content:
            print("获取失败，跳过该链接")
            continue
        
        # 使用新的级联提取函数
        nodes = extract_nodes(content)
        print(f"成功提取 {len(nodes)} 个节点")
        all_nodes.extend(nodes)
    
    # 使用线程池并发测试节点延迟
    print(f"\n开始测试节点延迟，共 {len(all_nodes)} 个节点...")
    valid_nodes = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_node = {executor.submit(process_node, node): node for node in all_nodes}
        for future in as_completed(future_to_node):
            processed_node = future.result()
            if processed_node:
                valid_nodes.append(processed_node)
    
    print(f"\n测试完成，有效节点数量: {len(valid_nodes)}")
    
    # 节点去重
    unique_nodes = remove_duplicates(valid_nodes)
    print(f"\n去重后剩余 {len(unique_nodes)} 个节点")
    
    # 转换为V2Ray URI格式并保存
    valid_uri_count = 0
    with open('v2ray.txt', 'w', encoding='utf-8') as f:
        for node in unique_nodes:
            uri = node_to_v2ray_uri(node)
            if uri:
                f.write(f"{uri}\n")
                valid_uri_count += 1
    
    print(f"\n已将 {valid_uri_count} 个有效节点保存到 v2ray.txt 文件")

if __name__ == '__main__':
    main()