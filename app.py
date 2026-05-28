#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
import subprocess
import json
import platform
import time
import shutil
import signal
from dataclasses import dataclass
from aiohttp import web

os.environ.setdefault('GRPC_VERBOSITY', 'ERROR')
os.environ.setdefault('GLOG_minloglevel', '2')

try:
    import fcntl
    import pty
    import termios
except ImportError:
    fcntl = None
    pty = None
    termios = None

try:
    import grpc
    import psutil
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
except ImportError as e:
    grpc = None
    psutil = None
    descriptor_pb2 = None
    descriptor_pool = None
    message_factory = None
    NEZHA_IMPORT_ERROR = e
else:
    NEZHA_IMPORT_ERROR = None

# 环境变量
UUID = os.environ.get('UUID', '7bd180e8-1142-4387-93f5-03e8d750a896')   # 节点UUID
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')    # 哪吒v0填写格式: nezha.xxx.com  哪吒v1填写格式: nezha.xxx.com:8008
NEZHA_PORT = os.environ.get('NEZHA_PORT', '')        # 哪吒v1请留空，哪吒v0 agent端口
NEZHA_KEY = os.environ.get('NEZHA_KEY', '')          # 哪吒v0或v1密钥，哪吒面板后台命令里获取
DOMAIN = os.environ.get('DOMAIN', '')                # 项目分配的域名或反代后的域名,不包含https://前缀,例如: domain.xxx.com
SUB_PATH = os.environ.get('SUB_PATH', 'sub')         # 节点订阅token
NAME = os.environ.get('NAME', '')                    # 节点名称
WSPATH = os.environ.get('WSPATH', UUID[:8])          # 节点路径
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)  # http和ws端口，默认自动优先获取容器分配的端口
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true' # 自动访问保活,默认关闭,true开启,false关闭,需同时填写DOMAIN变量
DEBUG = os.environ.get('DEBUG', '').lower() == 'true' # 保持默认,调试使用,true开启调试

# 全局变量
CurrentDomain = DOMAIN
CurrentPort = 443
Tls = 'tls'
ISP = ''

# dns server
DNS_SERVERS = ['8.8.4.4', '1.1.1.1']
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
]

# 日志级别
log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 禁用访问,连接等日志
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)
logging.getLogger('aiohttp.websocket').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None

def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    return any(host_lower == blocked or host_lower.endswith('.' + blocked) 
              for blocked in BLOCKED_DOMAINS)

async def get_isp():
    global ISP
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ip.sb/geoip', 
                                 headers={'User-Agent': 'Mozilla/5.0'},
                                 timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('country_code', '')}-{data.get('isp', '')}".replace(' ', '_')
                    return
    except:
        pass
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://ip-api.com/json',
                                 headers={'User-Agent': 'Mozilla/5.0'},
                                 timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('countryCode', '')}-{data.get('org', '')}".replace(' ', '_')
                    return
    except:
        pass
    
    ISP = 'Unknown'

async def get_ip():
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api-ipv4.ip.sb/ip', timeout=5) as resp:
                    if resp.status == 200:
                        ip = await resp.text()
                        CurrentDomain = ip.strip()
                        Tls = 'none'
                        CurrentPort = PORT
        except Exception as e:
            logger.error(f'Failed to get IP: {e}')
            CurrentDomain = 'change-your-domain.com'
            Tls = 'tls'
            CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443

async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except:
        pass
    
    for dns_server in DNS_SERVERS:
        try:
            async with aiohttp.ClientSession() as session:
                url = f'https://dns.google/resolve?name={host}&type=A'
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('Status') == 0 and data.get('Answer'):
                            for answer in data['Answer']:
                                if answer.get('type') == 1:
                                    return answer.get('data')
        except:
            continue
    
    return host  # 如果解析失败，返回原始域名

class ProxyHandler:
    def __init__(self, uuid: str):
        self.uuid = uuid
        self.uuid_bytes = bytes.fromhex(uuid)
        
    async def handle_vless(self, websocket, first_msg: bytes) -> bool:
        """处理VLS协议"""
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            
            # 验证UUID
            if first_msg[1:17] != self.uuid_bytes:
                return False
            
            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False
            
            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1
            
            # 解析地址
            host = ''
            if atyp == 1:  # IPv4
                if i + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:  # 域名
                if i >= len(first_msg):
                    return False
                host_len = first_msg[i]
                i += 1
                if i + host_len > len(first_msg):
                    return False
                host = first_msg[i:i+host_len].decode()
                i += host_len
            elif atyp == 3:  # IPv6
                if i + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' 
                              for j in range(i, i+16, 2))
                i += 16
            else:
                return False
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            await websocket.send_bytes(bytes([0, 0]))
            
            resolved_host = await resolve_host(host)
            
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                
                # 发送剩余数据
                if i < len(first_msg):
                    writer.write(first_msg[i:])
                    await writer.drain()
                
                # 双向转发
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                
                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass
                
                await asyncio.gather(
                    forward_ws_to_tcp(),
                    forward_tcp_to_ws()
                )
                
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            
            return True
            
        except Exception as e:
            if DEBUG:
                logger.error(f"VLESS handler error: {e}")
            return False
    
    async def handle_trojan(self, websocket, first_msg: bytes) -> bool:
        """处理Tro协议"""
        try:
            if len(first_msg) < 58:
                return False
            
            received_hash_bytes = first_msg[:56]
            
            # 验证密码 - 支持标准UUID和无短横线UUID
            hash_obj1 = hashlib.sha224()
            hash_obj1.update(self.uuid.encode())
            expected_hash_hex1 = hash_obj1.hexdigest()
            
            # 尝试使用标准UUID（带短横线）
            standard_uuid = UUID
            hash_obj2 = hashlib.sha224()
            hash_obj2.update(standard_uuid.encode())
            expected_hash_hex2 = hash_obj2.hexdigest()
            
            # 转换为hex字符串进行比较
            received_hash_hex = received_hash_bytes.decode('ascii', errors='ignore')
            
            # 检查是否匹配任一UUID格式
            if received_hash_hex != expected_hash_hex1 and received_hash_hex != expected_hash_hex2:
                return False
            
            offset = 56
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            
            cmd = first_msg[offset]
            if cmd != 1:
                return False
            offset += 1
            
            atyp = first_msg[offset]
            offset += 1
            
            # 解析地址
            host = ''
            if atyp == 1:  # IPv4
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:  # 域名
                host_len = first_msg[offset]
                offset += 1
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:  # IPv6
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' 
                              for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            # 连接目标
            resolved_host = await resolve_host(host)
            
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()
                
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                
                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass
                
                await asyncio.gather(
                    forward_ws_to_tcp(),
                    forward_tcp_to_ws()
                )
                
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            
            return True
            
        except Exception as e:
            if DEBUG:
                logger.error(f"Tro handler error: {e}")
            return False
    
    async def handle_shadowsocks(self, websocket, first_msg: bytes) -> bool:
        """处理ss协议"""
        try:
            if len(first_msg) < 7:
                return False
            
            offset = 0
            atyp = first_msg[offset]
            offset += 1
            
            # 解析地址
            host = ''
            if atyp == 1:  # IPv4
                if offset + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:  # 域名
                if offset >= len(first_msg):
                    return False
                host_len = first_msg[offset]
                offset += 1
                if offset + host_len > len(first_msg):
                    return False
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:  # IPv6
                if offset + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' 
                              for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            
            if offset + 2 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            # 连接目标
            resolved_host = await resolve_host(host)
            
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()
                
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                
                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass
                
                await asyncio.gather(
                    forward_ws_to_tcp(),
                    forward_tcp_to_ws()
                )
                
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            
            return True
            
        except Exception as e:
            if DEBUG:
                logger.error(f"Shadowsocks handler error: {e}")
            return False

async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    CUUID = UUID.replace('-', '')
    path = request.path
    
    if f'/{WSPATH}' not in path:
        await ws.close()
        return ws
    
    proxy = ProxyHandler(CUUID)
    
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        
        msg_data = first_msg.data
        
        # 尝试VLS
        if len(msg_data) > 17 and msg_data[0] == 0:
            if await proxy.handle_vless(ws, msg_data):
                return ws
        
        # 尝试Tro
        if len(msg_data) >= 58:
            if await proxy.handle_trojan(ws, msg_data):
                return ws
        
        # 尝试ss
        if len(msg_data) > 0 and msg_data[0] in (1, 3, 4):
            if await proxy.handle_shadowsocks(ws, msg_data):
                return ws
        
        await ws.close()
        
    except asyncio.TimeoutError:
        await ws.close()
    except Exception as e:
        if DEBUG:
            logger.error(f"WebSocket handler error: {e}")
        await ws.close()
    
    return ws

async def http_handler(request):
    if request.path == '/':
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                content = f.read()
            return web.Response(text=content, content_type='text/html')
        except:
            return web.Response(text='Hello world!', content_type='text/html')
    
    elif request.path == f'/{SUB_PATH}':
        await get_isp()
        await get_ip()
        
        name_part = f"{NAME}-{ISP}" if NAME else ISP
        tls_param = 'tls' if Tls == 'tls' else 'none'
        ss_tls_param = 'tls;' if Tls == 'tls' else ''
        
        # 生成配置链接
        vless_url = f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none&security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        trojan_url = f"trojan://{UUID}@{CurrentDomain}:{CurrentPort}?security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        
        ss_method_password = base64.b64encode(f"none:{UUID}".encode()).decode()
        ss_url = f"ss://{ss_method_password}@{CurrentDomain}:{CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{CurrentDomain};path%3D%2F{WSPATH};{ss_tls_param}sni%3D{CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#{name_part}"
        
        subscription = f"{vless_url}\n{trojan_url}\n{ss_url}"
        base64_content = base64.b64encode(subscription.encode()).decode()
        
        return web.Response(text=base64_content + '\n', content_type='text/plain')
    
    return web.Response(status=404, text='Not Found\n')

TLS_PORTS = {'443', '8443', '2096', '2087', '2083', '2053'}
NEZHA_AGENT_VERSION = 'python-agent-0.1.0'

TASK_TYPE_HTTP_GET = 1
TASK_TYPE_ICMP_PING = 2
TASK_TYPE_TCP_PING = 3
TASK_TYPE_COMMAND = 4
TASK_TYPE_KEEPALIVE = 7
TASK_TYPE_TERMINAL_GRPC = 8
TASK_TYPE_FM = 11
TASK_TYPE_REPORT_CONFIG = 12


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def env_int(name, default):
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        return default


def strip_scheme(value):
    text = (value or '').strip()
    if '://' in text:
        text = text.split('://', 1)[1]
    return text.strip('/')


def extract_port(value):
    text = strip_scheme(value)
    if not text:
        return ''
    if text.startswith('['):
        closing = text.find(']')
        if closing >= 0 and closing + 1 < len(text) and text[closing + 1] == ':':
            return text[closing + 2:]
        return ''
    first = text.find(':')
    last = text.rfind(':')
    if first >= 0 and first == last and last < len(text) - 1:
        return text[last + 1:]
    return ''


def has_explicit_port(value):
    return bool(extract_port(value))


def resolve_nezha_target(server, port):
    host = strip_scheme(server)
    if not host:
        return ''
    if has_explicit_port(host):
        return host
    resolved_port = (port or '').strip()
    if not resolved_port:
        return host
    if ':' in host and not host.startswith('['):
        host = f'[{host}]'
    return f'{host}:{resolved_port}'


def parse_host_port(value):
    text = (value or '').strip()
    if text.startswith('['):
        closing = text.find(']')
        if closing < 0 or closing + 1 >= len(text) or text[closing + 1] != ':':
            raise ValueError(f'invalid host:port: {value}')
        return text[1:closing], int(text[closing + 2:])
    split = text.rfind(':')
    if split <= 0 or split == len(text) - 1 or text.count(':') > 1:
        raise ValueError(f'invalid host:port: {value}')
    return text[:split], int(text[split + 1:])


@dataclass
class EmbeddedNezhaConfig:
    server: str
    client_secret: str
    client_uuid: str
    tls: bool
    report_delay: int = 4
    ip_report_period: int = 1800
    skip_connection_count: bool = True
    skip_procs_count: bool = True
    disable_command_execute: bool = False
    disable_send_query: bool = False
    disable_nat: bool = True
    use_ipv6_country_code: bool = False

    @classmethod
    def from_env(cls):
        if not NEZHA_SERVER or not NEZHA_KEY:
            return None
        target = resolve_nezha_target(NEZHA_SERVER, NEZHA_PORT)
        if not target or not has_explicit_port(target):
            logger.error('NEZHA_SERVER must include a port, or NEZHA_PORT must be set')
            return None
        port = extract_port(target)
        tls = env_bool('NEZHA_TLS', port in TLS_PORTS)
        return cls(
            server=target,
            client_secret=NEZHA_KEY,
            client_uuid=UUID,
            tls=tls,
            report_delay=max(1, min(4, env_int('NEZHA_REPORT_DELAY', 4))),
            ip_report_period=max(30, env_int('NEZHA_IP_REPORT_PERIOD', 1800)),
            skip_connection_count=env_bool('NEZHA_SKIP_CONNECTION_COUNT', True),
            skip_procs_count=env_bool('NEZHA_SKIP_PROCS_COUNT', True),
            disable_command_execute=env_bool('NEZHA_DISABLE_COMMAND_EXECUTE', False),
            disable_send_query=env_bool('NEZHA_DISABLE_SEND_QUERY', False),
            disable_nat=env_bool('NEZHA_DISABLE_NAT', True),
            use_ipv6_country_code=env_bool('NEZHA_USE_IPV6_COUNTRY_CODE', False),
        )

    @property
    def metadata(self):
        return (
            ('client_secret', self.client_secret),
            ('client_uuid', self.client_uuid),
        )

    def to_dict(self):
        return {
            'debug': DEBUG,
            'server': self.server,
            'client_secret': self.client_secret,
            'uuid': self.client_uuid,
            'tls': self.tls,
            'report_delay': self.report_delay,
            'ip_report_period': self.ip_report_period,
            'skip_connection_count': self.skip_connection_count,
            'skip_procs_count': self.skip_procs_count,
            'disable_command_execute': self.disable_command_execute,
            'disable_send_query': self.disable_send_query,
            'disable_nat': self.disable_nat,
            'gpu': False,
            'temperature': False,
            'disable_auto_update': True,
            'disable_force_update': True,
            'use_ipv6_country_code': self.use_ipv6_country_code,
        }


class NezhaProto:
    def __init__(self):
        file_proto = descriptor_pb2.FileDescriptorProto()
        file_proto.name = 'nezha.proto'
        file_proto.package = 'proto'
        file_proto.syntax = 'proto3'

        self._add_host(file_proto.message_type.add())
        self._add_state(file_proto.message_type.add())
        self._add_task(file_proto.message_type.add())
        self._add_task_result(file_proto.message_type.add())
        self._add_receipt(file_proto.message_type.add())
        self._add_uint64_receipt(file_proto.message_type.add())
        self._add_iostream_data(file_proto.message_type.add())
        self._add_geoip(file_proto.message_type.add())
        self._add_ip(file_proto.message_type.add())

        self.pool = descriptor_pool.DescriptorPool()
        self.pool.AddSerializedFile(file_proto.SerializeToString())
        self.Host = self._message_class('Host')
        self.State = self._message_class('State')
        self.Task = self._message_class('Task')
        self.TaskResult = self._message_class('TaskResult')
        self.Receipt = self._message_class('Receipt')
        self.Uint64Receipt = self._message_class('Uint64Receipt')
        self.IOStreamData = self._message_class('IOStreamData')
        self.GeoIP = self._message_class('GeoIP')
        self.IP = self._message_class('IP')

    def _message_class(self, name):
        descriptor = self.pool.FindMessageTypeByName(f'proto.{name}')
        if hasattr(message_factory, 'GetMessageClass'):
            return message_factory.GetMessageClass(descriptor)
        return message_factory.MessageFactory(self.pool).GetPrototype(descriptor)

    @staticmethod
    def _field(message, name, number, field_type, label=None, type_name=None):
        field = message.field.add()
        field.name = name
        field.number = number
        field.label = label or descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
        field.type = field_type
        if type_name:
            field.type_name = type_name

    def _add_host(self, message):
        message.name = 'Host'
        string = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
        uint64 = descriptor_pb2.FieldDescriptorProto.TYPE_UINT64
        repeated = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED
        self._field(message, 'platform', 1, string)
        self._field(message, 'platform_version', 2, string)
        self._field(message, 'cpu', 3, string, repeated)
        self._field(message, 'mem_total', 4, uint64)
        self._field(message, 'disk_total', 5, uint64)
        self._field(message, 'swap_total', 6, uint64)
        self._field(message, 'arch', 7, string)
        self._field(message, 'virtualization', 8, string)
        self._field(message, 'boot_time', 9, uint64)
        self._field(message, 'version', 10, string)
        self._field(message, 'gpu', 11, string, repeated)

    def _add_state(self, message):
        message.name = 'State'
        sensor = message.nested_type.add()
        sensor.name = 'SensorTemperature'
        self._field(sensor, 'name', 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        self._field(sensor, 'temperature', 2, descriptor_pb2.FieldDescriptorProto.TYPE_DOUBLE)
        uint64 = descriptor_pb2.FieldDescriptorProto.TYPE_UINT64
        double = descriptor_pb2.FieldDescriptorProto.TYPE_DOUBLE
        repeated = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED
        self._field(message, 'cpu', 1, double)
        self._field(message, 'mem_used', 2, uint64)
        self._field(message, 'swap_used', 3, uint64)
        self._field(message, 'disk_used', 4, uint64)
        self._field(message, 'net_in_transfer', 5, uint64)
        self._field(message, 'net_out_transfer', 6, uint64)
        self._field(message, 'net_in_speed', 7, uint64)
        self._field(message, 'net_out_speed', 8, uint64)
        self._field(message, 'uptime', 9, uint64)
        self._field(message, 'load1', 10, double)
        self._field(message, 'load5', 11, double)
        self._field(message, 'load15', 12, double)
        self._field(message, 'tcp_conn_count', 13, uint64)
        self._field(message, 'udp_conn_count', 14, uint64)
        self._field(message, 'process_count', 15, uint64)
        self._field(message, 'temperatures', 16, descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE, repeated, '.proto.State.SensorTemperature')
        self._field(message, 'gpu', 17, double, repeated)

    def _add_task(self, message):
        message.name = 'Task'
        self._field(message, 'id', 1, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64)
        self._field(message, 'type', 2, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64)
        self._field(message, 'data', 3, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)

    def _add_task_result(self, message):
        message.name = 'TaskResult'
        self._field(message, 'id', 1, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64)
        self._field(message, 'type', 2, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64)
        self._field(message, 'delay', 3, descriptor_pb2.FieldDescriptorProto.TYPE_FLOAT)
        self._field(message, 'data', 4, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        self._field(message, 'successful', 5, descriptor_pb2.FieldDescriptorProto.TYPE_BOOL)

    def _add_receipt(self, message):
        message.name = 'Receipt'
        self._field(message, 'proced', 1, descriptor_pb2.FieldDescriptorProto.TYPE_BOOL)

    def _add_uint64_receipt(self, message):
        message.name = 'Uint64Receipt'
        self._field(message, 'data', 1, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64)

    def _add_iostream_data(self, message):
        message.name = 'IOStreamData'
        self._field(message, 'data', 1, descriptor_pb2.FieldDescriptorProto.TYPE_BYTES)

    def _add_geoip(self, message):
        message.name = 'GeoIP'
        self._field(message, 'use6', 1, descriptor_pb2.FieldDescriptorProto.TYPE_BOOL)
        self._field(message, 'ip', 2, descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE, type_name='.proto.IP')
        self._field(message, 'country_code', 3, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        self._field(message, 'dashboard_boot_time', 4, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64)

    def _add_ip(self, message):
        message.name = 'IP'
        self._field(message, 'ipv4', 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        self._field(message, 'ipv6', 2, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)

    @staticmethod
    def serializer(message):
        return message.SerializeToString()

    @staticmethod
    def deserializer(cls):
        def parse(data):
            message = cls()
            message.ParseFromString(data)
            return message
        return parse


class NezhaSystemMonitor:
    def __init__(self, proto, config):
        self.proto = proto
        self.config = config
        self.boot_time = int(psutil.boot_time())
        self.net_in_transfer = 0
        self.net_out_transfer = 0
        self.net_in_speed = 0
        self.net_out_speed = 0
        self.last_net_sample = 0
        psutil.cpu_percent(interval=None)

    def collect_host(self):
        host = self.proto.Host()
        host.platform = platform.system().lower() or sys.platform
        host.platform_version = platform.version() or platform.release()
        cpu_name = platform.processor() or platform.machine() or 'CPU'
        if cpu_name:
            host.cpu.append(cpu_name)
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        host.mem_total = int(memory.total)
        host.disk_total = int(self._disk_total())
        host.swap_total = int(swap.total)
        host.arch = platform.machine()
        host.virtualization = ''
        host.boot_time = self.boot_time
        host.version = NEZHA_AGENT_VERSION
        return host

    def collect_state(self):
        state = self.proto.State()
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        net_in, net_out, in_speed, out_speed = self._network_stats()
        load1, load5, load15 = self._load_avg()
        tcp_count, udp_count = self._connection_counts()
        state.cpu = max(0.0, float(psutil.cpu_percent(interval=None)))
        state.mem_used = int(memory.total - memory.available)
        state.swap_used = int(swap.used)
        state.disk_used = int(self._disk_used())
        state.net_in_transfer = int(net_in)
        state.net_out_transfer = int(net_out)
        state.net_in_speed = int(in_speed)
        state.net_out_speed = int(out_speed)
        state.uptime = int(max(0, time.time() - self.boot_time))
        state.load1 = float(load1)
        state.load5 = float(load5)
        state.load15 = float(load15)
        state.tcp_conn_count = int(tcp_count)
        state.udp_conn_count = int(udp_count)
        if not self.config.skip_procs_count:
            try:
                state.process_count = len(psutil.pids())
            except Exception:
                state.process_count = 0
        return state

    def _disk_total(self):
        total = 0
        for usage in self._disk_usages():
            total += usage.total
        return total

    def _disk_used(self):
        used = 0
        for usage in self._disk_usages():
            used += usage.used
        return used

    def _disk_usages(self):
        usages = []
        seen = set()
        for part in psutil.disk_partitions(all=False):
            key = part.device or part.mountpoint
            if key in seen:
                continue
            seen.add(key)
            try:
                usages.append(psutil.disk_usage(part.mountpoint))
            except Exception:
                continue
        if not usages:
            try:
                usages.append(psutil.disk_usage(os.getcwd()))
            except Exception:
                pass
        return usages

    def _network_stats(self):
        counters = psutil.net_io_counters()
        if counters is None:
            return self.net_in_transfer, self.net_out_transfer, self.net_in_speed, self.net_out_speed
        now = int(time.time())
        net_in = int(counters.bytes_recv)
        net_out = int(counters.bytes_sent)
        diff = now - self.last_net_sample
        if diff > 0 and self.last_net_sample > 0:
            self.net_in_speed = max(0, net_in - self.net_in_transfer) // diff
            self.net_out_speed = max(0, net_out - self.net_out_transfer) // diff
        self.net_in_transfer = net_in
        self.net_out_transfer = net_out
        self.last_net_sample = now
        return self.net_in_transfer, self.net_out_transfer, self.net_in_speed, self.net_out_speed

    def _load_avg(self):
        if hasattr(os, 'getloadavg'):
            try:
                return os.getloadavg()
            except OSError:
                pass
        return 0.0, 0.0, 0.0

    def _connection_counts(self):
        if self.config.skip_connection_count:
            return 0, 0
        tcp = 0
        udp = 0
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.type == socket.SOCK_STREAM:
                    tcp += 1
                elif conn.type == socket.SOCK_DGRAM:
                    udp += 1
        except Exception:
            return 0, 0
        return tcp, udp


class NezhaTaskHandler:
    def __init__(self, client):
        self.client = client

    async def handle(self, task):
        result = self.client.proto.TaskResult()
        result.id = task.id
        result.type = task.type
        try:
            if task.type == TASK_TYPE_HTTP_GET:
                await self._http_get(task, result)
            elif task.type == TASK_TYPE_ICMP_PING:
                await self._icmp_ping(task, result)
            elif task.type == TASK_TYPE_TCP_PING:
                await self._tcp_ping(task, result)
            elif task.type == TASK_TYPE_COMMAND:
                await self._command(task, result)
            elif task.type == TASK_TYPE_KEEPALIVE:
                pass
            elif task.type == TASK_TYPE_TERMINAL_GRPC:
                await self.client.start_terminal(task.data)
                return None
            elif task.type == TASK_TYPE_FM:
                await self.client.start_file_manager(task.data)
                return None
            elif task.type == TASK_TYPE_REPORT_CONFIG:
                result.data = json.dumps(self.client.config.to_dict(), ensure_ascii=False)
                result.successful = True
            else:
                if DEBUG:
                    logger.info(f'Unsupported Nezha task type: {task.type}')
                return None
        except Exception as e:
            result.data = str(e)
        return result

    async def _http_get(self, task, result):
        if self.client.config.disable_send_query:
            result.data = 'This server has disabled query sending'
            return
        started = time.perf_counter()
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(task.data, allow_redirects=False, headers={'User-Agent': 'nezha-agent/1.0'}) as resp:
                await resp.read()
                result.delay = float((time.perf_counter() - started) * 1000)
                if 200 <= resp.status <= 399:
                    result.successful = True
                else:
                    result.data = f'HTTP error: {resp.status} {resp.reason}'

    async def _tcp_ping(self, task, result):
        if self.client.config.disable_send_query:
            result.data = 'This server has disabled query sending'
            return
        host, port = parse_host_port(task.data)
        started = time.perf_counter()
        reader = writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
            result.delay = float((time.perf_counter() - started) * 1000)
            result.successful = True
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()

    async def _icmp_ping(self, task, result):
        if self.client.config.disable_send_query:
            result.data = 'This server has disabled query sending'
            return
        ping_cmd = shutil.which('ping')
        if not ping_cmd:
            result.data = 'ping command is not available'
            return
        if os.name == 'nt':
            command = [ping_cmd, '-n', '5', '-w', '4000', task.data]
        else:
            command = [ping_cmd, '-c', '5', '-W', '4', task.data]
        started = time.perf_counter()
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output, _ = await asyncio.wait_for(proc.communicate(), timeout=25)
        result.delay = float((time.perf_counter() - started) * 1000 / 5)
        text = output.decode(errors='replace')
        if proc.returncode == 0:
            result.successful = True
            result.data = text[-2048:]
        else:
            result.data = text[-4096:] or f'ping exited with code {proc.returncode}'

    async def _command(self, task, result):
        if self.client.config.disable_command_execute:
            result.data = 'This agent has disabled command execution'
            return
        started = time.perf_counter()
        proc = await asyncio.create_subprocess_shell(
            task.data,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), timeout=7200)
        except asyncio.TimeoutError:
            proc.kill()
            output, _ = await proc.communicate()
            result.data = 'task execution timed out\n' + output.decode(errors='replace')[-1024 * 1024:]
            return
        result.delay = float(time.perf_counter() - started)
        data = output.decode(errors='replace')[-2 * 1024 * 1024:]
        if proc.returncode == 0:
            result.data = data
            result.successful = True
        else:
            result.data = f'{data}\nexit code: {proc.returncode}'


class NezhaIOStreamSession:
    STREAM_ID_PREFIX = bytes([0xff, 0x05, 0xff, 0x05])

    def __init__(self, client, stream_id):
        self.client = client
        self.stream_id = stream_id
        self.queue = asyncio.Queue()
        self.call = None
        self.closed = False

    async def open(self):
        await self.send(self.STREAM_ID_PREFIX + self.stream_id.encode())
        self.call = self.client.io_stream_call(self._outgoing(), metadata=self.client.config.metadata)

    async def send(self, data):
        if self.closed:
            return False
        message = self.client.proto.IOStreamData()
        message.data = data
        await self.queue.put(message)
        return True

    async def _outgoing(self):
        while not self.closed:
            message = await self.queue.get()
            yield message

    async def keepalive(self):
        while not self.closed:
            await asyncio.sleep(30)
            await self.send(b'')

    async def close(self):
        self.closed = True
        if self.call is not None:
            self.call.cancel()


class NezhaFileManagerProtocol:
    COMPLETE = b'NZUP'
    FILE = b'NZTD'
    FILE_NAME = b'NZFN'
    ERROR = b'NERR'

    @classmethod
    def listing_header(cls, path):
        path_bytes = path.encode()
        return cls.FILE_NAME + struct.pack('!I', len(path_bytes)) + path_bytes

    @classmethod
    def append_name(cls, payload, name, is_dir):
        name_bytes = name.encode()
        return payload + bytes([1 if is_dir else 0, len(name_bytes) & 0xff]) + name_bytes

    @classmethod
    def file_header(cls, size):
        return cls.FILE + struct.pack('!Q', size)

    @classmethod
    def error(cls, error):
        message = str(error) or error.__class__.__name__
        return cls.ERROR + message.encode(errors='replace')


class NezhaFileManagerSession:
    CHUNK_SIZE = 1024 * 1024

    def __init__(self, client, stream_id):
        self.session = NezhaIOStreamSession(client, stream_id)
        self.upload_file = None
        self.upload_size = 0
        self.upload_received = 0
        self.upload_path = None

    async def run(self):
        tasks = []
        try:
            await self.session.open()
            tasks = [asyncio.create_task(self.session.keepalive())]
            async for message in self.session.call:
                payload = bytes(message.data)
                if not payload:
                    continue
                await self._handle(payload)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            if DEBUG:
                logger.error(f'Nezha file manager session error: {e}')
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self._reset_upload()
            await self.session.close()

    async def _handle(self, payload):
        if self.upload_file is not None:
            await self._accept_upload_chunk(payload)
            return
        opcode = payload[0]
        if opcode == 0:
            await self._list_dir(self._path_from(payload, 1))
        elif opcode == 1:
            await self._download(self._path_from(payload, 1))
        elif opcode == 2:
            await self._begin_upload(payload)
        else:
            await self.session.send(NezhaFileManagerProtocol.error(f'unknown file manager opcode: {opcode}'))

    async def _list_dir(self, requested):
        directory = requested if requested and os.path.isdir(requested) else os.path.expanduser('~')
        try:
            display_path = os.path.abspath(directory) + os.sep
            payload = NezhaFileManagerProtocol.listing_header(display_path)
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        payload = NezhaFileManagerProtocol.append_name(payload, entry.name, entry.is_dir(follow_symlinks=False))
                    except OSError:
                        continue
            await self.session.send(payload)
        except Exception as e:
            await self.session.send(NezhaFileManagerProtocol.error(e))

    async def _download(self, path):
        if not path:
            await self.session.send(NezhaFileManagerProtocol.error('path is empty'))
            return
        try:
            size = os.path.getsize(path)
            if size <= 0:
                await self.session.send(NezhaFileManagerProtocol.error('requested file is empty'))
                return
            if not os.path.isfile(path):
                await self.session.send(NezhaFileManagerProtocol.error('requested path is not a file'))
                return
            await self.session.send(NezhaFileManagerProtocol.file_header(size))
            with open(path, 'rb') as file:
                while True:
                    chunk = file.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    await self.session.send(chunk)
        except Exception as e:
            await self.session.send(NezhaFileManagerProtocol.error(e))

    async def _begin_upload(self, payload):
        if len(payload) < 9:
            await self.session.send(NezhaFileManagerProtocol.error('data is invalid'))
            return
        self.upload_size = struct.unpack('!Q', payload[1:9])[0]
        self.upload_received = 0
        self.upload_path = self._path_from(payload, 9)
        if not self.upload_path:
            await self.session.send(NezhaFileManagerProtocol.error('path is empty'))
            await self._reset_upload()
            return
        try:
            parent = os.path.dirname(self.upload_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            self.upload_file = open(self.upload_path, 'wb')
            if self.upload_size == 0:
                await self._reset_upload()
                await self.session.send(NezhaFileManagerProtocol.COMPLETE)
        except Exception as e:
            await self.session.send(NezhaFileManagerProtocol.error(e))
            await self._reset_upload()

    async def _accept_upload_chunk(self, payload):
        try:
            self.upload_file.write(payload)
            self.upload_received += len(payload)
            if self.upload_received >= self.upload_size:
                await self._reset_upload()
                await self.session.send(NezhaFileManagerProtocol.COMPLETE)
        except Exception as e:
            await self.session.send(NezhaFileManagerProtocol.error(e))
            await self._reset_upload()

    async def _reset_upload(self):
        if self.upload_file is not None:
            try:
                self.upload_file.close()
            except Exception:
                pass
        self.upload_file = None
        self.upload_size = 0
        self.upload_received = 0
        self.upload_path = None

    @staticmethod
    def _path_from(payload, offset):
        if len(payload) <= offset:
            return None
        text = payload[offset:].decode(errors='replace')
        return text or None


class NezhaTerminalSession:
    STREAM_ID_PREFIX = bytes([0xff, 0x05, 0xff, 0x05])

    def __init__(self, client, stream_id):
        self.client = client
        self.stream_id = stream_id
        self.queue = asyncio.Queue()
        self.master_fd = None
        self.process = None
        self.call = None
        self.closed = False

    async def run(self):
        if pty is None or fcntl is None or termios is None or os.name == 'nt':
            logger.error('Nezha terminal requires a Unix PTY environment')
            return
        tasks = []
        try:
            self._start_shell()
            await self._send(self.STREAM_ID_PREFIX + self.stream_id.encode())
            self.call = self.client.io_stream_call(self._outgoing(), metadata=self.client.config.metadata)
            tasks = [
                asyncio.create_task(self._keepalive()),
                asyncio.create_task(self._read_remote()),
                asyncio.create_task(self._read_pty()),
                asyncio.create_task(self._wait_process()),
            ]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            if DEBUG:
                logger.error(f'Nezha terminal session error: {e}')
        finally:
            self.closed = True
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self._cleanup()

    def _start_shell(self):
        master_fd, slave_fd = pty.openpty()
        shell = shutil.which('bash') or shutil.which('sh') or '/bin/sh'
        env = os.environ.copy()
        env.setdefault('TERM', 'xterm-256color')
        env.setdefault('SHELL', shell)
        preexec = os.setsid if hasattr(os, 'setsid') else None
        self.process = subprocess.Popen(
            [shell, '-i'],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            env=env,
            preexec_fn=preexec,
        )
        os.close(slave_fd)
        self.master_fd = master_fd

    async def _send(self, data):
        message = self.client.proto.IOStreamData()
        message.data = data
        await self.queue.put(message)

    async def _outgoing(self):
        while not self.closed:
            message = await self.queue.get()
            yield message

    async def _keepalive(self):
        while not self.closed:
            await asyncio.sleep(30)
            await self._send(b'')

    async def _read_remote(self):
        async for message in self.call:
            payload = bytes(message.data)
            if not payload:
                continue
            if payload[0] == 0:
                await self._write_pty(payload[1:])
            elif payload[0] == 1:
                self._resize(payload[1:])
            else:
                await self._write_pty(payload)

    async def _write_pty(self, data):
        if self.master_fd is None or not data:
            return
        await asyncio.to_thread(os.write, self.master_fd, data)

    async def _read_pty(self):
        while not self.closed and self.master_fd is not None:
            try:
                data = await asyncio.to_thread(os.read, self.master_fd, 10 * 1024)
            except OSError:
                break
            if not data:
                break
            await self._send(data)

    async def _wait_process(self):
        if self.process is None:
            return
        await asyncio.to_thread(self.process.wait)

    def _resize(self, data):
        if self.master_fd is None:
            return
        try:
            payload = json.loads(data.decode(errors='ignore') or '{}')
            cols = int(payload.get('Cols') or payload.get('cols') or 0)
            rows = int(payload.get('Rows') or payload.get('rows') or 0)
            if cols > 0 and rows > 0:
                winsize = struct.pack('HHHH', rows, cols, 0, 0)
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
        except Exception:
            pass

    async def _cleanup(self):
        if self.call is not None:
            self.call.cancel()
        if self.process is not None and self.process.poll() is None:
            try:
                if hasattr(os, 'killpg'):
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                else:
                    self.process.terminate()
                await asyncio.to_thread(self.process.wait, 2)
            except Exception:
                try:
                    if hasattr(os, 'killpg'):
                        os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                    else:
                        self.process.kill()
                except Exception:
                    pass
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None


class NezhaPythonClient:
    def __init__(self, config):
        self.config = config
        self.proto = NezhaProto()
        self.monitor = NezhaSystemMonitor(self.proto, config)
        self.task_handler = NezhaTaskHandler(self)
        self.channel = None
        self.running = True
        self.terminals = set()
        self.file_managers = set()
        self.report_host_call = None
        self.report_geoip_call = None
        self.state_call = None
        self.task_call = None
        self.io_stream_call = None
        self.last_geo_query_ip = ''

    async def run_forever(self):
        while self.running:
            try:
                await self._run_once()
            except asyncio.CancelledError:
                self.running = False
                raise
            except Exception as e:
                logger.error(f'Nezha client disconnected: {e}')
            await self._close_channel()
            await self._close_terminals()
            await self._close_file_managers()
            if self.running:
                await asyncio.sleep(10)

    def stop(self):
        self.running = False

    async def _run_once(self):
        self.channel = self._new_channel()
        await asyncio.wait_for(self.channel.channel_ready(), timeout=15)
        self._bind_calls()
        receipt = await self.report_host_call(
            self.monitor.collect_host(),
            timeout=10,
            metadata=self.config.metadata,
        )
        if DEBUG:
            logger.debug(f'embedded Nezha client connected to {self.config.server}, dashboard boot: {receipt.data}')
        stop_event = asyncio.Event()
        result_queue = asyncio.Queue()
        tasks = [
            asyncio.create_task(self._state_stream(stop_event)),
            asyncio.create_task(self._task_stream(result_queue, stop_event)),
            asyncio.create_task(self._host_report_loop(stop_event)),
            asyncio.create_task(self._geoip_report_loop(stop_event)),
        ]
        done, pending = await asyncio.wait(tasks[:2], return_when=asyncio.FIRST_EXCEPTION)
        stop_event.set()
        await result_queue.put(None)
        for task in list(pending) + tasks[2:]:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for task in done:
            error = task.exception()
            if error:
                raise error
        raise RuntimeError('Nezha stream closed')

    def _new_channel(self):
        options = (
            ('grpc.keepalive_time_ms', 30000),
            ('grpc.keepalive_timeout_ms', 10000),
            ('grpc.keepalive_permit_without_calls', 1),
            ('grpc.max_receive_message_length', 16 * 1024 * 1024),
        )
        if self.config.tls:
            return grpc.aio.secure_channel(self.config.server, grpc.ssl_channel_credentials(), options=options)
        return grpc.aio.insecure_channel(self.config.server, options=options)

    def _bind_calls(self):
        self.report_host_call = self.channel.unary_unary(
            '/proto.NezhaService/ReportSystemInfo2',
            request_serializer=NezhaProto.serializer,
            response_deserializer=NezhaProto.deserializer(self.proto.Uint64Receipt),
        )
        self.report_geoip_call = self.channel.unary_unary(
            '/proto.NezhaService/ReportGeoIP',
            request_serializer=NezhaProto.serializer,
            response_deserializer=NezhaProto.deserializer(self.proto.GeoIP),
        )
        self.state_call = self.channel.stream_stream(
            '/proto.NezhaService/ReportSystemState',
            request_serializer=NezhaProto.serializer,
            response_deserializer=NezhaProto.deserializer(self.proto.Receipt),
        )
        self.task_call = self.channel.stream_stream(
            '/proto.NezhaService/RequestTask',
            request_serializer=NezhaProto.serializer,
            response_deserializer=NezhaProto.deserializer(self.proto.Task),
        )
        self.io_stream_call = self.channel.stream_stream(
            '/proto.NezhaService/IOStream',
            request_serializer=NezhaProto.serializer,
            response_deserializer=NezhaProto.deserializer(self.proto.IOStreamData),
        )

    async def _state_stream(self, stop_event):
        async def requests():
            while self.running and not stop_event.is_set():
                yield self.monitor.collect_state()
                await asyncio.sleep(self.config.report_delay)
        call = self.state_call(requests(), metadata=self.config.metadata)
        async for _ in call:
            pass
        raise RuntimeError('state stream ended')

    async def _task_stream(self, result_queue, stop_event):
        async def results():
            while self.running and not stop_event.is_set():
                try:
                    result = await asyncio.wait_for(result_queue.get(), timeout=1)
                except asyncio.TimeoutError:
                    continue
                if result is None:
                    break
                yield result
        call = self.task_call(results(), metadata=self.config.metadata)
        handler_tasks = set()
        try:
            async for task in call:
                handler_task = asyncio.create_task(self._handle_task(task, result_queue))
                handler_tasks.add(handler_task)
                handler_task.add_done_callback(handler_tasks.discard)
        finally:
            for handler_task in handler_tasks:
                handler_task.cancel()
            await asyncio.gather(*handler_tasks, return_exceptions=True)
        raise RuntimeError('task stream ended')

    async def _handle_task(self, task, result_queue):
        result = await self.task_handler.handle(task)
        if result is not None:
            await result_queue.put(result)

    async def _host_report_loop(self, stop_event):
        while self.running and not stop_event.is_set():
            await asyncio.sleep(600)
            if stop_event.is_set():
                return
            try:
                await self.report_host_call(self.monitor.collect_host(), timeout=10, metadata=self.config.metadata)
            except Exception as e:
                if DEBUG:
                    logger.error(f'Nezha host report failed: {e}')

    async def _geoip_report_loop(self, stop_event):
        while self.running and not stop_event.is_set():
            try:
                geoip = await self._fetch_geoip()
                if geoip is not None:
                    await self.report_geoip_call(geoip, timeout=10, metadata=self.config.metadata)
            except Exception as e:
                if DEBUG:
                    logger.error(f'Nezha GeoIP report failed: {e}')
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self.config.ip_report_period)
            except asyncio.TimeoutError:
                pass

    async def _fetch_geoip(self):
        endpoints = [
            'https://blog.cloudflare.com/cdn-cgi/trace',
            'https://developers.cloudflare.com/cdn-cgi/trace',
            'https://hostinger.com/cdn-cgi/trace',
            'https://ahrefs.com/cdn-cgi/trace',
        ]
        ipv4 = ''
        ipv6 = ''
        timeout = aiohttp.ClientTimeout(total=20, connect=5)
        async with aiohttp.ClientSession(timeout=timeout, headers={'User-Agent': 'nezha-agent/1.0'}) as session:
            for endpoint in endpoints:
                try:
                    async with session.get(endpoint, allow_redirects=False) as resp:
                        body = await resp.text()
                except Exception:
                    continue
                candidate = self._extract_ip(body)
                if not candidate:
                    continue
                try:
                    parsed = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if parsed.version == 4 and not ipv4:
                    ipv4 = candidate
                elif parsed.version == 6 and not ipv6:
                    ipv6 = candidate
                if ipv4 and ipv6:
                    break
        selected = ipv6 if self.config.use_ipv6_country_code and ipv6 else ipv4 or ipv6
        if not selected and self.last_geo_query_ip == '':
            return None
        if selected == self.last_geo_query_ip:
            return None
        self.last_geo_query_ip = selected
        ip_msg = self.proto.IP()
        ip_msg.ipv4 = ipv4
        ip_msg.ipv6 = ipv6
        geoip = self.proto.GeoIP()
        geoip.use6 = self.config.use_ipv6_country_code
        geoip.ip.CopyFrom(ip_msg)
        return geoip

    @staticmethod
    def _extract_ip(body):
        for line in (body or '').splitlines():
            text = line.strip()
            if text.startswith('ip='):
                return text[3:].strip()
        return (body or '').strip()

    async def start_terminal(self, data):
        stream_id = self._stream_id_from_task(data, 'terminal')
        if not stream_id:
            return
        session = NezhaTerminalSession(self, stream_id)
        task = asyncio.create_task(session.run())
        self.terminals.add(task)
        task.add_done_callback(self.terminals.discard)

    async def start_file_manager(self, data):
        stream_id = self._stream_id_from_task(data, 'file manager')
        if not stream_id:
            return
        session = NezhaFileManagerSession(self, stream_id)
        task = asyncio.create_task(session.run())
        self.file_managers.add(task)
        task.add_done_callback(self.file_managers.discard)

    @staticmethod
    def _stream_id_from_task(data, label):
        try:
            payload = json.loads(data or '{}')
        except json.JSONDecodeError:
            logger.error(f'Invalid Nezha {label} task payload')
            return None
        stream_id = payload.get('StreamID') or payload.get('stream_id') or payload.get('streamId')
        if not stream_id:
            logger.error(f'Nezha {label} task missing StreamID')
            return None
        return stream_id

    async def _close_terminals(self):
        for task in list(self.terminals):
            task.cancel()
        await asyncio.gather(*self.terminals, return_exceptions=True)
        self.terminals.clear()

    async def _close_file_managers(self):
        for task in list(self.file_managers):
            task.cancel()
        await asyncio.gather(*self.file_managers, return_exceptions=True)
        self.file_managers.clear()

    async def _close_channel(self):
        if self.channel is not None:
            await self.channel.close(grace=0)
            self.channel = None


def create_nezha_client():
    config = EmbeddedNezhaConfig.from_env()
    if config is None:
        return None
    if NEZHA_IMPORT_ERROR is not None:
        logger.error(f'Embedded Nezha client dependencies are missing: {NEZHA_IMPORT_ERROR}')
        return None
    return NezhaPythonClient(config)

async def add_access_task():
    if not AUTO_ACCESS or not DOMAIN:
        return
    
    full_url = f"https://{DOMAIN}/{SUB_PATH}"
    try:
        async with aiohttp.ClientSession() as session:
            await session.post("https://oooo.serv00.net/add-url",
                             json={"url": full_url},
                             headers={'Content-Type': 'application/json'})
        logger.info('Automatic Access Task added successfully')
    except:
        pass

async def main():
    actual_port = PORT
    
    # 检查端口是否可用，如果不可用则查找可用端口
    if not is_port_available(actual_port):
        logger.warning(f"Port {actual_port} is already in use, finding available port...")
        new_port = find_available_port(actual_port + 1)
        if new_port:
            actual_port = new_port
            logger.info(f"Using port {actual_port} instead of {PORT}")
        else:
            logger.error("No available ports found")
            sys.exit(1)
    
    app = web.Application()
    
    # 路由
    app.router.add_get('/', http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)
    
    # 启动服务
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', actual_port)
    await site.start()
    logger.info(f"✅ server is running on port {actual_port}")

    nezha_client = create_nezha_client()
    nezha_task = None
    if nezha_client is not None:
        nezha_task = asyncio.create_task(nezha_client.run_forever())

    await add_access_task()

    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        if nezha_client is not None:
            nezha_client.stop()
        if nezha_task is not None:
            nezha_task.cancel()
            await asyncio.gather(nezha_task, return_exceptions=True)
        await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
