"""
MCP Tool Server - 将渗透测试工具封装为可被 LLM 调用的 Tools
"""
import asyncio
import json
from typing import Dict, Any, List, Callable, Optional
from dataclasses import dataclass, field

from .tools.http_tools import HttpTools
from .tools.scan_tools import ScanTools
from .tools.exploit_tools import ExploitTools
from .tools.utils_tools import UtilsTools


@dataclass
class ToolDefinition:
    """工具定义"""
    name: str
    description: str
    parameters: Dict[str, Any]
    handler: Callable
    category: str = "general"


class MCPToolServer:
    """MCP 工具服务器 - 管理所有渗透测试工具"""

    def __init__(self):
        self.http_tools = HttpTools()
        self.scan_tools = ScanTools()
        self.exploit_tools = ExploitTools()
        self.utils_tools = UtilsTools()

        self.tools: Dict[str, ToolDefinition] = {}
        self._register_all_tools()

    def _register_all_tools(self):
        """注册所有工具"""

        # ==================== HTTP 工具 ====================
        self._register_tool(
            name="http_request",
            description="发送 HTTP 请求到目标 URL。支持 GET、POST 等方法，可自定义请求头和数据。用于探测 Web 服务、获取页面内容、测试接口等。",
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL (必须包含 http:// 或 https://)"
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP 方法",
                        "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
                        "default": "GET"
                    },
                    "headers": {
                        "type": "object",
                        "description": "自定义请求头"
                    },
                    "data": {
                        "type": "object",
                        "description": "POST 请求数据"
                    },
                    "params": {
                        "type": "object",
                        "description": "URL 查询参数"
                    }
                },
                "required": ["url"]
            },
            handler=self.http_tools.http_request,
            category="http"
        )

        self._register_tool(
            name="dir_bruteforce",
            description="对目标网站进行目录爆破，发现隐藏的路径、文件和后台入口。使用常见目录字典进行探测。",
            parameters={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "description": "目标网站基础 URL"
                    },
                    "wordlist": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "自定义目录字典（可选，默认使用内置字典）"
                    },
                    "extensions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "文件扩展名列表，如 ['.php', '.html']"
                    },
                    "threads": {
                        "type": "integer",
                        "description": "并发线程数",
                        "default": 10
                    }
                },
                "required": ["base_url"]
            },
            handler=self.http_tools.dir_bruteforce,
            category="http"
        )

        self._register_tool(
            name="grab_banner",
            description="获取 Web 服务器的 Banner 信息，识别服务器类型、使用的技术栈（如 PHP、ASP.NET、WordPress 等）。",
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL"
                    }
                },
                "required": ["url"]
            },
            handler=self.http_tools.grab_banner,
            category="http"
        )

        self._register_tool(
            name="crawl_links",
            description="爬取目标页面的所有链接和表单，发现隐藏的入口点和可测试的参数。",
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "起始 URL"
                    },
                    "depth": {
                        "type": "integer",
                        "description": "爬取深度",
                        "default": 1
                    }
                },
                "required": ["url"]
            },
            handler=self.http_tools.crawl_links,
            category="http"
        )

        # ==================== 扫描工具 ====================
        self._register_tool(
            name="port_scan",
            description="对目标进行端口扫描，发现开放的服务端口，识别运行的服务类型。这是渗透测试的第一步。",
            parameters={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "目标 IP 地址或域名"
                    },
                    "ports": {
                        "type": "string",
                        "description": "端口范围，如 '1-1000' 或 '80,443,8080'（可选，默认扫描常见端口）"
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "扫描类型",
                        "enum": ["tcp", "udp"],
                        "default": "tcp"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "连接超时时间（秒）",
                        "default": 1
                    }
                },
                "required": ["target"]
            },
            handler=self.scan_tools.port_scan,
            category="scan"
        )

        self._register_tool(
            name="nmap_scan",
            description="使用 nmap 进行高级端口和服务扫描（需要系统安装 nmap）。可以进行版本检测、脚本扫描等。",
            parameters={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "目标 IP 或域名"
                    },
                    "arguments": {
                        "type": "string",
                        "description": "nmap 参数，如 '-sV -sC' 进行版本和脚本扫描",
                        "default": "-sV -sC"
                    }
                },
                "required": ["target"]
            },
            handler=self.scan_tools.nmap_scan,
            category="scan"
        )

        self._register_tool(
            name="subdomain_enum",
            description="枚举目标域名的子域名，发现更多攻击面。使用字典进行 DNS 查询。",
            parameters={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "主域名（如 example.com）"
                    },
                    "wordlist": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "自定义子域名字典（可选）"
                    }
                },
                "required": ["domain"]
            },
            handler=self.scan_tools.subdomain_enum,
            category="scan"
        )

        # ==================== 漏洞检测工具 ====================
        self._register_tool(
            name="sql_injection_test",
            description="检测 SQL 注入漏洞。对 URL 参数或 POST 数据进行 SQL 注入测试，包括报错注入和时间盲注检测。",
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL"
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP 方法",
                        "enum": ["GET", "POST"],
                        "default": "GET"
                    },
                    "params": {
                        "type": "object",
                        "description": "GET 参数，如 {'id': '1', 'name': 'test'}"
                    },
                    "data": {
                        "type": "object",
                        "description": "POST 数据，如 {'username': 'admin', 'password': 'test'}"
                    },
                    "payloads": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "自定义 SQL 注入 payload 列表（可选）"
                    }
                },
                "required": ["url"]
            },
            handler=self.exploit_tools.sql_injection_test,
            category="exploit"
        )

        self._register_tool(
            name="xss_test",
            description="检测跨站脚本（XSS）漏洞。测试参数是否存在反射型 XSS。",
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL"
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP 方法",
                        "enum": ["GET", "POST"],
                        "default": "GET"
                    },
                    "params": {
                        "type": "object",
                        "description": "GET 参数"
                    },
                    "data": {
                        "type": "object",
                        "description": "POST 数据"
                    }
                },
                "required": ["url"]
            },
            handler=self.exploit_tools.xss_test,
            category="exploit"
        )

        self._register_tool(
            name="lfi_test",
            description="检测本地文件包含（LFI）漏洞。测试是否可以读取服务器上的敏感文件。",
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL"
                    },
                    "param": {
                        "type": "string",
                        "description": "待测试的参数名（如 'file' 或 'page'）"
                    },
                    "payloads": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "自定义 LFI payload 列表（可选）"
                    }
                },
                "required": ["url", "param"]
            },
            handler=self.exploit_tools.lfi_test,
            category="exploit"
        )

        self._register_tool(
            name="command_injection_test",
            description="检测命令注入漏洞。测试参数是否可以执行系统命令。",
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL"
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP 方法",
                        "enum": ["GET", "POST"],
                        "default": "GET"
                    },
                    "params": {
                        "type": "object",
                        "description": "GET 参数"
                    },
                    "data": {
                        "type": "object",
                        "description": "POST 数据"
                    }
                },
                "required": ["url"]
            },
            handler=self.exploit_tools.command_injection_test,
            category="exploit"
        )

        self._register_tool(
            name="generate_payload",
            description="生成漏洞利用 Payload。根据漏洞类型和目标环境生成相应的攻击载荷。",
            parameters={
                "type": "object",
                "properties": {
                    "vuln_type": {
                        "type": "string",
                        "description": "漏洞类型",
                        "enum": ["sqli", "xss", "lfi", "rce"]
                    },
                    "target_db": {
                        "type": "string",
                        "description": "目标数据库类型（用于 SQL 注入）",
                        "enum": ["mysql", "mssql", "postgresql", "oracle"],
                        "default": "mysql"
                    },
                    "context": {
                        "type": "object",
                        "description": "上下文信息（如已知的表名、列名等）"
                    }
                },
                "required": ["vuln_type"]
            },
            handler=self.exploit_tools.generate_payload,
            category="exploit"
        )

        # ==================== 辅助工具 ====================
        self._register_tool(
            name="dns_lookup",
            description="DNS 查询，获取域名的 A、AAAA 记录。",
            parameters={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "要查询的域名"
                    }
                },
                "required": ["domain"]
            },
            handler=self.utils_tools.dns_lookup,
            category="utils"
        )

        self._register_tool(
            name="encode_payload",
            description="编码 Payload，支持 Base64、URL、Hex 等编码方式。用于绑过 WAF 或过滤。",
            parameters={
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "string",
                        "description": "要编码的 payload"
                    },
                    "encoding": {
                        "type": "string",
                        "description": "编码方式",
                        "enum": ["base64", "url", "double_url", "hex", "html", "unicode"],
                        "default": "base64"
                    }
                },
                "required": ["payload"]
            },
            handler=self.utils_tools.encode_payload,
            category="utils"
        )

        self._register_tool(
            name="decode_payload",
            description="解码 Payload，支持 Base64、URL、Hex 等解码。",
            parameters={
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "string",
                        "description": "要解码的 payload"
                    },
                    "encoding": {
                        "type": "string",
                        "description": "编码方式",
                        "enum": ["base64", "url", "hex", "html"],
                        "default": "base64"
                    }
                },
                "required": ["payload"]
            },
            handler=self.utils_tools.decode_payload,
            category="utils"
        )

        self._register_tool(
            name="analyze_headers",
            description="分析 HTTP 响应头的安全性，检查是否缺少安全头、是否泄露敏感信息。",
            parameters={
                "type": "object",
                "properties": {
                    "headers": {
                        "type": "object",
                        "description": "HTTP 响应头字典"
                    }
                },
                "required": ["headers"]
            },
            handler=self.utils_tools.analyze_headers,
            category="utils"
        )

        self._register_tool(
            name="check_waf",
            description="检测目标网站是否使用 WAF（Web 应用防火墙），识别 WAF 类型。",
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL"
                    }
                },
                "required": ["url"]
            },
            handler=self.utils_tools.check_waf,
            category="utils"
        )

    def _register_tool(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        handler: Callable,
        category: str = "general"
    ):
        """注册工具"""
        self.tools[name] = ToolDefinition(
            name=name,
            description=description,
            parameters=parameters,
            handler=handler,
            category=category
        )

    def get_tools_for_claude(self) -> List[Dict[str, Any]]:
        """获取 Claude API 格式的工具定义"""
        claude_tools = []
        for tool in self.tools.values():
            claude_tools.append({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.parameters
            })
        return claude_tools

    async def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """执行工具"""
        if name not in self.tools:
            return {"success": False, "error": f"Unknown tool: {name}"}

        tool = self.tools[name]
        try:
            result = await tool.handler(**arguments)
            return result
        except Exception as e:
            return {"success": False, "error": f"Tool execution failed: {str(e)}"}

    def get_tool_categories(self) -> Dict[str, List[str]]:
        """按类别获取工具列表"""
        categories = {}
        for tool in self.tools.values():
            if tool.category not in categories:
                categories[tool.category] = []
            categories[tool.category].append(tool.name)
        return categories

    def get_tool_info(self, name: str) -> Optional[Dict[str, Any]]:
        """获取工具详细信息"""
        if name not in self.tools:
            return None

        tool = self.tools[name]
        return {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters,
            "category": tool.category
        }
