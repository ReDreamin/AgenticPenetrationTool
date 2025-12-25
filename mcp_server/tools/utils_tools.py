"""
辅助工具
"""
import asyncio
import base64
import hashlib
import socket
import struct
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse


class UtilsTools:
    """辅助工具集"""

    async def dns_lookup(self, domain: str) -> Dict[str, Any]:
        """
        DNS 查询

        Args:
            domain: 域名

        Returns:
            DNS 记录
        """
        results = {
            "success": True,
            "domain": domain,
            "records": {}
        }

        try:
            # A 记录
            try:
                a_records = socket.getaddrinfo(domain, None, socket.AF_INET)
                results["records"]["A"] = list(set([r[4][0] for r in a_records]))
            except socket.gaierror:
                results["records"]["A"] = []

            # AAAA 记录
            try:
                aaaa_records = socket.getaddrinfo(domain, None, socket.AF_INET6)
                results["records"]["AAAA"] = list(set([r[4][0] for r in aaaa_records]))
            except socket.gaierror:
                results["records"]["AAAA"] = []

        except Exception as e:
            return {"success": False, "error": str(e)}

        return results

    async def reverse_dns(self, ip: str) -> Dict[str, Any]:
        """
        反向 DNS 查询

        Args:
            ip: IP 地址

        Returns:
            主机名
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return {
                "success": True,
                "ip": ip,
                "hostname": hostname
            }
        except socket.herror:
            return {"success": False, "error": "No PTR record found"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def encode_payload(
        self,
        payload: str,
        encoding: str = "base64"
    ) -> Dict[str, Any]:
        """
        编码 Payload

        Args:
            payload: 原始 payload
            encoding: 编码方式 (base64, url, hex, html)

        Returns:
            编码后的 payload
        """
        from urllib.parse import quote
        import html

        encoded = ""

        if encoding == "base64":
            encoded = base64.b64encode(payload.encode()).decode()
        elif encoding == "url":
            encoded = quote(payload)
        elif encoding == "double_url":
            encoded = quote(quote(payload))
        elif encoding == "hex":
            encoded = payload.encode().hex()
        elif encoding == "html":
            encoded = html.escape(payload)
        elif encoding == "unicode":
            encoded = "".join([f"\\u{ord(c):04x}" for c in payload])
        else:
            return {"success": False, "error": f"Unknown encoding: {encoding}"}

        return {
            "success": True,
            "original": payload,
            "encoding": encoding,
            "encoded": encoded
        }

    async def decode_payload(
        self,
        payload: str,
        encoding: str = "base64"
    ) -> Dict[str, Any]:
        """
        解码 Payload

        Args:
            payload: 编码后的 payload
            encoding: 编码方式

        Returns:
            解码后的 payload
        """
        from urllib.parse import unquote
        import html

        decoded = ""

        try:
            if encoding == "base64":
                decoded = base64.b64decode(payload).decode()
            elif encoding == "url":
                decoded = unquote(payload)
            elif encoding == "hex":
                decoded = bytes.fromhex(payload).decode()
            elif encoding == "html":
                decoded = html.unescape(payload)
            else:
                return {"success": False, "error": f"Unknown encoding: {encoding}"}
        except Exception as e:
            return {"success": False, "error": f"Decode failed: {str(e)}"}

        return {
            "success": True,
            "original": payload,
            "encoding": encoding,
            "decoded": decoded
        }

    async def hash_text(
        self,
        text: str,
        algorithm: str = "md5"
    ) -> Dict[str, Any]:
        """
        计算文本哈希

        Args:
            text: 原始文本
            algorithm: 哈希算法 (md5, sha1, sha256, sha512)

        Returns:
            哈希值
        """
        try:
            if algorithm == "md5":
                hash_obj = hashlib.md5(text.encode())
            elif algorithm == "sha1":
                hash_obj = hashlib.sha1(text.encode())
            elif algorithm == "sha256":
                hash_obj = hashlib.sha256(text.encode())
            elif algorithm == "sha512":
                hash_obj = hashlib.sha512(text.encode())
            else:
                return {"success": False, "error": f"Unknown algorithm: {algorithm}"}

            return {
                "success": True,
                "text": text,
                "algorithm": algorithm,
                "hash": hash_obj.hexdigest()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def analyze_headers(
        self,
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        分析 HTTP 响应头安全性

        Args:
            headers: HTTP 响应头

        Returns:
            安全分析结果
        """
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": None,  # 只检查是否存在
            "Content-Security-Policy": None,
            "Referrer-Policy": None,
            "Permissions-Policy": None,
        }

        issues = []
        present_headers = []

        for header, expected in security_headers.items():
            header_value = headers.get(header) or headers.get(header.lower())

            if header_value is None:
                issues.append({
                    "header": header,
                    "issue": "Missing",
                    "severity": "medium",
                    "recommendation": f"Add {header} header"
                })
            else:
                present_headers.append({
                    "header": header,
                    "value": header_value
                })

                # 检查值是否正确
                if expected:
                    if isinstance(expected, list):
                        if header_value not in expected:
                            issues.append({
                                "header": header,
                                "issue": f"Unexpected value: {header_value}",
                                "severity": "low",
                                "recommendation": f"Set to one of: {expected}"
                            })
                    elif header_value != expected:
                        issues.append({
                            "header": header,
                            "issue": f"Unexpected value: {header_value}",
                            "severity": "low",
                            "recommendation": f"Set to: {expected}"
                        })

        # 检查敏感信息泄露
        sensitive_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
        for header in sensitive_headers:
            if header in headers or header.lower() in headers:
                issues.append({
                    "header": header,
                    "issue": "Information disclosure",
                    "severity": "low",
                    "recommendation": f"Remove or customize {header} header"
                })

        return {
            "success": True,
            "present_security_headers": present_headers,
            "issues_count": len(issues),
            "issues": issues
        }

    async def parse_url(self, url: str) -> Dict[str, Any]:
        """
        解析 URL

        Args:
            url: URL 字符串

        Returns:
            URL 组成部分
        """
        try:
            parsed = urlparse(url)
            return {
                "success": True,
                "url": url,
                "scheme": parsed.scheme,
                "netloc": parsed.netloc,
                "path": parsed.path,
                "params": parsed.params,
                "query": parsed.query,
                "fragment": parsed.fragment,
                "hostname": parsed.hostname,
                "port": parsed.port
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_waf(self, url: str) -> Dict[str, Any]:
        """
        WAF 检测

        Args:
            url: 目标 URL

        Returns:
            WAF 检测结果
        """
        import aiohttp

        waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
            "Akamai": ["akamai", "x-akamai"],
            "Sucuri": ["sucuri", "x-sucuri"],
            "Imperva": ["incapsula", "x-iinfo"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "F5 BIG-IP": ["bigip", "f5"],
            "Barracuda": ["barracuda"],
            "Fortinet": ["fortigate", "fortiweb"],
        }

        # 发送正常请求
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    headers = dict(response.headers)
                    body = await response.text()

            detected_waf = []
            check_content = str(headers).lower() + body.lower()

            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in check_content:
                        detected_waf.append(waf_name)
                        break

            return {
                "success": True,
                "url": url,
                "waf_detected": len(detected_waf) > 0,
                "detected_waf": list(set(detected_waf))
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
