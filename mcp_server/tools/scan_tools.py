"""
扫描相关工具
"""
import asyncio
import socket
import subprocess
import re
from typing import Dict, Any, Optional, List
import config


class ScanTools:
    """扫描工具集"""

    async def port_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        scan_type: str = "tcp",
        timeout: int = 1
    ) -> Dict[str, Any]:
        """
        端口扫描

        Args:
            target: 目标 IP 或域名
            ports: 端口范围 (如 "1-1000" 或 "80,443,8080")
            scan_type: 扫描类型 (tcp/udp)
            timeout: 连接超时时间(秒)

        Returns:
            开放端口列表
        """
        if ports is None:
            ports = config.DEFAULT_PORTS

        # 解析端口列表
        port_list = self._parse_ports(ports)
        open_ports = []

        async def check_port(port: int) -> Optional[Dict[str, Any]]:
            try:
                if scan_type == "tcp":
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()

                    # 尝试获取 banner
                    banner = await self._grab_port_banner(target, port)
                    service = self._guess_service(port, banner)

                    return {
                        "port": port,
                        "state": "open",
                        "protocol": "tcp",
                        "service": service,
                        "banner": banner[:200] if banner else None
                    }
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception:
                return None

        # 并发扫描
        semaphore = asyncio.Semaphore(100)

        async def bounded_check(port: int):
            async with semaphore:
                return await check_port(port)

        tasks = [bounded_check(port) for port in port_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result is not None:
                open_ports.append(result)

        # 按端口排序
        open_ports.sort(key=lambda x: x["port"])

        return {
            "success": True,
            "target": target,
            "scanned_ports": len(port_list),
            "open_ports_count": len(open_ports),
            "open_ports": open_ports
        }

    async def _grab_port_banner(self, host: str, port: int, timeout: float = 2) -> Optional[str]:
        """尝试获取端口 Banner"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

            # 对于某些服务发送探测请求
            if port in [80, 8080, 8443, 443]:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            elif port == 22:
                pass  # SSH 会自动发送 banner
            else:
                writer.write(b"\r\n")

            await writer.drain()

            banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            await writer.wait_closed()

            return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            return None

    def _guess_service(self, port: int, banner: Optional[str] = None) -> str:
        """根据端口和 banner 猜测服务"""
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            1521: "oracle",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb"
        }

        service = common_ports.get(port, "unknown")

        # 从 banner 中识别
        if banner:
            banner_lower = banner.lower()
            if "ssh" in banner_lower:
                service = "ssh"
            elif "http" in banner_lower:
                service = "http"
            elif "ftp" in banner_lower:
                service = "ftp"
            elif "smtp" in banner_lower:
                service = "smtp"
            elif "mysql" in banner_lower:
                service = "mysql"
            elif "apache" in banner_lower:
                service = "http (Apache)"
            elif "nginx" in banner_lower:
                service = "http (Nginx)"
            elif "iis" in banner_lower:
                service = "http (IIS)"

        return service

    def _parse_ports(self, ports_str: str) -> List[int]:
        """解析端口字符串"""
        port_list = []
        parts = ports_str.split(",")

        for part in parts:
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-")
                    port_list.extend(range(int(start), int(end) + 1))
                except ValueError:
                    continue
            else:
                try:
                    port_list.append(int(part))
                except ValueError:
                    continue

        # 过滤有效端口范围
        return [p for p in port_list if 1 <= p <= 65535]

    async def nmap_scan(
        self,
        target: str,
        arguments: str = "-sV -sC"
    ) -> Dict[str, Any]:
        """
        使用 nmap 进行扫描（如果可用）

        Args:
            target: 目标
            arguments: nmap 参数

        Returns:
            nmap 扫描结果
        """
        try:
            # 检查 nmap 是否安装
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return {"success": False, "error": "nmap not installed"}
        except Exception:
            return {"success": False, "error": "nmap not available"}

        try:
            # 执行 nmap 扫描
            cmd = f"nmap {arguments} {target}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.SCAN_TIMEOUT
            )

            return {
                "success": True,
                "target": target,
                "arguments": arguments,
                "output": stdout.decode('utf-8', errors='ignore'),
                "errors": stderr.decode('utf-8', errors='ignore') if stderr else None
            }
        except asyncio.TimeoutError:
            return {"success": False, "error": "nmap scan timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def subdomain_enum(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        子域名枚举

        Args:
            domain: 主域名
            wordlist: 子域名字典

        Returns:
            发现的子域名
        """
        if wordlist is None:
            wordlist = [
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
                "ns1", "ns2", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
                "blog", "shop", "forum", "admin", "api", "dev", "staging",
                "test", "demo", "portal", "secure", "vpn", "remote", "cloud",
                "app", "apps", "mobile", "m", "static", "assets", "cdn",
                "git", "gitlab", "github", "jenkins", "ci", "build",
                "db", "database", "sql", "mysql", "postgres", "mongo",
                "redis", "cache", "queue", "mq", "rabbit", "elastic",
                "log", "logs", "monitor", "grafana", "prometheus", "kibana"
            ]

        found_subdomains = []

        async def check_subdomain(subdomain: str):
            full_domain = f"{subdomain}.{domain}"
            try:
                # DNS 解析
                result = await asyncio.get_event_loop().getaddrinfo(
                    full_domain, None,
                    family=socket.AF_INET
                )
                if result:
                    ip = result[0][4][0]
                    return {
                        "subdomain": full_domain,
                        "ip": ip
                    }
            except socket.gaierror:
                return None
            except Exception:
                return None

        semaphore = asyncio.Semaphore(50)

        async def bounded_check(subdomain: str):
            async with semaphore:
                return await check_subdomain(subdomain)

        tasks = [bounded_check(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result is not None:
                found_subdomains.append(result)

        return {
            "success": True,
            "domain": domain,
            "tested_count": len(wordlist),
            "found_count": len(found_subdomains),
            "subdomains": found_subdomains
        }

    async def whois_lookup(self, target: str) -> Dict[str, Any]:
        """
        WHOIS 查询

        Args:
            target: 域名或 IP

        Returns:
            WHOIS 信息
        """
        try:
            process = await asyncio.create_subprocess_shell(
                f"whois {target}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=30
            )

            output = stdout.decode('utf-8', errors='ignore')

            if not output.strip():
                return {"success": False, "error": "No WHOIS data returned"}

            return {
                "success": True,
                "target": target,
                "whois_data": output
            }
        except asyncio.TimeoutError:
            return {"success": False, "error": "WHOIS lookup timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}
