"""
HTTP 请求相关工具
"""
import asyncio
import aiohttp
import ssl
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, urlparse
import config


class HttpTools:
    """HTTP 请求工具集"""

    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=config.REQUEST_TIMEOUT)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

    async def http_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        verify_ssl: bool = False
    ) -> Dict[str, Any]:
        """
        发送 HTTP 请求

        Args:
            url: 目标 URL
            method: HTTP 方法 (GET, POST, PUT, DELETE 等)
            headers: 自定义请求头
            data: POST 数据
            params: URL 查询参数
            follow_redirects: 是否跟随重定向
            verify_ssl: 是否验证 SSL 证书

        Returns:
            包含响应信息的字典
        """
        request_headers = {**self.headers, **(headers or {})}

        ssl_context = None if verify_ssl else ssl.create_default_context()
        if not verify_ssl and ssl_context:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        try:
            connector = aiohttp.TCPConnector(ssl=ssl_context if not verify_ssl else None)
            async with aiohttp.ClientSession(
                timeout=self.timeout,
                connector=connector
            ) as session:
                async with session.request(
                    method=method.upper(),
                    url=url,
                    headers=request_headers,
                    data=data,
                    params=params,
                    allow_redirects=follow_redirects
                ) as response:
                    try:
                        body = await response.text()
                    except Exception:
                        body = "[Binary content]"

                    return {
                        "success": True,
                        "status_code": response.status,
                        "headers": dict(response.headers),
                        "body": body[:10000],  # 限制返回大小
                        "url": str(response.url),
                        "content_length": len(body)
                    }
        except asyncio.TimeoutError:
            return {"success": False, "error": "Request timeout"}
        except aiohttp.ClientError as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"Unexpected error: {str(e)}"}

    async def dir_bruteforce(
        self,
        base_url: str,
        wordlist: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
        threads: int = 10
    ) -> Dict[str, Any]:
        """
        目录爆破

        Args:
            base_url: 基础 URL
            wordlist: 目录字典
            extensions: 文件扩展名列表
            threads: 并发线程数

        Returns:
            发现的路径列表
        """
        if wordlist is None:
            wordlist = config.COMMON_DIRS

        if extensions is None:
            extensions = ["", ".php", ".html", ".txt", ".bak"]

        # 确保 base_url 以 / 结尾
        if not base_url.endswith("/"):
            base_url += "/"

        found_paths = []
        tested_count = 0

        async def check_path(path: str) -> Optional[Dict[str, Any]]:
            url = urljoin(base_url, path)
            result = await self.http_request(url, method="GET", follow_redirects=False)

            if result.get("success") and result.get("status_code") in [200, 301, 302, 403]:
                return {
                    "path": path,
                    "url": url,
                    "status_code": result["status_code"],
                    "content_length": result.get("content_length", 0)
                }
            return None

        # 生成所有待测试路径
        paths_to_test = []
        for word in wordlist:
            for ext in extensions:
                paths_to_test.append(f"{word}{ext}")

        # 分批并发执行
        semaphore = asyncio.Semaphore(threads)

        async def bounded_check(path: str):
            async with semaphore:
                return await check_path(path)

        tasks = [bounded_check(path) for path in paths_to_test]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            tested_count += 1
            if isinstance(result, dict) and result is not None:
                found_paths.append(result)

        return {
            "success": True,
            "base_url": base_url,
            "tested_count": tested_count,
            "found_count": len(found_paths),
            "found_paths": found_paths
        }

    async def grab_banner(self, url: str) -> Dict[str, Any]:
        """
        获取 Web 服务器 Banner 信息

        Args:
            url: 目标 URL

        Returns:
            Banner 信息
        """
        result = await self.http_request(url)

        if not result.get("success"):
            return result

        headers = result.get("headers", {})
        body = result.get("body", "")

        # 提取关键信息
        banner_info = {
            "success": True,
            "url": url,
            "server": headers.get("Server", "Unknown"),
            "powered_by": headers.get("X-Powered-By", "Unknown"),
            "content_type": headers.get("Content-Type", "Unknown"),
            "technologies": []
        }

        # 简单的技术识别
        tech_signatures = {
            "PHP": ["php", "PHP"],
            "ASP.NET": ["asp.net", "ASP.NET", "__VIEWSTATE"],
            "Apache": ["Apache"],
            "Nginx": ["nginx", "Nginx"],
            "IIS": ["IIS", "Microsoft-IIS"],
            "WordPress": ["wp-content", "wp-includes", "WordPress"],
            "Drupal": ["Drupal", "drupal"],
            "Joomla": ["Joomla", "joomla"],
            "jQuery": ["jquery", "jQuery"],
            "Bootstrap": ["bootstrap"],
            "React": ["react", "React"],
            "Vue": ["vue", "Vue"],
            "Laravel": ["laravel", "Laravel"],
            "Django": ["django", "csrfmiddlewaretoken"],
        }

        check_content = str(headers) + body
        for tech, signatures in tech_signatures.items():
            for sig in signatures:
                if sig in check_content:
                    if tech not in banner_info["technologies"]:
                        banner_info["technologies"].append(tech)
                    break

        return banner_info

    async def crawl_links(self, url: str, depth: int = 1) -> Dict[str, Any]:
        """
        爬取页面链接

        Args:
            url: 起始 URL
            depth: 爬取深度

        Returns:
            发现的链接列表
        """
        import re

        visited = set()
        links = []
        forms = []

        parsed_base = urlparse(url)
        base_domain = parsed_base.netloc

        async def extract_from_page(page_url: str, current_depth: int):
            if current_depth > depth or page_url in visited:
                return

            visited.add(page_url)
            result = await self.http_request(page_url)

            if not result.get("success"):
                return

            body = result.get("body", "")

            # 提取链接
            href_pattern = r'href=["\']([^"\']+)["\']'
            src_pattern = r'src=["\']([^"\']+)["\']'
            action_pattern = r'action=["\']([^"\']+)["\']'

            for pattern in [href_pattern, src_pattern, action_pattern]:
                matches = re.findall(pattern, body, re.IGNORECASE)
                for match in matches:
                    # 转换为绝对 URL
                    if match.startswith("http"):
                        full_url = match
                    elif match.startswith("//"):
                        full_url = f"{parsed_base.scheme}:{match}"
                    elif match.startswith("/"):
                        full_url = f"{parsed_base.scheme}://{base_domain}{match}"
                    else:
                        full_url = urljoin(page_url, match)

                    parsed = urlparse(full_url)
                    if parsed.netloc == base_domain and full_url not in [l["url"] for l in links]:
                        links.append({
                            "url": full_url,
                            "source": page_url,
                            "type": "internal"
                        })

            # 提取表单
            form_pattern = r'<form[^>]*>(.*?)</form>'
            form_matches = re.findall(form_pattern, body, re.IGNORECASE | re.DOTALL)
            for form_content in form_matches:
                # 提取表单 action
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
                method_match = re.search(r'method=["\']([^"\']*)["\']', form_content, re.IGNORECASE)

                # 提取输入字段
                input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
                inputs = re.findall(input_pattern, form_content, re.IGNORECASE)

                forms.append({
                    "action": action_match.group(1) if action_match else page_url,
                    "method": method_match.group(1).upper() if method_match else "GET",
                    "inputs": inputs,
                    "source": page_url
                })

        await extract_from_page(url, 0)

        return {
            "success": True,
            "base_url": url,
            "links_found": len(links),
            "forms_found": len(forms),
            "links": links[:50],  # 限制返回数量
            "forms": forms[:20]
        }
