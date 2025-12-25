"""
LLM 编排器 - 核心调度层，负责与 Claude API 交互并调度工具
"""
import asyncio
import json
import time
from typing import Dict, Any, List, Optional, Callable
import httpx
from anthropic import Anthropic, APIConnectionError, AuthenticationError, APIStatusError
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn

import config
from mcp_server.server import MCPToolServer
from .task_manager import TaskManager, TaskPhase
from prompts.system_prompt import SYSTEM_PROMPT, get_task_prompt


class Orchestrator:
    """LLM 编排器"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        verbose: bool = True,
        proxy: Optional[str] = None
    ):
        self.api_key = api_key or config.ANTHROPIC_API_KEY
        self.model = model or config.CLAUDE_MODEL
        self.verbose = verbose
        self.console = Console()

        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set. Please set the environment variable or pass api_key parameter.")

        # 配置代理
        proxy_url = proxy or config.HTTPS_PROXY or config.HTTP_PROXY

        # 创建带代理的 HTTP 客户端
        if proxy_url:
            self._print(f"[dim]使用代理: {proxy_url}[/dim]")
            http_client = httpx.Client(
                proxy=proxy_url,
                timeout=httpx.Timeout(config.REQUEST_TIMEOUT, connect=10.0)
            )
        else:
            http_client = httpx.Client(
                timeout=httpx.Timeout(config.REQUEST_TIMEOUT, connect=10.0)
            )

        # 创建 Anthropic 客户端
        client_kwargs = {
            "api_key": self.api_key,
            "http_client": http_client,
            "max_retries": config.MAX_RETRIES
        }

        # 如果设置了自定义 base_url
        if config.ANTHROPIC_BASE_URL:
            client_kwargs["base_url"] = config.ANTHROPIC_BASE_URL
            self._print(f"[dim]使用自定义 API 端点: {config.ANTHROPIC_BASE_URL}[/dim]")

        self.client = Anthropic(**client_kwargs)
        self.tool_server = MCPToolServer()
        self.task_manager = TaskManager()

        # 回调函数
        self.on_tool_call: Optional[Callable] = None
        self.on_tool_result: Optional[Callable] = None
        self.on_thinking: Optional[Callable] = None
        self.on_message: Optional[Callable] = None

    def _print(self, message: str, style: str = ""):
        """打印消息"""
        if self.verbose:
            self.console.print(message, style=style)

    def _print_panel(self, content: str, title: str = "", style: str = "blue"):
        """打印面板"""
        if self.verbose:
            self.console.print(Panel(content, title=title, border_style=style))

    def _print_tool_call(self, tool_name: str, args: Dict[str, Any]):
        """打印工具调用"""
        if self.verbose:
            args_str = json.dumps(args, ensure_ascii=False, indent=2)
            self.console.print(f"\n[bold cyan]🔧 调用工具:[/bold cyan] {tool_name}")
            self.console.print(f"[dim]{args_str}[/dim]")

    def _print_tool_result(self, tool_name: str, result: Dict[str, Any], duration: float):
        """打印工具结果"""
        if self.verbose:
            success = result.get("success", False)
            icon = "✅" if success else "❌"
            color = "green" if success else "red"

            self.console.print(f"[{color}]{icon} {tool_name} 完成[/{color}] [dim]({duration:.2f}s)[/dim]")

            # 打印关键结果
            if tool_name == "port_scan" and success:
                ports = result.get("open_ports", [])
                if ports:
                    self.console.print(f"  发现 {len(ports)} 个开放端口")
                    for p in ports[:5]:
                        self.console.print(f"    - {p['port']}/{p['protocol']} ({p.get('service', 'unknown')})")
                    if len(ports) > 5:
                        self.console.print(f"    ... 共 {len(ports)} 个端口")

            elif tool_name == "dir_bruteforce" and success:
                paths = result.get("found_paths", [])
                if paths:
                    self.console.print(f"  发现 {len(paths)} 个路径")
                    for p in paths[:5]:
                        self.console.print(f"    - [{p['status_code']}] {p['path']}")

            elif tool_name in ["sql_injection_test", "xss_test", "lfi_test", "command_injection_test"]:
                if result.get("vulnerable"):
                    self.console.print(f"  [bold red]⚠️  发现漏洞![/bold red]")
                    for v in result.get("vulnerabilities", [])[:3]:
                        self.console.print(f"    - {v.get('type', 'unknown')}: {v.get('param', '-')}")

    async def run_task(
        self,
        target: str,
        task_type: str = "full",
        user_message: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        运行渗透测试任务

        Args:
            target: 目标地址
            task_type: 任务类型 (full/recon/vuln_scan/exploit)
            user_message: 用户自定义指令

        Returns:
            任务结果
        """
        # 创建任务
        task = self.task_manager.create_task(target, task_type)
        self.task_manager.start_task(task.task_id)

        self._print_panel(
            f"目标: {target}\n任务类型: {task_type}\n任务ID: {task.task_id}",
            title="🚀 开始渗透测试任务",
            style="green"
        )

        # 准备初始消息
        if user_message:
            initial_message = user_message
        else:
            initial_message = get_task_prompt(target, task_type)

        # 初始化对话历史
        messages = [{"role": "user", "content": initial_message}]
        task.messages = messages.copy()

        try:
            # 主循环
            while True:
                # 调用 Claude API
                response = await self._call_claude(messages)

                if not response:
                    self._print("[red]Claude API 调用失败[/red]")
                    break

                # 处理响应
                assistant_message = {"role": "assistant", "content": response.content}
                messages.append(assistant_message)

                # 检查是否有工具调用
                tool_calls = [block for block in response.content if block.type == "tool_use"]

                if not tool_calls:
                    # 没有工具调用，提取文本响应
                    text_blocks = [block for block in response.content if block.type == "text"]
                    if text_blocks:
                        final_text = text_blocks[0].text
                        self._print_panel(
                            Markdown(final_text),
                            title="🤖 AI 分析",
                            style="blue"
                        )

                    # 检查是否应该结束
                    if response.stop_reason == "end_turn":
                        break
                    continue

                # 执行工具调用
                tool_results = []
                for tool_call in tool_calls:
                    tool_name = tool_call.name
                    tool_input = tool_call.input

                    self._print_tool_call(tool_name, tool_input)

                    # 执行工具
                    start_time = time.time()
                    result = await self.tool_server.execute_tool(tool_name, tool_input)
                    duration = time.time() - start_time

                    self._print_tool_result(tool_name, result, duration)

                    # 记录工具调用
                    self.task_manager.add_tool_call(
                        task.task_id,
                        tool_name,
                        tool_input,
                        result,
                        duration
                    )

                    # 准备工具结果
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_call.id,
                        "content": json.dumps(result, ensure_ascii=False)
                    })

                    # 回调
                    if self.on_tool_result:
                        self.on_tool_result(tool_name, result)

                # 添加工具结果到消息
                messages.append({"role": "user", "content": tool_results})

                # 检查停止条件
                if response.stop_reason == "end_turn":
                    # 再调用一次获取最终分析
                    continue

        except KeyboardInterrupt:
            self._print("\n[yellow]任务被用户中断[/yellow]")
        except Exception as e:
            self._print(f"[red]任务执行出错: {str(e)}[/red]")
            self.task_manager.fail_task(task.task_id, str(e))
            raise

        # 完成任务
        self.task_manager.complete_task(task.task_id)

        return self.task_manager.export_task(task.task_id)

    async def _call_claude(self, messages: List[Dict[str, Any]]) -> Any:
        """调用 Claude API"""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=self.tool_server.get_tools_for_claude(),
                messages=messages
            )
            return response
        except AuthenticationError as e:
            self._print(f"[red]API Key 认证失败: {str(e)}[/red]")
            self._print("[yellow]请检查 ANTHROPIC_API_KEY 是否正确设置[/yellow]")
            return None
        except APIConnectionError as e:
            self._print(f"[red]API 连接失败: {str(e)}[/red]")
            self._print("[yellow]请检查网络连接或代理设置[/yellow]")
            self._print("[dim]提示: 设置 HTTP_PROXY 或 HTTPS_PROXY 环境变量，或使用 --proxy 参数[/dim]")
            return None
        except APIStatusError as e:
            self._print(f"[red]API 状态错误 ({e.status_code}): {str(e)}[/red]")
            return None
        except httpx.TimeoutException as e:
            self._print(f"[red]请求超时: {str(e)}[/red]")
            self._print("[yellow]请检查网络连接或增加超时时间[/yellow]")
            return None
        except Exception as e:
            self._print(f"[red]API 调用错误: {str(e)}[/red]")
            return None

    async def chat(self, message: str) -> str:
        """
        交互式对话

        Args:
            message: 用户消息

        Returns:
            AI 回复
        """
        task = self.task_manager.get_current_task()

        if task:
            # 在现有任务上下文中对话
            context = self.task_manager.get_task_context(task.task_id)
            full_message = f"{context}\n\n用户: {message}"
        else:
            full_message = message

        messages = [{"role": "user", "content": full_message}]

        response = await self._call_claude(messages)

        if response:
            # 处理工具调用
            while True:
                tool_calls = [block for block in response.content if block.type == "tool_use"]

                if not tool_calls:
                    break

                # 添加助手消息
                messages.append({"role": "assistant", "content": response.content})

                # 执行工具
                tool_results = []
                for tool_call in tool_calls:
                    tool_name = tool_call.name
                    tool_input = tool_call.input

                    self._print_tool_call(tool_name, tool_input)

                    start_time = time.time()
                    result = await self.tool_server.execute_tool(tool_name, tool_input)
                    duration = time.time() - start_time

                    self._print_tool_result(tool_name, result, duration)

                    if task:
                        self.task_manager.add_tool_call(
                            task.task_id,
                            tool_name,
                            tool_input,
                            result,
                            duration
                        )

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_call.id,
                        "content": json.dumps(result, ensure_ascii=False)
                    })

                messages.append({"role": "user", "content": tool_results})

                # 继续对话
                response = await self._call_claude(messages)
                if not response:
                    return "API 调用失败"

            # 提取最终文本
            text_blocks = [block for block in response.content if block.type == "text"]
            if text_blocks:
                return text_blocks[0].text

        return "无法获取响应"

    def get_task_summary(self) -> Optional[Dict[str, Any]]:
        """获取当前任务摘要"""
        task = self.task_manager.get_current_task()
        if task:
            return self.task_manager.get_task_summary(task.task_id)
        return None

    def list_tools(self) -> Dict[str, List[str]]:
        """列出所有可用工具"""
        return self.tool_server.get_tool_categories()
