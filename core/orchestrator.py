"""
LLM 编排器 - 核心调度层，负责与 Claude API 交互并调度工具
"""
import asyncio
import json
import time
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
import httpx
from anthropic import AsyncAnthropic, APIConnectionError, AuthenticationError, APIStatusError
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

        # 创建带代理的异步 HTTP 客户端
        if proxy_url:
            self._print(f"[dim]使用代理: {proxy_url}[/dim]")
            http_client = httpx.AsyncClient(
                proxy=proxy_url,
                timeout=httpx.Timeout(config.REQUEST_TIMEOUT, connect=10.0)
            )
        else:
            http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(config.REQUEST_TIMEOUT, connect=10.0)
            )

        # 创建异步 Anthropic 客户端
        client_kwargs = {
            "api_key": self.api_key,
            "http_client": http_client,
            "max_retries": config.MAX_RETRIES
        }

        # 如果设置了自定义 base_url
        if config.ANTHROPIC_BASE_URL:
            client_kwargs["base_url"] = config.ANTHROPIC_BASE_URL
            self._print(f"[dim]使用自定义 API 端点: {config.ANTHROPIC_BASE_URL}[/dim]")

        self.client = AsyncAnthropic(**client_kwargs)
        self.tool_server = MCPToolServer()
        self.task_manager = TaskManager()

        # 对话历史 (用于 chat 模式的上下文记忆)
        self.chat_history: List[Dict[str, Any]] = []

        # 输出模式: True=详细模式, False=简洁模式
        self.detailed_mode: bool = False
        self.detail_max_chars: int = 1000  # 详细模式下结果最大显示字符数

        # 对话保存目录
        self.sessions_dir = Path("sessions")
        self.sessions_dir.mkdir(exist_ok=True)

        # 回调函数
        self.on_tool_call: Optional[Callable] = None
        self.on_tool_result: Optional[Callable] = None
        self.on_thinking: Optional[Callable] = None
        self.on_message: Optional[Callable] = None

    def set_detailed_mode(self, enabled: bool):
        """设置输出模式"""
        self.detailed_mode = enabled
        mode_name = "详细模式" if enabled else "简洁模式"
        self._print(f"[cyan]已切换到 {mode_name}[/cyan]")

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
            if self.detailed_mode:
                # 详细模式：显示完整参数
                args_str = json.dumps(args, ensure_ascii=False, indent=2)
                self.console.print(f"\n[bold cyan]🔧 调用工具:[/bold cyan] {tool_name}")
                self.console.print(f"[dim]{args_str}[/dim]")
            else:
                # 简洁模式：只显示工具名和关键参数
                key_params = []
                for k, v in args.items():
                    if k in ['url', 'target', 'domain', 'param']:
                        key_params.append(f"{k}={v}")
                params_str = ", ".join(key_params) if key_params else ""
                self.console.print(f"[cyan]🔧 {tool_name}[/cyan] {params_str}")

    def _print_tool_result(self, tool_name: str, result: Dict[str, Any], duration: float):
        """打印工具结果"""
        if not self.verbose:
            return

        success = result.get("success", False)
        icon = "✅" if success else "❌"
        color = "green" if success else "red"

        if self.detailed_mode:
            # 详细模式：显示完整结果
            self.console.print(f"[{color}]{icon} {tool_name} 完成[/{color}] [dim]({duration:.2f}s)[/dim]")

            # 格式化并截断结果
            result_str = json.dumps(result, ensure_ascii=False, indent=2)
            if len(result_str) > self.detail_max_chars:
                result_str = result_str[:self.detail_max_chars] + f"\n... [dim](结果已截断，共 {len(result_str)} 字符)[/dim]"
            self.console.print(Panel(result_str, title="工具返回结果", border_style="dim"))
        else:
            # 简洁模式：只显示关键信息
            self.console.print(f"[{color}]{icon} {tool_name}[/{color}] [dim]({duration:.2f}s)[/dim]", end="")

            # 打印关键结果摘要
            if tool_name == "port_scan" and success:
                ports = result.get("open_ports", [])
                self.console.print(f" - 发现 {len(ports)} 个开放端口")
            elif tool_name == "dir_bruteforce" and success:
                paths = result.get("found_paths", [])
                self.console.print(f" - 发现 {len(paths)} 个路径")
            elif tool_name in ["sql_injection_test", "xss_test", "lfi_test", "command_injection_test", "sqlmap_scan"]:
                if result.get("vulnerable"):
                    self.console.print(f" - [bold red]发现漏洞![/bold red]")
                else:
                    self.console.print(f" - 未发现漏洞")
            elif tool_name == "sqlmap_dump" and success:
                dbs = result.get("databases", [])
                tables = result.get("tables", [])
                if dbs:
                    self.console.print(f" - 获取 {len(dbs)} 个数据库")
                elif tables:
                    self.console.print(f" - 获取 {len(tables)} 个表")
                else:
                    self.console.print("")
            else:
                self.console.print("")

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
        """调用 Claude API (异步)"""
        try:
            response = await self.client.messages.create(
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
        交互式对话（保持上下文记忆）

        Args:
            message: 用户消息

        Returns:
            AI 回复
        """
        task = self.task_manager.get_current_task()

        # 如果有任务上下文且是第一条消息，注入上下文
        if task and len(self.chat_history) == 0:
            context = self.task_manager.get_task_context(task.task_id)
            context_message = f"[当前任务上下文]\n{context}\n\n[用户消息]\n{message}"
            self.chat_history.append({"role": "user", "content": context_message})
        else:
            self.chat_history.append({"role": "user", "content": message})

        response = await self._call_claude(self.chat_history)

        if response:
            # 处理工具调用
            while True:
                tool_calls = [block for block in response.content if block.type == "tool_use"]

                if not tool_calls:
                    break

                # 添加助手消息到历史
                self.chat_history.append({"role": "assistant", "content": response.content})

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

                # 添加工具结果到历史
                self.chat_history.append({"role": "user", "content": tool_results})

                # 继续对话
                response = await self._call_claude(self.chat_history)
                if not response:
                    return "API 调用失败"

            # 提取最终文本并保存到历史
            text_blocks = [block for block in response.content if block.type == "text"]
            if text_blocks:
                reply = text_blocks[0].text
                self.chat_history.append({"role": "assistant", "content": reply})
                return reply

        return "无法获取响应"

    def clear_chat_history(self):
        """清空对话历史"""
        self.chat_history = []
        self._print("[dim]对话历史已清空[/dim]")

    def save_session(self, name: Optional[str] = None) -> str:
        """
        保存当前对话会话

        Args:
            name: 会话名称（可选，默认使用时间戳）

        Returns:
            保存的文件路径
        """
        if not self.chat_history:
            self._print("[yellow]当前没有对话历史可保存[/yellow]")
            return ""

        # 生成文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if name:
            filename = f"{name}_{timestamp}.json"
        else:
            filename = f"session_{timestamp}.json"

        filepath = self.sessions_dir / filename

        # 获取当前任务信息
        task = self.task_manager.get_current_task()
        task_info = None
        if task:
            task_info = {
                "task_id": task.task_id,
                "target": task.target,
                "task_type": task.task_type,
                "phase": task.phase.value,
                "vulnerabilities_count": len(task.vulnerabilities)
            }

        # 构建保存数据
        session_data = {
            "version": "1.0",
            "saved_at": datetime.now().isoformat(),
            "model": self.model,
            "task": task_info,
            "chat_history": self._serialize_chat_history(),
            "message_count": len(self.chat_history)
        }

        # 保存到文件
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, ensure_ascii=False, indent=2)

        self._print(f"[green]对话已保存到: {filepath}[/green]")
        return str(filepath)

    def _serialize_chat_history(self) -> List[Dict[str, Any]]:
        """序列化对话历史（处理不可序列化的对象）"""
        serialized = []
        for msg in self.chat_history:
            content = msg.get("content")
            role = msg.get("role", "user")

            if isinstance(content, str):
                serialized.append({"role": role, "content": content})
            elif isinstance(content, list):
                # 处理列表类型的 content (可能包含 TextBlock, ToolUse 等对象)
                serialized_content = []
                for item in content:
                    serialized_content.append(self._serialize_content_block(item))
                serialized.append({"role": role, "content": serialized_content})
            else:
                # 处理单个对象（如 TextBlock）
                serialized.append({
                    "role": role,
                    "content": self._serialize_content_block(content)
                })
        return serialized

    def _serialize_content_block(self, block: Any) -> Any:
        """序列化单个内容块"""
        # 如果已经是基础类型，直接返回
        if isinstance(block, (str, int, float, bool, type(None))):
            return block

        # 如果是字典，递归处理
        if isinstance(block, dict):
            return {k: self._serialize_content_block(v) for k, v in block.items()}

        # 如果是列表，递归处理
        if isinstance(block, list):
            return [self._serialize_content_block(item) for item in block]

        # 处理 Anthropic 的 TextBlock 对象
        if hasattr(block, 'type') and hasattr(block, 'text') and block.type == 'text':
            return {"type": "text", "text": block.text}

        # 处理 Anthropic 的 ToolUseBlock 对象
        if hasattr(block, 'type') and block.type == 'tool_use':
            return {
                "type": "tool_use",
                "id": getattr(block, 'id', ''),
                "name": getattr(block, 'name', ''),
                "input": getattr(block, 'input', {})
            }

        # 尝试转换为字典（如果对象有 model_dump 或 dict 方法）
        if hasattr(block, 'model_dump'):
            return block.model_dump()
        if hasattr(block, 'dict'):
            return block.dict()

        # 最后手段：转为字符串
        return str(block)

    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        列出所有已保存的会话

        Returns:
            会话列表
        """
        sessions = []
        for filepath in sorted(self.sessions_dir.glob("*.json"), reverse=True):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                sessions.append({
                    "filename": filepath.name,
                    "filepath": str(filepath),
                    "saved_at": data.get("saved_at", "未知"),
                    "message_count": data.get("message_count", 0),
                    "task": data.get("task"),
                })
            except Exception as e:
                sessions.append({
                    "filename": filepath.name,
                    "filepath": str(filepath),
                    "error": str(e)
                })

        return sessions

    def load_session(self, filepath: str) -> bool:
        """
        加载已保存的会话

        Args:
            filepath: 会话文件路径

        Returns:
            是否成功加载
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # 恢复对话历史
            self.chat_history = data.get("chat_history", [])

            # 显示加载信息
            self._print(f"[green]已加载会话: {filepath}[/green]")
            self._print(f"[dim]保存时间: {data.get('saved_at', '未知')}[/dim]")
            self._print(f"[dim]消息数量: {len(self.chat_history)}[/dim]")

            task_info = data.get("task")
            if task_info:
                self._print(f"[dim]目标: {task_info.get('target', '未知')}[/dim]")

            return True
        except FileNotFoundError:
            self._print(f"[red]文件不存在: {filepath}[/red]")
            return False
        except json.JSONDecodeError:
            self._print(f"[red]文件格式错误: {filepath}[/red]")
            return False
        except Exception as e:
            self._print(f"[red]加载失败: {str(e)}[/red]")
            return False

    def get_task_summary(self) -> Optional[Dict[str, Any]]:
        """获取当前任务摘要"""
        task = self.task_manager.get_current_task()
        if task:
            return self.task_manager.get_task_summary(task.task_id)
        return None

    def list_tools(self) -> Dict[str, List[str]]:
        """列出所有可用工具"""
        return self.tool_server.get_tool_categories()
