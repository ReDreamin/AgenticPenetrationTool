"""
LLM 客户端抽象层 - 支持多服务商 (Anthropic, OpenAI)
"""
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx


@dataclass
class ToolCall:
    """工具调用信息"""
    id: str
    name: str
    input: Dict[str, Any]


@dataclass
class TextBlock:
    """文本内容块"""
    type: str = "text"
    text: str = ""


@dataclass
class LLMResponse:
    """统一的 LLM 响应格式"""
    content: List[Any]  # TextBlock 或 ToolCall 的列表
    stop_reason: str  # "end_turn", "tool_use" 等
    model: str
    usage: Dict[str, int]  # {"input_tokens": x, "output_tokens": y}


class BaseLLMClient(ABC):
    """LLM 客户端基类"""

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: Optional[str] = None,
        proxy: Optional[str] = None,
        timeout: int = 60,
        max_retries: int = 3
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.proxy = proxy
        self.timeout = timeout
        self.max_retries = max_retries

    @abstractmethod
    async def create_message(
        self,
        messages: List[Dict[str, Any]],
        system: str,
        tools: List[Dict[str, Any]],
        max_tokens: int = 4096
    ) -> Optional[LLMResponse]:
        """创建消息（调用 LLM API）"""
        pass

    @abstractmethod
    def convert_tools_format(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """将工具定义转换为服务商特定格式"""
        pass

    @abstractmethod
    def format_tool_result(self, tool_call_id: str, result: str) -> Dict[str, Any]:
        """格式化工具调用结果"""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """服务商名称"""
        pass


class AnthropicClient(BaseLLMClient):
    """Anthropic (Claude) 客户端"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        from anthropic import AsyncAnthropic

        # 创建 HTTP 客户端
        http_client = httpx.AsyncClient(
            proxy=self.proxy,
            timeout=httpx.Timeout(self.timeout, connect=10.0)
        ) if self.proxy else httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=10.0)
        )

        # 创建 Anthropic 客户端
        client_kwargs = {
            "api_key": self.api_key,
            "http_client": http_client,
            "max_retries": self.max_retries
        }
        if self.base_url:
            client_kwargs["base_url"] = self.base_url

        self.client = AsyncAnthropic(**client_kwargs)

    @property
    def provider_name(self) -> str:
        return "Anthropic"

    def convert_tools_format(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Anthropic 格式的工具定义不需要转换"""
        return tools

    def format_tool_result(self, tool_call_id: str, result: str) -> Dict[str, Any]:
        """格式化 Anthropic 的工具结果"""
        return {
            "type": "tool_result",
            "tool_use_id": tool_call_id,
            "content": result
        }

    async def create_message(
        self,
        messages: List[Dict[str, Any]],
        system: str,
        tools: List[Dict[str, Any]],
        max_tokens: int = 4096
    ) -> Optional[LLMResponse]:
        """调用 Anthropic API"""
        from anthropic import APIConnectionError, AuthenticationError, APIStatusError

        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                tools=tools,
                messages=messages
            )

            # 转换为统一格式
            content = []
            for block in response.content:
                if block.type == "text":
                    content.append(TextBlock(type="text", text=block.text))
                elif block.type == "tool_use":
                    content.append(ToolCall(
                        id=block.id,
                        name=block.name,
                        input=block.input
                    ))

            return LLMResponse(
                content=content,
                stop_reason=response.stop_reason,
                model=response.model,
                usage={
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens
                }
            )
        except AuthenticationError as e:
            raise LLMAuthError(f"Anthropic API Key 认证失败: {str(e)}")
        except APIConnectionError as e:
            raise LLMConnectionError(f"Anthropic API 连接失败: {str(e)}")
        except APIStatusError as e:
            raise LLMAPIError(f"Anthropic API 状态错误 ({e.status_code}): {str(e)}")
        except httpx.TimeoutException as e:
            raise LLMTimeoutError(f"请求超时: {str(e)}")
        except Exception as e:
            raise LLMAPIError(f"Anthropic API 调用错误: {str(e)}")


class OpenAIClient(BaseLLMClient):
    """OpenAI 客户端"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        from openai import AsyncOpenAI

        # 创建 HTTP 客户端
        http_client = httpx.AsyncClient(
            proxy=self.proxy,
            timeout=httpx.Timeout(self.timeout, connect=10.0)
        ) if self.proxy else httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=10.0)
        )

        # 创建 OpenAI 客户端
        client_kwargs = {
            "api_key": self.api_key,
            "http_client": http_client,
            "max_retries": self.max_retries
        }
        if self.base_url:
            client_kwargs["base_url"] = self.base_url

        self.client = AsyncOpenAI(**client_kwargs)

    @property
    def provider_name(self) -> str:
        return "OpenAI"

    def convert_tools_format(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """将 Anthropic 格式的工具定义转换为 OpenAI 格式"""
        openai_tools = []
        for tool in tools:
            openai_tool = {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {})
                }
            }
            openai_tools.append(openai_tool)
        return openai_tools

    def format_tool_result(self, tool_call_id: str, result: str) -> Dict[str, Any]:
        """格式化 OpenAI 的工具结果"""
        return {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": result
        }

    def _convert_messages_to_openai(
        self,
        messages: List[Dict[str, Any]],
        system: str
    ) -> List[Dict[str, Any]]:
        """将 Anthropic 格式的消息转换为 OpenAI 格式"""
        openai_messages = []

        # 添加系统消息
        if system:
            openai_messages.append({"role": "system", "content": system})

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content")

            if role == "user":
                if isinstance(content, str):
                    openai_messages.append({"role": "user", "content": content})
                elif isinstance(content, list):
                    # 处理工具结果列表
                    for item in content:
                        if isinstance(item, dict):
                            # OpenAI 格式的工具结果 (role: "tool")
                            if item.get("role") == "tool":
                                openai_messages.append({
                                    "role": "tool",
                                    "tool_call_id": item.get("tool_call_id", ""),
                                    "content": item.get("content", "")
                                })
                            # Anthropic 格式的工具结果 (type: "tool_result")
                            elif item.get("type") == "tool_result":
                                openai_messages.append({
                                    "role": "tool",
                                    "tool_call_id": item.get("tool_use_id", ""),
                                    "content": item.get("content", "")
                                })
                            # 文本内容
                            elif item.get("type") == "text":
                                openai_messages.append({"role": "user", "content": item.get("text", "")})
                            else:
                                # 其他类型的内容，尝试提取文本
                                text = item.get("text") or item.get("content")
                                if text:
                                    openai_messages.append({"role": "user", "content": str(text)})

            elif role == "assistant":
                if isinstance(content, str):
                    openai_messages.append({"role": "assistant", "content": content})
                elif isinstance(content, list):
                    # 处理助手消息（可能包含文本和工具调用）
                    text_parts = []
                    tool_calls = []

                    for item in content:
                        if hasattr(item, 'type'):
                            # Anthropic 对象
                            if item.type == "text":
                                text_parts.append(item.text)
                            elif item.type == "tool_use":
                                tool_calls.append({
                                    "id": item.id,
                                    "type": "function",
                                    "function": {
                                        "name": item.name,
                                        "arguments": json.dumps(item.input, ensure_ascii=False)
                                    }
                                })
                        elif isinstance(item, dict):
                            if item.get("type") == "text":
                                text_parts.append(item.get("text", ""))
                            elif item.get("type") == "tool_use":
                                tool_calls.append({
                                    "id": item.get("id", ""),
                                    "type": "function",
                                    "function": {
                                        "name": item.get("name", ""),
                                        "arguments": json.dumps(item.get("input", {}), ensure_ascii=False)
                                    }
                                })

                    assistant_msg = {"role": "assistant"}
                    if text_parts:
                        assistant_msg["content"] = "\n".join(text_parts)
                    if tool_calls:
                        assistant_msg["tool_calls"] = tool_calls
                        if "content" not in assistant_msg:
                            assistant_msg["content"] = None

                    openai_messages.append(assistant_msg)

            # 直接处理 tool 角色的消息（来自之前转换的结果）
            elif role == "tool":
                openai_messages.append({
                    "role": "tool",
                    "tool_call_id": msg.get("tool_call_id", ""),
                    "content": content if isinstance(content, str) else str(content)
                })

        return openai_messages

    async def create_message(
        self,
        messages: List[Dict[str, Any]],
        system: str,
        tools: List[Dict[str, Any]],
        max_tokens: int = 4096
    ) -> Optional[LLMResponse]:
        """调用 OpenAI API"""
        from openai import APIConnectionError, AuthenticationError, APIStatusError

        try:
            # 转换消息格式
            openai_messages = self._convert_messages_to_openai(messages, system)

            # 转换工具格式
            openai_tools = self.convert_tools_format(tools)

            # 调用 API
            response = await self.client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=openai_messages,
                tools=openai_tools if openai_tools else None,
                tool_choice="auto" if openai_tools else None
            )

            # 转换为统一格式
            content = []
            choice = response.choices[0]

            if choice.message.content:
                content.append(TextBlock(type="text", text=choice.message.content))

            if choice.message.tool_calls:
                for tool_call in choice.message.tool_calls:
                    content.append(ToolCall(
                        id=tool_call.id,
                        name=tool_call.function.name,
                        input=json.loads(tool_call.function.arguments)
                    ))

            # 确定停止原因
            stop_reason = "end_turn"
            if choice.finish_reason == "tool_calls":
                stop_reason = "tool_use"
            elif choice.finish_reason == "stop":
                stop_reason = "end_turn"

            return LLMResponse(
                content=content,
                stop_reason=stop_reason,
                model=response.model,
                usage={
                    "input_tokens": response.usage.prompt_tokens,
                    "output_tokens": response.usage.completion_tokens
                }
            )
        except AuthenticationError as e:
            raise LLMAuthError(f"OpenAI API Key 认证失败: {str(e)}")
        except APIConnectionError as e:
            raise LLMConnectionError(f"OpenAI API 连接失败: {str(e)}")
        except APIStatusError as e:
            raise LLMAPIError(f"OpenAI API 状态错误: {str(e)}")
        except httpx.TimeoutException as e:
            raise LLMTimeoutError(f"请求超时: {str(e)}")
        except Exception as e:
            raise LLMAPIError(f"OpenAI API 调用错误: {str(e)}")


# 自定义异常
class LLMError(Exception):
    """LLM 错误基类"""
    pass


class LLMAuthError(LLMError):
    """认证错误"""
    pass


class LLMConnectionError(LLMError):
    """连接错误"""
    pass


class LLMAPIError(LLMError):
    """API 错误"""
    pass


class LLMTimeoutError(LLMError):
    """超时错误"""
    pass


def create_llm_client(
    provider: str,
    api_key: str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    proxy: Optional[str] = None,
    timeout: int = 60,
    max_retries: int = 3
) -> BaseLLMClient:
    """
    创建 LLM 客户端工厂函数

    Args:
        provider: 服务商名称 ("anthropic" 或 "openai")
        api_key: API Key
        model: 模型名称（可选，使用默认值）
        base_url: 自定义 API 端点（可选）
        proxy: 代理地址（可选）
        timeout: 请求超时时间
        max_retries: 最大重试次数

    Returns:
        LLM 客户端实例
    """
    import config

    provider = provider.lower()

    if provider == "anthropic":
        return AnthropicClient(
            api_key=api_key,
            model=model or config.CLAUDE_MODEL,
            base_url=base_url or config.ANTHROPIC_BASE_URL,
            proxy=proxy,
            timeout=timeout,
            max_retries=max_retries
        )
    elif provider == "openai":
        return OpenAIClient(
            api_key=api_key,
            model=model or config.OPENAI_MODEL,
            base_url=base_url or config.OPENAI_BASE_URL,
            proxy=proxy,
            timeout=timeout,
            max_retries=max_retries
        )
    else:
        raise ValueError(f"不支持的服务商: {provider}。支持的服务商: anthropic, openai")
