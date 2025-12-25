"""
任务管理器 - 管理渗透测试任务的生命周期
"""
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import json


class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


class TaskPhase(Enum):
    """任务阶段"""
    INIT = "init"
    RECON = "recon"                    # 信息收集
    VULN_DETECTION = "vuln_detection"  # 漏洞检测
    EXPLOITATION = "exploitation"       # 漏洞利用
    POST_EXPLOIT = "post_exploit"      # 后渗透
    REPORTING = "reporting"            # 报告生成
    DONE = "done"


@dataclass
class ToolCall:
    """工具调用记录"""
    tool_name: str
    arguments: Dict[str, Any]
    result: Optional[Dict[str, Any]] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration: float = 0.0
    success: bool = False


@dataclass
class Vulnerability:
    """漏洞记录"""
    vuln_type: str
    severity: str  # critical, high, medium, low, info
    url: str
    param: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Task:
    """渗透测试任务"""
    task_id: str
    target: str
    task_type: str = "full"
    status: TaskStatus = TaskStatus.PENDING
    phase: TaskPhase = TaskPhase.INIT
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    # 收集的信息
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    discovered_paths: List[Dict[str, Any]] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)

    # 漏洞发现
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    # 工具调用历史
    tool_calls: List[ToolCall] = field(default_factory=list)

    # 对话历史（用于 LLM）
    messages: List[Dict[str, Any]] = field(default_factory=list)


class TaskManager:
    """任务管理器"""

    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.current_task: Optional[str] = None
        self._task_counter = 0

    def create_task(self, target: str, task_type: str = "full") -> Task:
        """创建新任务"""
        self._task_counter += 1
        task_id = f"task_{self._task_counter:04d}"

        task = Task(
            task_id=task_id,
            target=target,
            task_type=task_type
        )

        self.tasks[task_id] = task
        self.current_task = task_id

        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        """获取任务"""
        return self.tasks.get(task_id)

    def get_current_task(self) -> Optional[Task]:
        """获取当前任务"""
        if self.current_task:
            return self.tasks.get(self.current_task)
        return None

    def start_task(self, task_id: str) -> bool:
        """开始任务"""
        task = self.tasks.get(task_id)
        if task and task.status == TaskStatus.PENDING:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now().isoformat()
            task.phase = TaskPhase.RECON
            return True
        return False

    def update_phase(self, task_id: str, phase: TaskPhase):
        """更新任务阶段"""
        task = self.tasks.get(task_id)
        if task:
            task.phase = phase

    def complete_task(self, task_id: str):
        """完成任务"""
        task = self.tasks.get(task_id)
        if task:
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now().isoformat()
            task.phase = TaskPhase.DONE

    def fail_task(self, task_id: str, reason: str = ""):
        """任务失败"""
        task = self.tasks.get(task_id)
        if task:
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now().isoformat()

    def add_tool_call(
        self,
        task_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        result: Dict[str, Any],
        duration: float = 0.0
    ):
        """添加工具调用记录"""
        task = self.tasks.get(task_id)
        if task:
            tool_call = ToolCall(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                duration=duration,
                success=result.get("success", False)
            )
            task.tool_calls.append(tool_call)

            # 自动提取信息
            self._extract_info_from_result(task, tool_name, result)

    def _extract_info_from_result(self, task: Task, tool_name: str, result: Dict[str, Any]):
        """从工具结果中自动提取信息"""
        if not result.get("success"):
            return

        if tool_name == "port_scan":
            task.open_ports.extend(result.get("open_ports", []))

        elif tool_name == "dir_bruteforce":
            task.discovered_paths.extend(result.get("found_paths", []))

        elif tool_name == "grab_banner":
            task.technologies.extend(result.get("technologies", []))

        elif tool_name == "crawl_links":
            task.forms.extend(result.get("forms", []))

        # 检测到漏洞时添加
        elif tool_name in ["sql_injection_test", "xss_test", "lfi_test", "command_injection_test"]:
            if result.get("vulnerable"):
                for vuln in result.get("vulnerabilities", []):
                    self._add_vulnerability(task, tool_name, vuln, result.get("url", ""))

    def _add_vulnerability(self, task: Task, tool_name: str, vuln_data: Dict, url: str):
        """添加漏洞"""
        vuln_type_map = {
            "sql_injection_test": "SQL Injection",
            "xss_test": "Cross-Site Scripting (XSS)",
            "lfi_test": "Local File Inclusion",
            "command_injection_test": "Command Injection"
        }

        severity_map = {
            "SQL Injection": "critical",
            "Command Injection": "critical",
            "Local File Inclusion": "high",
            "Cross-Site Scripting (XSS)": "medium"
        }

        vuln_type = vuln_type_map.get(tool_name, vuln_data.get("type", "Unknown"))
        severity = severity_map.get(vuln_type, "medium")

        vuln = Vulnerability(
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            param=vuln_data.get("param"),
            payload=vuln_data.get("payload"),
            evidence=vuln_data.get("evidence")
        )

        task.vulnerabilities.append(vuln)

    def add_vulnerability(
        self,
        task_id: str,
        vuln_type: str,
        severity: str,
        url: str,
        **kwargs
    ):
        """手动添加漏洞"""
        task = self.tasks.get(task_id)
        if task:
            vuln = Vulnerability(
                vuln_type=vuln_type,
                severity=severity,
                url=url,
                **kwargs
            )
            task.vulnerabilities.append(vuln)

    def add_message(self, task_id: str, role: str, content: str):
        """添加对话消息"""
        task = self.tasks.get(task_id)
        if task:
            task.messages.append({
                "role": role,
                "content": content
            })

    def get_task_summary(self, task_id: str) -> Dict[str, Any]:
        """获取任务摘要"""
        task = self.tasks.get(task_id)
        if not task:
            return {}

        return {
            "task_id": task.task_id,
            "target": task.target,
            "status": task.status.value,
            "phase": task.phase.value,
            "created_at": task.created_at,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
            "open_ports_count": len(task.open_ports),
            "discovered_paths_count": len(task.discovered_paths),
            "vulnerabilities_count": len(task.vulnerabilities),
            "tool_calls_count": len(task.tool_calls),
            "vulnerabilities_by_severity": self._count_vulns_by_severity(task)
        }

    def _count_vulns_by_severity(self, task: Task) -> Dict[str, int]:
        """按严重程度统计漏洞"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in task.vulnerabilities:
            if vuln.severity in counts:
                counts[vuln.severity] += 1
        return counts

    def get_task_context(self, task_id: str) -> str:
        """获取任务上下文（用于 LLM）"""
        task = self.tasks.get(task_id)
        if not task:
            return ""

        context = f"""
## 当前任务状态
- 目标: {task.target}
- 阶段: {task.phase.value}
- 状态: {task.status.value}

## 已收集信息
- 开放端口: {len(task.open_ports)} 个
- 发现路径: {len(task.discovered_paths)} 个
- 识别技术: {', '.join(task.technologies) if task.technologies else '无'}
- 发现表单: {len(task.forms)} 个

## 发现漏洞
- 总数: {len(task.vulnerabilities)} 个
"""
        for vuln in task.vulnerabilities:
            context += f"  - [{vuln.severity.upper()}] {vuln.vuln_type} at {vuln.url}\n"

        return context

    def export_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """导出任务数据"""
        task = self.tasks.get(task_id)
        if not task:
            return None

        return {
            "task_id": task.task_id,
            "target": task.target,
            "task_type": task.task_type,
            "status": task.status.value,
            "phase": task.phase.value,
            "created_at": task.created_at,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
            "open_ports": task.open_ports,
            "discovered_paths": task.discovered_paths,
            "technologies": task.technologies,
            "forms": task.forms,
            "vulnerabilities": [
                {
                    "vuln_type": v.vuln_type,
                    "severity": v.severity,
                    "url": v.url,
                    "param": v.param,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "description": v.description,
                    "recommendation": v.recommendation,
                    "discovered_at": v.discovered_at
                }
                for v in task.vulnerabilities
            ],
            "tool_calls": [
                {
                    "tool_name": tc.tool_name,
                    "arguments": tc.arguments,
                    "success": tc.success,
                    "timestamp": tc.timestamp,
                    "duration": tc.duration
                }
                for tc in task.tool_calls
            ]
        }
