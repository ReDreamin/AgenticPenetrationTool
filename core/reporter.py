"""
报告生成器 - 生成渗透测试报告
"""
from datetime import datetime
from typing import Dict, Any, List, Optional
from .task_manager import Task, Vulnerability


class Reporter:
    """报告生成器"""

    def __init__(self):
        self.severity_colors = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪"
        }

        self.severity_scores = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1,
            "info": 0
        }

    def generate_markdown_report(self, task: Task) -> str:
        """生成 Markdown 格式报告"""
        report = []

        # 标题
        report.append("# 渗透测试报告")
        report.append(f"\n**目标**: {task.target}")
        report.append(f"**测试时间**: {task.started_at} - {task.completed_at or '进行中'}")
        report.append(f"**任务状态**: {task.status.value}")
        report.append("")

        # 执行摘要
        report.append("## 执行摘要")
        report.append("")
        vuln_counts = self._count_vulns_by_severity(task.vulnerabilities)
        total_vulns = len(task.vulnerabilities)
        risk_score = self._calculate_risk_score(task.vulnerabilities)

        report.append(f"本次测试共发现 **{total_vulns}** 个安全漏洞：")
        report.append("")
        report.append(f"- {self.severity_colors['critical']} 严重: {vuln_counts['critical']}")
        report.append(f"- {self.severity_colors['high']} 高危: {vuln_counts['high']}")
        report.append(f"- {self.severity_colors['medium']} 中危: {vuln_counts['medium']}")
        report.append(f"- {self.severity_colors['low']} 低危: {vuln_counts['low']}")
        report.append(f"- {self.severity_colors['info']} 信息: {vuln_counts['info']}")
        report.append("")
        report.append(f"**风险评分**: {risk_score}/100")
        report.append("")

        # 信息收集结果
        report.append("## 信息收集")
        report.append("")

        # 开放端口
        report.append("### 开放端口")
        if task.open_ports:
            report.append("")
            report.append("| 端口 | 协议 | 服务 | Banner |")
            report.append("|------|------|------|--------|")
            for port in task.open_ports:
                banner = port.get('banner', '-')
                if banner and len(banner) > 50:
                    banner = banner[:50] + "..."
                report.append(f"| {port.get('port', '-')} | {port.get('protocol', 'tcp')} | {port.get('service', '-')} | {banner or '-'} |")
        else:
            report.append("*未发现开放端口*")
        report.append("")

        # 发现路径
        report.append("### 发现路径")
        if task.discovered_paths:
            report.append("")
            report.append("| 路径 | 状态码 | 大小 |")
            report.append("|------|--------|------|")
            for path in task.discovered_paths[:20]:  # 最多显示20个
                report.append(f"| {path.get('path', '-')} | {path.get('status_code', '-')} | {path.get('content_length', '-')} |")
            if len(task.discovered_paths) > 20:
                report.append(f"\n*... 共 {len(task.discovered_paths)} 个路径*")
        else:
            report.append("*未发现隐藏路径*")
        report.append("")

        # 技术栈
        report.append("### 识别技术")
        if task.technologies:
            report.append("")
            for tech in task.technologies:
                report.append(f"- {tech}")
        else:
            report.append("*未识别到技术栈*")
        report.append("")

        # 漏洞详情
        report.append("## 漏洞详情")
        report.append("")

        if task.vulnerabilities:
            # 按严重程度排序
            sorted_vulns = sorted(
                task.vulnerabilities,
                key=lambda v: self.severity_scores.get(v.severity, 0),
                reverse=True
            )

            for i, vuln in enumerate(sorted_vulns, 1):
                report.append(f"### {i}. {self.severity_colors[vuln.severity]} [{vuln.severity.upper()}] {vuln.vuln_type}")
                report.append("")
                report.append(f"**URL**: `{vuln.url}`")
                if vuln.param:
                    report.append(f"**参数**: `{vuln.param}`")
                if vuln.payload:
                    report.append(f"**Payload**: `{vuln.payload}`")
                if vuln.evidence:
                    report.append(f"**证据**: {vuln.evidence}")
                report.append("")
                report.append(f"**描述**: {vuln.description or self._get_vuln_description(vuln.vuln_type)}")
                report.append("")
                report.append(f"**修复建议**: {vuln.recommendation or self._get_vuln_recommendation(vuln.vuln_type)}")
                report.append("")
        else:
            report.append("*本次测试未发现安全漏洞*")
        report.append("")

        # 工具调用统计
        report.append("## 测试统计")
        report.append("")
        report.append(f"- 工具调用次数: {len(task.tool_calls)}")
        successful_calls = sum(1 for tc in task.tool_calls if tc.success)
        report.append(f"- 成功调用: {successful_calls}")
        report.append(f"- 失败调用: {len(task.tool_calls) - successful_calls}")
        report.append("")

        # 工具使用统计
        tool_usage = {}
        for tc in task.tool_calls:
            tool_usage[tc.tool_name] = tool_usage.get(tc.tool_name, 0) + 1

        if tool_usage:
            report.append("### 工具使用统计")
            report.append("")
            report.append("| 工具 | 调用次数 |")
            report.append("|------|----------|")
            for tool, count in sorted(tool_usage.items(), key=lambda x: x[1], reverse=True):
                report.append(f"| {tool} | {count} |")
        report.append("")

        # 结论
        report.append("## 结论")
        report.append("")
        if total_vulns == 0:
            report.append("本次渗透测试未发现明显的安全漏洞。建议继续保持良好的安全实践。")
        elif vuln_counts['critical'] > 0 or vuln_counts['high'] > 0:
            report.append("本次测试发现了严重的安全漏洞，建议立即修复。")
        else:
            report.append("本次测试发现了一些安全问题，建议按照优先级进行修复。")
        report.append("")

        # 页脚
        report.append("---")
        report.append(f"*报告生成时间: {datetime.now().isoformat()}*")
        report.append("*Generated by WuTong - 智能渗透测试工具*")

        return "\n".join(report)

    def _count_vulns_by_severity(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """按严重程度统计漏洞"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulnerabilities:
            if vuln.severity in counts:
                counts[vuln.severity] += 1
        return counts

    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> int:
        """计算风险评分 (0-100)"""
        if not vulnerabilities:
            return 0

        total_score = 0
        for vuln in vulnerabilities:
            total_score += self.severity_scores.get(vuln.severity, 0)

        # 归一化到 0-100
        max_possible = len(vulnerabilities) * 10
        if max_possible == 0:
            return 0

        return min(100, int((total_score / max_possible) * 100))

    def _get_vuln_description(self, vuln_type: str) -> str:
        """获取漏洞描述"""
        descriptions = {
            "SQL Injection": "SQL 注入是一种代码注入技术，攻击者可以通过在输入中插入恶意 SQL 语句来操纵数据库。",
            "Cross-Site Scripting (XSS)": "跨站脚本攻击允许攻击者在用户浏览器中执行恶意脚本，可能导致会话劫持、数据窃取等。",
            "Local File Inclusion": "本地文件包含漏洞允许攻击者读取服务器上的任意文件，可能导致敏感信息泄露。",
            "Command Injection": "命令注入漏洞允许攻击者在服务器上执行任意系统命令，可能导致完全控制服务器。"
        }
        return descriptions.get(vuln_type, "该漏洞可能导致安全风险，建议进行修复。")

    def _get_vuln_recommendation(self, vuln_type: str) -> str:
        """获取修复建议"""
        recommendations = {
            "SQL Injection": "使用参数化查询或预编译语句，对用户输入进行严格验证和转义，使用 ORM 框架。",
            "Cross-Site Scripting (XSS)": "对所有用户输入进行 HTML 实体编码，使用 Content-Security-Policy 头，使用现代前端框架的自动转义功能。",
            "Local File Inclusion": "禁止用户控制文件路径，使用白名单验证文件名，设置正确的文件权限。",
            "Command Injection": "避免使用系统命令，如必须使用则进行严格的输入验证，使用安全的 API 替代。"
        }
        return recommendations.get(vuln_type, "建议对相关代码进行安全审计，并实施适当的安全措施。")

    def generate_json_report(self, task: Task) -> Dict[str, Any]:
        """生成 JSON 格式报告"""
        return {
            "report_type": "penetration_test",
            "generated_at": datetime.now().isoformat(),
            "target": task.target,
            "task_id": task.task_id,
            "duration": {
                "started_at": task.started_at,
                "completed_at": task.completed_at
            },
            "summary": {
                "total_vulnerabilities": len(task.vulnerabilities),
                "by_severity": self._count_vulns_by_severity(task.vulnerabilities),
                "risk_score": self._calculate_risk_score(task.vulnerabilities)
            },
            "reconnaissance": {
                "open_ports": task.open_ports,
                "discovered_paths": task.discovered_paths,
                "technologies": task.technologies,
                "forms": task.forms
            },
            "vulnerabilities": [
                {
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "url": v.url,
                    "parameter": v.param,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "description": v.description or self._get_vuln_description(v.vuln_type),
                    "recommendation": v.recommendation or self._get_vuln_recommendation(v.vuln_type),
                    "discovered_at": v.discovered_at
                }
                for v in task.vulnerabilities
            ],
            "tool_calls": len(task.tool_calls)
        }

    def print_summary(self, task: Task):
        """打印任务摘要到控制台"""
        vuln_counts = self._count_vulns_by_severity(task.vulnerabilities)

        print("\n" + "=" * 60)
        print("渗透测试摘要")
        print("=" * 60)
        print(f"目标: {task.target}")
        print(f"状态: {task.status.value}")
        print(f"阶段: {task.phase.value}")
        print("-" * 60)
        print("发现信息:")
        print(f"  - 开放端口: {len(task.open_ports)}")
        print(f"  - 发现路径: {len(task.discovered_paths)}")
        print(f"  - 识别技术: {len(task.technologies)}")
        print("-" * 60)
        print("漏洞统计:")
        print(f"  {self.severity_colors['critical']} 严重: {vuln_counts['critical']}")
        print(f"  {self.severity_colors['high']} 高危: {vuln_counts['high']}")
        print(f"  {self.severity_colors['medium']} 中危: {vuln_counts['medium']}")
        print(f"  {self.severity_colors['low']} 低危: {vuln_counts['low']}")
        print("-" * 60)
        print(f"风险评分: {self._calculate_risk_score(task.vulnerabilities)}/100")
        print("=" * 60)
