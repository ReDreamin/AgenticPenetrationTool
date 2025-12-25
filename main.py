#!/usr/bin/env python3
"""
WuTong (梧桐) - 智能渗透测试工具
命令行入口
"""
import asyncio
import argparse
import sys
import os
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.prompt import Prompt
from rich.table import Table

from core.orchestrator import Orchestrator
from core.reporter import Reporter
from core.task_manager import TaskManager


console = Console()

BANNER = """
██╗    ██╗██╗   ██╗████████╗ ██████╗ ███╗   ██╗ ██████╗
██║    ██║██║   ██║╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
██║ █╗ ██║██║   ██║   ██║   ██║   ██║██╔██╗ ██║██║  ███╗
██║███╗██║██║   ██║   ██║   ██║   ██║██║╚██╗██║██║   ██║
╚███╔███╔╝╚██████╔╝   ██║   ╚██████╔╝██║ ╚████║╚██████╔╝
 ╚══╝╚══╝  ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝

    智能渗透测试工具 v0.1.0
    Powered by Claude AI
"""

HELP_TEXT = """
可用命令:
  scan <target>     - 对目标进行完整渗透测试
  recon <target>    - 仅进行信息收集
  vuln <target>     - 仅进行漏洞扫描
  chat              - 进入交互对话模式
  report            - 生成当前任务报告
  status            - 查看当前任务状态
  tools             - 列出所有可用工具
  mode              - 切换详细/简洁模式
  save [name]       - 保存当前对话
  resume            - 恢复已保存的对话
  clear             - 清空对话历史
  help              - 显示帮助信息
  exit/quit         - 退出程序

示例:
  scan 192.168.1.100
  save dvwa_test
  resume
"""


async def run_scan(orchestrator: Orchestrator, target: str, task_type: str = "full"):
    """运行扫描任务"""
    try:
        result = await orchestrator.run_task(target, task_type)
        return result
    except Exception as e:
        console.print(f"[red]扫描出错: {str(e)}[/red]")
        return None


async def interactive_chat(orchestrator: Orchestrator):
    """交互式对话模式"""
    console.print("\n[cyan]进入交互对话模式[/cyan]")
    console.print("[dim]输入 'exit' 或 'quit' 退出对话模式[/dim]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold green]You[/bold green]")

            if user_input.lower() in ['exit', 'quit', 'q']:
                console.print("[cyan]退出对话模式[/cyan]")
                break

            if not user_input.strip():
                continue

            console.print()
            with console.status("[bold blue]AI 思考中...[/bold blue]"):
                response = await orchestrator.chat(user_input)

            console.print(Panel(
                Markdown(response),
                title="[bold blue]AI[/bold blue]",
                border_style="blue"
            ))

        except KeyboardInterrupt:
            console.print("\n[cyan]退出对话模式[/cyan]")
            break


def show_tools(orchestrator: Orchestrator):
    """显示可用工具"""
    categories = orchestrator.list_tools()

    table = Table(title="可用渗透测试工具")
    table.add_column("类别", style="cyan")
    table.add_column("工具", style="green")

    category_names = {
        "http": "HTTP 工具",
        "scan": "扫描工具",
        "exploit": "漏洞利用",
        "utils": "辅助工具"
    }

    for category, tools in categories.items():
        name = category_names.get(category, category)
        table.add_row(name, ", ".join(tools))

    console.print(table)


def show_status(orchestrator: Orchestrator):
    """显示任务状态"""
    summary = orchestrator.get_task_summary()

    if not summary:
        console.print("[yellow]当前没有活动任务[/yellow]")
        return

    table = Table(title="任务状态")
    table.add_column("属性", style="cyan")
    table.add_column("值", style="green")

    table.add_row("任务 ID", summary.get("task_id", "-"))
    table.add_row("目标", summary.get("target", "-"))
    table.add_row("状态", summary.get("status", "-"))
    table.add_row("阶段", summary.get("phase", "-"))
    table.add_row("开放端口", str(summary.get("open_ports_count", 0)))
    table.add_row("发现路径", str(summary.get("discovered_paths_count", 0)))
    table.add_row("发现漏洞", str(summary.get("vulnerabilities_count", 0)))
    table.add_row("工具调用", str(summary.get("tool_calls_count", 0)))

    console.print(table)

    # 漏洞统计
    vuln_by_severity = summary.get("vulnerabilities_by_severity", {})
    if any(vuln_by_severity.values()):
        console.print("\n[bold]漏洞统计:[/bold]")
        console.print(f"  🔴 严重: {vuln_by_severity.get('critical', 0)}")
        console.print(f"  🟠 高危: {vuln_by_severity.get('high', 0)}")
        console.print(f"  🟡 中危: {vuln_by_severity.get('medium', 0)}")
        console.print(f"  🔵 低危: {vuln_by_severity.get('low', 0)}")


def generate_report(orchestrator: Orchestrator, output_file: str = None):
    """生成报告"""
    task = orchestrator.task_manager.get_current_task()

    if not task:
        console.print("[yellow]没有可生成报告的任务[/yellow]")
        return

    reporter = Reporter()
    report = reporter.generate_markdown_report(task)

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        console.print(f"[green]报告已保存到: {output_file}[/green]")
    else:
        # 默认文件名
        filename = f"report_{task.target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        console.print(f"[green]报告已保存到: {filename}[/green]")

    # 打印摘要
    reporter.print_summary(task)


async def main_loop(orchestrator: Orchestrator):
    """主交互循环"""
    console.print(BANNER, style="bold cyan")
    console.print("[dim]输入 'help' 查看可用命令[/dim]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold magenta]WuTong[/bold magenta]").strip()

            if not user_input:
                continue

            parts = user_input.split(maxsplit=1)
            command = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            if command in ['exit', 'quit', 'q']:
                console.print("[cyan]再见![/cyan]")
                break

            elif command == 'help':
                console.print(HELP_TEXT)

            elif command == 'scan':
                if not args:
                    console.print("[red]请指定目标，例如: scan 192.168.1.100[/red]")
                    continue
                await run_scan(orchestrator, args, "full")

            elif command == 'recon':
                if not args:
                    console.print("[red]请指定目标[/red]")
                    continue
                await run_scan(orchestrator, args, "recon")

            elif command == 'vuln':
                if not args:
                    console.print("[red]请指定目标[/red]")
                    continue
                await run_scan(orchestrator, args, "vuln_scan")

            elif command == 'chat':
                await interactive_chat(orchestrator)

            elif command == 'tools':
                show_tools(orchestrator)

            elif command == 'status':
                show_status(orchestrator)

            elif command == 'report':
                generate_report(orchestrator, args if args else None)

            elif command == 'clear':
                orchestrator.clear_chat_history()
                console.print("[green]对话历史已清空[/green]")

            elif command == 'mode':
                # 切换输出模式
                orchestrator.set_detailed_mode(not orchestrator.detailed_mode)

            elif command == 'save':
                # 保存当前对话
                name = args.strip() if args else None
                orchestrator.save_session(name)

            elif command == 'resume':
                # 恢复已保存的对话
                sessions = orchestrator.list_sessions()
                if not sessions:
                    console.print("[yellow]没有已保存的对话[/yellow]")
                    continue

                # 显示会话列表
                console.print("\n[bold]已保存的对话:[/bold]")
                table = Table(show_header=True)
                table.add_column("#", style="cyan", width=4)
                table.add_column("文件名", style="green")
                table.add_column("保存时间", style="dim")
                table.add_column("消息数", justify="right")
                table.add_column("目标", style="yellow")

                for i, session in enumerate(sessions, 1):
                    target = session.get("task", {}).get("target", "-") if session.get("task") else "-"
                    saved_at = session.get("saved_at", "未知")
                    if saved_at != "未知":
                        # 简化时间显示
                        try:
                            saved_at = saved_at.split("T")[0] + " " + saved_at.split("T")[1][:8]
                        except Exception:
                            pass
                    table.add_row(
                        str(i),
                        session.get("filename", ""),
                        saved_at,
                        str(session.get("message_count", 0)),
                        target
                    )

                console.print(table)

                # 让用户选择
                choice = Prompt.ask("\n选择要恢复的对话编号 (输入 0 取消)")
                try:
                    idx = int(choice)
                    if idx == 0:
                        console.print("[dim]已取消[/dim]")
                    elif 1 <= idx <= len(sessions):
                        filepath = sessions[idx - 1]["filepath"]
                        orchestrator.load_session(filepath)
                    else:
                        console.print("[red]无效的编号[/red]")
                except ValueError:
                    console.print("[red]请输入数字[/red]")

            else:
                # 尝试作为自然语言指令处理
                console.print(f"\n[dim]将 '{user_input}' 作为自然语言指令处理...[/dim]\n")
                with console.status("[bold blue]AI 处理中...[/bold blue]"):
                    response = await orchestrator.chat(user_input)
                console.print(Panel(
                    Markdown(response),
                    title="[bold blue]AI[/bold blue]",
                    border_style="blue"
                ))

        except KeyboardInterrupt:
            console.print("\n[yellow]使用 'exit' 命令退出程序[/yellow]")
        except Exception as e:
            console.print(f"[red]错误: {str(e)}[/red]")


async def run_single_task(target: str, task_type: str, output: str = None, api_key: str = None, proxy: str = None):
    """运行单个任务（非交互模式）"""
    orchestrator = Orchestrator(api_key=api_key, proxy=proxy)

    console.print(BANNER, style="bold cyan")

    result = await run_scan(orchestrator, target, task_type)

    if result and output:
        generate_report(orchestrator, output)

    return result


def main():
    """主入口"""
    parser = argparse.ArgumentParser(
        description="WuTong - 智能渗透测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py                          # 交互模式
  python main.py -t 192.168.1.100         # 扫描目标
  python main.py -t target.com --recon    # 仅信息收集
  python main.py -t target.com -o report.md  # 输出报告
        """
    )

    parser.add_argument(
        '-t', '--target',
        help='目标地址 (IP 或 URL)'
    )

    parser.add_argument(
        '--recon',
        action='store_true',
        help='仅进行信息收集'
    )

    parser.add_argument(
        '--vuln',
        action='store_true',
        help='仅进行漏洞扫描'
    )

    parser.add_argument(
        '-o', '--output',
        help='报告输出文件路径'
    )

    parser.add_argument(
        '--api-key',
        help='Anthropic API Key (或设置 ANTHROPIC_API_KEY 环境变量)'
    )

    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='静默模式，减少输出'
    )

    parser.add_argument(
        '--proxy',
        help='HTTP 代理地址 (如 http://127.0.0.1:7890)'
    )

    parser.add_argument(
        '--base-url',
        help='自定义 API 端点 (用于 API 转发服务)'
    )

    args = parser.parse_args()

    # 确定任务类型
    if args.recon:
        task_type = "recon"
    elif args.vuln:
        task_type = "vuln_scan"
    else:
        task_type = "full"

    # 如果指定了 base_url，设置到 config
    if args.base_url:
        import config as cfg
        cfg.ANTHROPIC_BASE_URL = args.base_url

    try:
        if args.target:
            # 非交互模式：直接执行任务
            asyncio.run(run_single_task(
                args.target,
                task_type,
                args.output,
                args.api_key,
                args.proxy
            ))
        else:
            # 交互模式
            orchestrator = Orchestrator(api_key=args.api_key, verbose=not args.quiet, proxy=args.proxy)
            asyncio.run(main_loop(orchestrator))

    except KeyboardInterrupt:
        console.print("\n[cyan]程序已退出[/cyan]")
    except ValueError as e:
        console.print(f"[red]配置错误: {str(e)}[/red]")
        console.print("[yellow]请设置 ANTHROPIC_API_KEY 环境变量或使用 --api-key 参数[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]程序错误: {str(e)}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
