# WuTong (梧桐)

智能化安全渗透测试工具，基于大语言模型 (Claude) 驱动，支持自然语言交互的自动化渗透测试平台。

## 功能特性

- **自然语言交互**：通过对话方式下达渗透测试指令，无需记忆复杂命令
- **任务智能分解**：自动将测试目标分解为信息收集、漏洞检测、漏洞利用等阶段
- **攻击路径规划**：AI 根据收集的信息智能决策下一步行动
- **工具自动调度**：根据目标情况自动选择合适的渗透测试工具
- **实时过程展示**：显示任务执行过程、工具调用日志、漏洞发现详情
- **报告自动生成**：测试完成后自动生成 Markdown 格式的专业报告

## 架构设计

```
┌─────────────────────────────────────────────────────────┐
│                    命令行交互层 (CLI)                    │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                   LLM 编排层 (Orchestrator)              │
│   - 自然语言理解          - 任务分解与规划                │
│   - 工具调度              - 结果分析与决策                │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                     MCP Tool 层                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ HTTP工具  │ │ 扫描工具  │ │ 漏洞利用  │ │ 辅助工具  │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
└─────────────────────────────────────────────────────────┘
```

## 安装

### 环境要求

- Python 3.9+
- Anthropic API Key

### 安装步骤

```bash
# 克隆项目
git clone https://github.com/your-repo/WuTong.git
cd WuTong

# 安装依赖
pip install -r requirements.txt

# 设置 API Key
export ANTHROPIC_API_KEY="your-api-key"
```

## 使用方法

### 交互模式

```bash
python main.py
```

进入交互模式后，可以使用以下命令：

| 命令 | 说明 |
|------|------|
| `scan <target>` | 对目标进行完整渗透测试 |
| `recon <target>` | 仅进行信息收集 |
| `vuln <target>` | 仅进行漏洞扫描 |
| `chat` | 进入对话模式 |
| `report` | 生成测试报告 |
| `status` | 查看当前任务状态 |
| `tools` | 列出所有可用工具 |
| `help` | 显示帮助信息 |

### 命令行模式

```bash
# 完整渗透测试
python main.py -t 192.168.1.100

# 仅信息收集
python main.py -t target.com --recon

# 仅漏洞扫描
python main.py -t target.com --vuln

# 输出报告到指定文件
python main.py -t target.com -o report.md
```

### 自然语言交互示例

```
WuTong> 帮我对 192.168.1.100 进行安全测试，重点检查 SQL 注入和 XSS 漏洞

WuTong> 扫描目标的开放端口，识别运行的服务

WuTong> 对登录页面进行 SQL 注入测试
```

## 内置工具

### HTTP 工具
| 工具名 | 功能描述 |
|--------|----------|
| `http_request` | 发送 HTTP 请求 |
| `dir_bruteforce` | 目录爆破 |
| `grab_banner` | 获取服务器 Banner |
| `crawl_links` | 爬取页面链接和表单 |

### 扫描工具
| 工具名 | 功能描述 |
|--------|----------|
| `port_scan` | 端口扫描 |
| `nmap_scan` | Nmap 高级扫描 |
| `subdomain_enum` | 子域名枚举 |

### 漏洞检测工具
| 工具名 | 功能描述 |
|--------|----------|
| `sql_injection_test` | SQL 注入检测 |
| `xss_test` | XSS 跨站脚本检测 |
| `lfi_test` | 本地文件包含检测 |
| `command_injection_test` | 命令注入检测 |
| `generate_payload` | 生成漏洞利用 Payload |

### 辅助工具
| 工具名 | 功能描述 |
|--------|----------|
| `dns_lookup` | DNS 查询 |
| `encode_payload` | Payload 编码 |
| `decode_payload` | Payload 解码 |
| `analyze_headers` | HTTP 安全头分析 |
| `check_waf` | WAF 检测 |

## 项目结构

```
WuTong/
├── main.py                     # CLI 入口
├── config.py                   # 配置文件
├── requirements.txt            # 项目依赖
├── core/
│   ├── orchestrator.py         # LLM 编排器
│   ├── task_manager.py         # 任务管理器
│   └── reporter.py             # 报告生成器
├── mcp_server/
│   ├── server.py               # MCP 工具服务器
│   └── tools/
│       ├── http_tools.py       # HTTP 请求工具
│       ├── scan_tools.py       # 扫描工具
│       ├── exploit_tools.py    # 漏洞利用工具
│       └── utils_tools.py      # 辅助工具
└── prompts/
    └── system_prompt.py        # 系统提示词
```

## 免责声明

本工具仅用于授权的安全测试和研究目的。使用本工具进行任何未经授权的测试均属违法行为。使用者需自行承担所有法律责任。

**请确保：**
- 仅对自己拥有或获得明确授权的系统进行测试
- 遵守当地法律法规
- 在隔离的测试环境中使用

## 许可证

MIT License
