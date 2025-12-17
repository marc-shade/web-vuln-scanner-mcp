# Web Vulnerability Scanner MCP Server

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![Python-3.10+](https://img.shields.io/badge/Python-3.10%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Part of Agentic System](https://img.shields.io/badge/Part_of-Agentic_System-brightgreen)](https://github.com/marc-shade/agentic-system-oss)

> **Web application vulnerability scanning and security testing.**

Part of the [Agentic System](https://github.com/marc-shade/agentic-system-oss) - a 24/7 autonomous AI framework with persistent memory.

OWASP Top 10 vulnerability detection for web applications.

## Features

- **SQL Injection Detection**: Test for SQLi vulnerabilities
- **XSS Detection**: Cross-Site Scripting checks
- **Security Headers Analysis**: Check for missing security headers
- **SSL/TLS Analysis**: Certificate and configuration checks
- **Directory Traversal**: Path traversal vulnerability testing
- **Information Disclosure**: Sensitive data exposure checks
- **CSRF Detection**: Cross-Site Request Forgery analysis

## Tools

| Tool | Description |
|------|-------------|
| `analyze_security_headers` | Check HTTP security headers |
| `check_ssl_config` | Analyze SSL/TLS configuration |
| `test_sqli_params` | Test URL parameters for SQL injection |
| `test_xss_reflection` | Test for reflected XSS |
| `scan_directories` | Find hidden directories and files |
| `check_info_disclosure` | Find information leakage |
| `generate_vuln_report` | Comprehensive vulnerability report |

## Security Headers Checked

- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Strict-Transport-Security (HSTS)
- Referrer-Policy
- Permissions-Policy

## IMPORTANT: Authorized Use Only

This tool is for **authorized security testing only**:
- Only scan systems you own or have explicit permission to test
- Do not use against production systems without approval
- Follow responsible disclosure practices
---

## Part of the MCP Ecosystem

This server integrates with other MCP servers for comprehensive AGI capabilities:

| Server | Purpose |
|--------|---------|
| [enhanced-memory-mcp](https://github.com/marc-shade/enhanced-memory-mcp) | 4-tier persistent memory with semantic search |
| [agent-runtime-mcp](https://github.com/marc-shade/agent-runtime-mcp) | Persistent task queues and goal decomposition |
| [agi-mcp](https://github.com/marc-shade/agi-mcp) | Full AGI orchestration with 21 tools |
| [cluster-execution-mcp](https://github.com/marc-shade/cluster-execution-mcp) | Distributed task routing across nodes |
| [node-chat-mcp](https://github.com/marc-shade/node-chat-mcp) | Inter-node AI communication |
| [ember-mcp](https://github.com/marc-shade/ember-mcp) | Production-only policy enforcement |

See [agentic-system-oss](https://github.com/marc-shade/agentic-system-oss) for the complete framework.
