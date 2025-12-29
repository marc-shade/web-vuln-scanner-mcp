"""Tests for MCP server endpoints and tool registration."""

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(__file__).replace("/tests/test_mcp_server.py", "/src"))

from web_vuln_scanner_mcp.server import (
    mcp,
    analyze_security_headers,
    check_ssl_config,
    test_sqli_params,
    test_xss_reflection,
    scan_sensitive_paths,
    check_info_disclosure,
    generate_vuln_report,
)
from tests.test_constants import HTML_SAFE


class TestMcpServerSetup:
    """Tests for MCP server configuration."""

    def test_mcp_server_name(self):
        """Test MCP server has correct name."""
        assert mcp.name == "web-vuln-scanner"

    def test_mcp_server_exists(self):
        """Test MCP server instance exists."""
        assert mcp is not None


class TestToolEndpoints:
    """Tests for MCP tool endpoint functionality."""

    @pytest.mark.asyncio
    async def test_analyze_security_headers_returns_json(self, mock_session_factory):
        """Test analyze_security_headers returns valid JSON."""
        mock_session = mock_session_factory([(200, HTML_SAFE, {})])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("http://example.com")
            data = json.loads(result)

        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_check_ssl_config_returns_json(self):
        """Test check_ssl_config returns valid JSON."""
        mock_socket = MagicMock()
        mock_socket.version.return_value = "TLSv1.3"
        mock_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_socket.getpeercert.return_value = None
        mock_socket.__enter__ = MagicMock(return_value=mock_socket)
        mock_socket.__exit__ = MagicMock(return_value=None)

        with patch("socket.create_connection") as mock_conn, \
             patch("ssl.create_default_context") as mock_ctx:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=None)

            mock_ctx_instance = MagicMock()
            mock_ctx_instance.wrap_socket.return_value = mock_socket
            mock_ctx.return_value = mock_ctx_instance

            result = await check_ssl_config("example.com")
            data = json.loads(result)

        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_test_sqli_params_returns_json(self, mock_session_factory):
        """Test test_sqli_params returns valid JSON."""
        mock_session = mock_session_factory([(200, HTML_SAFE, {})] * 20)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_test_xss_reflection_returns_json(self, mock_session_factory):
        """Test test_xss_reflection returns valid JSON."""
        mock_session = mock_session_factory([(200, HTML_SAFE, {})] * 20)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_scan_sensitive_paths_returns_json(self, mock_session_factory):
        """Test scan_sensitive_paths returns valid JSON."""
        mock_session = mock_session_factory([(404, "Not Found", {})] * 20)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_check_info_disclosure_returns_json(self, mock_session_factory):
        """Test check_info_disclosure returns valid JSON."""
        mock_session = mock_session_factory([(200, HTML_SAFE, {})])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_generate_vuln_report_returns_json(self, mock_session_factory):
        """Test generate_vuln_report returns valid JSON."""
        mock_session = mock_session_factory([(200, HTML_SAFE, {})] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        assert isinstance(data, dict)
        assert "success" in data


class TestToolErrorHandling:
    """Tests for error handling in tools."""

    @pytest.mark.asyncio
    async def test_security_headers_network_error(self):
        """Test graceful handling of network error."""
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=Exception("Connection refused"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("http://unreachable.example.com")
            data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_sqli_no_params_error(self):
        """Test SQLi with no parameters returns error."""
        result = await test_sqli_params("http://example.com/page")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_xss_no_params_error(self):
        """Test XSS with no parameters returns error."""
        result = await test_xss_reflection("http://example.com/page")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data


class TestToolIntegration:
    """Integration tests for tool workflows."""

    @pytest.mark.asyncio
    async def test_full_vuln_report_workflow(self, mock_session_factory):
        """Test complete vulnerability report generation."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {"X-Content-Type-Options": "nosniff"})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        assert "target" in data
        assert "scan_date" in data
        assert "summary" in data
        assert "sections" in data
        assert "overall_risk" in data

    @pytest.mark.asyncio
    async def test_vuln_report_includes_headers_section(self, mock_session_factory):
        """Test vulnerability report includes security headers section."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        headers_section = next(
            (s for s in data["sections"] if s["name"] == "Security Headers"),
            None
        )
        assert headers_section is not None

    @pytest.mark.asyncio
    async def test_vuln_report_includes_info_disclosure_section(self, mock_session_factory):
        """Test vulnerability report includes info disclosure section."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        info_section = next(
            (s for s in data["sections"] if s["name"] == "Information Disclosure"),
            None
        )
        assert info_section is not None

    @pytest.mark.asyncio
    async def test_vuln_report_includes_sensitive_paths_section(self, mock_session_factory):
        """Test vulnerability report includes sensitive paths section."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),
            (404, "Not Found", {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        paths_section = next(
            (s for s in data["sections"] if s["name"] == "Sensitive Paths"),
            None
        )
        assert paths_section is not None

    @pytest.mark.asyncio
    async def test_vuln_report_summary_counts(self, mock_session_factory):
        """Test vulnerability report contains severity counts."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        summary = data["summary"]
        assert "total_checks" in summary
        assert "high_severity" in summary
        assert "medium_severity" in summary
        assert "low_severity" in summary

    @pytest.mark.asyncio
    async def test_vuln_report_risk_level_high(self, mock_session_factory):
        """Test high risk level in vulnerability report."""
        # Response with exposed password
        body = '<html><body>password = "admin123"</body></html>'
        mock_session = mock_session_factory([
            (200, body, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        assert data["overall_risk"] == "HIGH"

    @pytest.mark.asyncio
    async def test_vuln_report_recommendations(self, mock_session_factory):
        """Test vulnerability report includes recommendations."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        assert "recommendations" in data


class TestOutputFormatConsistency:
    """Tests for consistent output formatting."""

    @pytest.mark.asyncio
    async def test_all_tools_return_success_field(self, mock_session_factory):
        """Test all tools include success field in response."""
        mock_session = mock_session_factory([(200, HTML_SAFE, {})] * 100)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            tools = [
                analyze_security_headers("http://example.com"),
                test_sqli_params("http://example.com/page?id=1"),
                test_xss_reflection("http://example.com/search?q=test"),
                scan_sensitive_paths("http://example.com"),
                check_info_disclosure("http://example.com"),
                generate_vuln_report("http://example.com"),
            ]

            for tool_coro in tools:
                result = await tool_coro
                data = json.loads(result)
                assert "success" in data, f"Missing 'success' field in {result[:100]}"

    @pytest.mark.asyncio
    async def test_json_output_is_indented(self, mock_session_factory):
        """Test JSON output is formatted with indentation."""
        mock_session = mock_session_factory([(200, HTML_SAFE, {})])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("http://example.com")

        # Indented JSON should have newlines
        assert "\n" in result
        # Should be parseable
        json.loads(result)

    @pytest.mark.asyncio
    async def test_error_responses_consistent_format(self):
        """Test error responses have consistent format."""
        # Test no params error
        result1 = await test_sqli_params("http://example.com/page")
        data1 = json.loads(result1)
        assert data1["success"] is False
        assert "error" in data1

        result2 = await test_xss_reflection("http://example.com/page")
        data2 = json.loads(result2)
        assert data2["success"] is False
        assert "error" in data2
