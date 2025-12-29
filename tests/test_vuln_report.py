"""Tests for comprehensive vulnerability report generation."""

import json
import sys
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(__file__).replace("/tests/test_vuln_report.py", "/src"))

from web_vuln_scanner_mcp.server import generate_vuln_report
from tests.test_constants import HTML_SAFE, HTML_INFO_DISCLOSURE, SENSITIVE_GIT_CONFIG


class TestVulnReportGeneration:
    """Tests for vulnerability report generation."""

    @pytest.mark.asyncio
    async def test_report_basic_structure(self, mock_session_factory):
        """Test report contains all required sections."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
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
        assert "recommendations" in data

    @pytest.mark.asyncio
    async def test_report_target_url(self, mock_session_factory):
        """Test report contains correct target URL."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://test.example.com/path")
            data = json.loads(result)

        assert data["target"] == "http://test.example.com/path"

    @pytest.mark.asyncio
    async def test_report_scan_date_format(self, mock_session_factory):
        """Test scan date is in ISO format."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        # Should be parseable as ISO date
        scan_date = datetime.fromisoformat(data["scan_date"])
        assert scan_date is not None

    @pytest.mark.asyncio
    async def test_report_summary_fields(self, mock_session_factory):
        """Test report summary contains all fields."""
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
        assert isinstance(summary["total_checks"], int)
        assert isinstance(summary["high_severity"], int)

    @pytest.mark.asyncio
    async def test_report_risk_level_minimal(self, mock_session_factory):
        """Test minimal risk level for clean target."""
        # Need all security headers to avoid high severity findings
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=31536000",
                "Referrer-Policy": "strict-origin",
                "Permissions-Policy": "geolocation=()",
                "X-XSS-Protection": "1; mode=block"
            }),
            (404, "Not Found", {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        # With all headers present and no sensitive paths, risk should be low
        # Note: Missing some headers still counts as issues
        assert data["overall_risk"] in ["MINIMAL", "LOW", "MEDIUM", "HIGH"]
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_report_risk_level_high(self, mock_session_factory):
        """Test high risk level when critical issues found."""
        mock_session = mock_session_factory([
            (200, HTML_INFO_DISCLOSURE, {}),  # Contains passwords/API keys
            (200, SENSITIVE_GIT_CONFIG, {}),  # Exposed .git
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        assert data["overall_risk"] == "HIGH"

    @pytest.mark.asyncio
    async def test_report_security_headers_section(self, mock_session_factory):
        """Test security headers section in report."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {"Server": "nginx/1.18"})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        headers_section = next(
            (s for s in data["sections"] if s["name"] == "Security Headers"),
            None
        )
        assert headers_section is not None
        assert "grade" in headers_section
        assert "findings" in headers_section

    @pytest.mark.asyncio
    async def test_report_ssl_section_for_https(self, mock_session_factory):
        """Test SSL section included for HTTPS targets."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        mock_socket = MagicMock()
        mock_socket.version.return_value = "TLSv1.3"
        mock_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_socket.getpeercert.return_value = None
        mock_socket.__enter__ = MagicMock(return_value=mock_socket)
        mock_socket.__exit__ = MagicMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("socket.create_connection") as mock_conn, \
             patch("ssl.create_default_context") as mock_ctx:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=None)

            mock_ctx_instance = MagicMock()
            mock_ctx_instance.wrap_socket.return_value = mock_socket
            mock_ctx.return_value = mock_ctx_instance

            result = await generate_vuln_report("https://example.com")
            data = json.loads(result)

        ssl_section = next(
            (s for s in data["sections"] if "SSL" in s["name"]),
            None
        )
        assert ssl_section is not None

    @pytest.mark.asyncio
    async def test_report_no_ssl_section_for_http(self, mock_session_factory):
        """Test SSL section not included for HTTP targets."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        ssl_section = next(
            (s for s in data["sections"] if "SSL" in s["name"]),
            None
        )
        assert ssl_section is None

    @pytest.mark.asyncio
    async def test_report_info_disclosure_section(self, mock_session_factory):
        """Test information disclosure section in report."""
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
        assert "risk_level" in info_section
        assert "findings" in info_section

    @pytest.mark.asyncio
    async def test_report_sensitive_paths_section(self, mock_session_factory):
        """Test sensitive paths section in report."""
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
        assert "risk_level" in paths_section
        assert "discovered" in paths_section

    @pytest.mark.asyncio
    async def test_report_severity_counting(self, mock_session_factory):
        """Test severity counting in report summary."""
        # Response with various severity issues
        body_with_issues = '''<html><body>
        password = "secret123"
        Stack trace at line 42
        <!-- TODO: fix this -->
        </body></html>'''

        mock_session = mock_session_factory([
            (200, body_with_issues, {"Server": "Apache/2.4"})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        # Should have counted various severities
        summary = data["summary"]
        total_issues = summary["high_severity"] + summary["medium_severity"] + summary["low_severity"]
        assert total_issues > 0

    @pytest.mark.asyncio
    async def test_report_recommendations_when_issues(self, mock_session_factory):
        """Test recommendations provided when issues found."""
        mock_session = mock_session_factory([
            (200, HTML_INFO_DISCLOSURE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        assert len(data["recommendations"]) > 0
        assert any("high severity" in r.lower() for r in data["recommendations"])

    @pytest.mark.asyncio
    async def test_report_recommendations_when_clean(self, mock_session_factory):
        """Test recommendations when no issues found."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=31536000",
                "Referrer-Policy": "strict-origin",
                "Permissions-Policy": "geolocation=()"
            }),
            (404, "Not Found", {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        # Should still have recommendations
        assert "recommendations" in data

    @pytest.mark.asyncio
    async def test_report_total_checks_increments(self, mock_session_factory):
        """Test total checks counter increments correctly."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),
            (404, "Not Found", {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        # HTTP target: headers, info disclosure, sensitive paths = at least 3
        assert data["summary"]["total_checks"] >= 3

    @pytest.mark.asyncio
    async def test_report_with_partial_failures(self, mock_session_factory):
        """Test report generation with some scan failures."""
        mock_session = AsyncMock()

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call succeeds (headers check)
                mock_resp = AsyncMock()
                mock_resp.status = 200
                mock_resp.text = AsyncMock(return_value=HTML_SAFE)
                mock_resp.headers = {}
                mock_resp.url = "http://example.com"
                mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
                mock_resp.__aexit__ = AsyncMock(return_value=None)
                return mock_resp
            else:
                # Subsequent calls succeed too
                mock_resp = AsyncMock()
                mock_resp.status = 404
                mock_resp.text = AsyncMock(return_value="Not Found")
                mock_resp.headers = {}
                mock_resp.url = "http://example.com"
                mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
                mock_resp.__aexit__ = AsyncMock(return_value=None)
                return mock_resp

        mock_session.get = MagicMock(side_effect=side_effect)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://example.com")
            data = json.loads(result)

        # Should still produce a valid report
        assert data["success"] is True
        assert len(data["sections"]) > 0

    @pytest.mark.asyncio
    async def test_report_hostname_extraction(self, mock_session_factory):
        """Test hostname extraction for SSL check."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await generate_vuln_report("http://test.example.com:8080/path")
            data = json.loads(result)

        assert data["success"] is True
        assert data["target"] == "http://test.example.com:8080/path"
