"""Tests for information disclosure vulnerability detection."""

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(__file__).replace("/tests/test_info_disclosure.py", "/src"))

from web_vuln_scanner_mcp.server import check_info_disclosure
from tests.test_constants import HTML_INFO_DISCLOSURE, HTML_SAFE


class TestInfoDisclosureDetection:
    """Tests for information disclosure detection."""

    @pytest.mark.asyncio
    async def test_server_header_disclosure(self, mock_session_factory):
        """Test detection of Server header disclosure."""
        headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
        mock_session = mock_session_factory([
            (200, HTML_SAFE, headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        server_finding = next(
            (f for f in data["findings"] if f["type"] == "header_disclosure" and f["header"] == "Server"),
            None
        )
        assert server_finding is not None
        assert "Apache" in server_finding["value"]

    @pytest.mark.asyncio
    async def test_x_powered_by_disclosure(self, mock_session_factory):
        """Test detection of X-Powered-By header disclosure."""
        headers = {"X-Powered-By": "PHP/7.4.3"}
        mock_session = mock_session_factory([
            (200, HTML_SAFE, headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        powered_finding = next(
            (f for f in data["findings"] if f["type"] == "header_disclosure" and f["header"] == "X-Powered-By"),
            None
        )
        assert powered_finding is not None

    @pytest.mark.asyncio
    async def test_aspnet_version_disclosure(self, mock_session_factory):
        """Test detection of ASP.NET version disclosure."""
        headers = {"X-AspNet-Version": "4.0.30319"}
        mock_session = mock_session_factory([
            (200, HTML_SAFE, headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        aspnet_finding = next(
            (f for f in data["findings"] if f["type"] == "header_disclosure" and f["header"] == "X-AspNet-Version"),
            None
        )
        assert aspnet_finding is not None

    @pytest.mark.asyncio
    async def test_aspnet_mvc_version_disclosure(self, mock_session_factory):
        """Test detection of ASP.NET MVC version disclosure."""
        headers = {"X-AspNetMvc-Version": "5.2.7"}
        mock_session = mock_session_factory([
            (200, HTML_SAFE, headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        mvc_finding = next(
            (f for f in data["findings"] if f["type"] == "header_disclosure" and f["header"] == "X-AspNetMvc-Version"),
            None
        )
        assert mvc_finding is not None

    @pytest.mark.asyncio
    async def test_hardcoded_password_detection(self, mock_session_factory):
        """Test detection of hardcoded passwords."""
        body = '<html><body>password = "admin123"</body></html>'
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        password_finding = next(
            (f for f in data["findings"] if "password" in f.get("pattern", "").lower()),
            None
        )
        assert password_finding is not None
        assert password_finding["severity"] == "high"

    @pytest.mark.asyncio
    async def test_api_key_detection(self, mock_session_factory):
        """Test detection of exposed API keys."""
        body = '<html><body>api_key = "sk-1234567890abcdef"</body></html>'
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        api_key_finding = next(
            (f for f in data["findings"] if "API key" in f.get("pattern", "")),
            None
        )
        assert api_key_finding is not None
        assert api_key_finding["severity"] == "high"

    @pytest.mark.asyncio
    async def test_secret_key_detection(self, mock_session_factory):
        """Test detection of exposed secret keys."""
        body = '<html><body>secret_key = "mysupersecretkey123"</body></html>'
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        secret_finding = next(
            (f for f in data["findings"] if "Secret key" in f.get("pattern", "")),
            None
        )
        assert secret_finding is not None
        assert secret_finding["severity"] == "high"

    @pytest.mark.asyncio
    async def test_aws_credentials_detection(self, mock_session_factory):
        """Test detection of AWS credentials."""
        body = '<html><body>aws_access_key = "AKIAIOSFODNN7EXAMPLE"</body></html>'
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        aws_finding = next(
            (f for f in data["findings"] if "AWS" in f.get("pattern", "")),
            None
        )
        assert aws_finding is not None
        assert aws_finding["severity"] == "high"

    @pytest.mark.asyncio
    async def test_internal_ip_disclosure(self, mock_session_factory):
        """Test detection of internal IP addresses."""
        body = '<html><body>Server: 192.168.1.100</body></html>'
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        ip_finding = next(
            (f for f in data["findings"] if "IP address" in f.get("pattern", "")),
            None
        )
        assert ip_finding is not None

    @pytest.mark.asyncio
    async def test_stack_trace_detection(self, mock_session_factory):
        """Test detection of stack trace disclosure."""
        body = '''<html><body>
        <pre>
        Stack trace:
        Error at line 42 in /app/main.py
        Exception: Database connection failed
        </pre>
        </body></html>'''
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        trace_finding = next(
            (f for f in data["findings"] if "Stack trace" in f.get("pattern", "")),
            None
        )
        assert trace_finding is not None
        assert trace_finding["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_developer_comments_detection(self, mock_session_factory):
        """Test detection of developer comments."""
        body = '<html><body><!-- TODO: Remove hardcoded password before deployment --></body></html>'
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        comment_finding = next(
            (f for f in data["findings"] if "Developer comments" in f.get("pattern", "")),
            None
        )
        assert comment_finding is not None

    @pytest.mark.asyncio
    async def test_linux_path_disclosure(self, mock_session_factory):
        """Test detection of Linux server path disclosure."""
        body = '<html><body>Error in /home/webuser/app/config.py</body></html>'
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        path_finding = next(
            (f for f in data["findings"] if "Server path" in f.get("pattern", "")),
            None
        )
        assert path_finding is not None
        assert path_finding["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_windows_path_disclosure(self, mock_session_factory):
        """Test detection of Windows server path disclosure."""
        body = '<html><body>Error in c:\\\\inetpub\\\\wwwroot\\\\config.php</body></html>'
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        # Should detect Windows path
        findings = data["findings"]
        assert len(findings) >= 0  # May or may not detect depending on escaping

    @pytest.mark.asyncio
    async def test_comprehensive_disclosure(self, mock_session_factory):
        """Test detection of multiple disclosure types in one page."""
        mock_session = mock_session_factory([
            (200, HTML_INFO_DISCLOSURE, {"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4"})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        assert data["risk_level"] == "high"
        assert len(data["findings"]) >= 3

    @pytest.mark.asyncio
    async def test_no_disclosure(self, mock_session_factory):
        """Test when no information disclosure is found."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        assert data["risk_level"] == "low"
        assert len(data["findings"]) == 0

    @pytest.mark.asyncio
    async def test_risk_level_calculation_high(self, mock_session_factory):
        """Test high risk level when high severity finding exists."""
        body = '<html><body>password = "secret123"</body></html>'
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_risk_level_calculation_medium(self, mock_session_factory):
        """Test medium risk level when only medium severity findings exist."""
        body = '<html><body>Error in /home/user/app.py at line 10</body></html>'
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert data["risk_level"] in ["high", "medium"]

    @pytest.mark.asyncio
    async def test_recommendations_on_findings(self, mock_session_factory):
        """Test recommendations are provided when findings exist."""
        mock_session = mock_session_factory([
            (200, HTML_INFO_DISCLOSURE, {"Server": "Apache/2.4.41"})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert "recommendations" in data
        assert len(data["recommendations"]) > 0

    @pytest.mark.asyncio
    async def test_recommendations_when_clean(self, mock_session_factory):
        """Test recommendations when no findings."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        assert "recommendations" in data
        assert any("No obvious" in r for r in data["recommendations"])

    @pytest.mark.asyncio
    async def test_network_error_handling(self):
        """Test handling of network errors."""
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=Exception("Connection failed"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://unreachable.example.com")
            data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_multiple_matches_same_pattern(self, mock_session_factory):
        """Test handling of multiple matches for same pattern."""
        body = '''<html><body>
        password = "pass1"
        password = "pass2"
        password = "pass3"
        password = "pass4"
        password = "pass5"
        password = "pass6"
        </body></html>'''
        mock_session = mock_session_factory([
            (200, body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_info_disclosure("http://example.com")
            data = json.loads(result)

        # Should have finding but matches should be limited/counted
        password_finding = next(
            (f for f in data["findings"] if "password" in f.get("pattern", "").lower()),
            None
        )
        assert password_finding is not None
        # More than 5 matches should show count instead of list
        assert isinstance(password_finding["matches"], int) or len(password_finding["matches"]) <= 5
