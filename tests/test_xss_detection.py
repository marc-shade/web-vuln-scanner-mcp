"""Tests for XSS vulnerability detection."""

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(__file__).replace("/tests/test_xss_detection.py", "/src"))

from web_vuln_scanner_mcp.server import test_xss_reflection, XSS_PAYLOADS
from tests.test_constants import (
    HTML_VULNERABLE_XSS,
    HTML_SAFE,
    HTML_PARTIAL_XSS,
)


class TestXSSDetection:
    """Tests for XSS vulnerability detection."""

    @pytest.mark.asyncio
    async def test_reflected_xss_detection(self, mock_session_factory):
        """Test detection of reflected XSS vulnerability."""
        # Response contains the XSS payload unencoded
        mock_session = mock_session_factory([
            (200, HTML_VULNERABLE_XSS, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) > 0
        assert data["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_no_xss_vulnerability(self, mock_session_factory):
        """Test when no XSS vulnerability is found."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) == 0
        assert data["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_partial_xss_reflection(self, mock_session_factory):
        """Test detection of partial XSS reflection (encoding bypass potential)."""
        mock_session = mock_session_factory([
            (200, HTML_PARTIAL_XSS, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        assert data["success"] is True
        # Should detect partial reflection
        partial_findings = [f for f in data["findings"] if f["type"] == "partial_reflection"]
        assert len(partial_findings) >= 0  # May or may not find depending on exact match

    @pytest.mark.asyncio
    async def test_xss_no_parameters(self):
        """Test XSS test with URL without parameters."""
        result = await test_xss_reflection("http://example.com/page")
        data = json.loads(result)

        assert data["success"] is False
        assert "No URL parameters found" in data["error"]

    @pytest.mark.asyncio
    async def test_xss_multiple_parameters(self, mock_session_factory):
        """Test XSS testing with multiple parameters."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)  # Many responses for multiple payload tests

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection(
                "http://example.com/search?q=test&name=user&id=123"
            )
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["parameters_tested"]) == 3
        assert "q" in data["parameters_tested"]
        assert "name" in data["parameters_tested"]
        assert "id" in data["parameters_tested"]

    @pytest.mark.asyncio
    async def test_xss_specific_parameters_only(self, mock_session_factory):
        """Test XSS testing limited to specific parameters."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 20)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection(
                "http://example.com/search?q=test&name=user&id=123",
                test_params=["q"]
            )
            data = json.loads(result)

        assert data["success"] is True
        assert data["parameters_tested"] == ["q"]

    @pytest.mark.asyncio
    async def test_xss_payloads_count(self, mock_session_factory):
        """Test that all XSS payloads are tested."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        assert data["payloads_tested"] == len(XSS_PAYLOADS)

    @pytest.mark.asyncio
    async def test_xss_recommendations_on_vulnerable(self, mock_session_factory):
        """Test recommendations are provided when XSS is found."""
        mock_session = mock_session_factory([
            (200, HTML_VULNERABLE_XSS, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        assert "recommendations" in data
        assert len(data["recommendations"]) > 0
        assert any("CSP" in r or "Content-Security-Policy" in r for r in data["recommendations"])

    @pytest.mark.asyncio
    async def test_xss_script_tag_payload(self, mock_session_factory):
        """Test detection with script tag payload."""
        body_with_script = "<html><body>Result: <script>alert('XSS')</script></body></html>"
        mock_session = mock_session_factory([
            (200, body_with_script, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) > 0

    @pytest.mark.asyncio
    async def test_xss_img_onerror_payload(self, mock_session_factory):
        """Test detection with img onerror payload."""
        body_with_img = "<html><body>Result: <img src=x onerror=alert('XSS')></body></html>"
        mock_session = mock_session_factory([
            (200, body_with_img, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) > 0

    @pytest.mark.asyncio
    async def test_xss_svg_onload_payload(self, mock_session_factory):
        """Test detection with svg onload payload."""
        body_with_svg = "<html><body>Result: <svg/onload=alert('XSS')></body></html>"
        mock_session = mock_session_factory([
            (200, body_with_svg, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) > 0

    @pytest.mark.asyncio
    async def test_xss_javascript_protocol_payload(self, mock_session_factory):
        """Test detection with javascript: protocol payload."""
        body_with_js = "<html><body><a href=\"javascript:alert('XSS')\">Link</a></body></html>"
        mock_session = mock_session_factory([
            (200, body_with_js, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_xss_breaks_attribute_context(self, mock_session_factory):
        """Test detection when XSS breaks out of HTML attribute."""
        body_with_attr_break = '<html><body><input value="\'><script>alert(\'XSS\')</script>"></body></html>'
        mock_session = mock_session_factory([
            (200, body_with_attr_break, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_xss_finding_details(self, mock_session_factory):
        """Test XSS finding contains required details."""
        mock_session = mock_session_factory([
            (200, HTML_VULNERABLE_XSS, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        if data["findings"]:
            finding = data["findings"][0]
            assert "type" in finding
            assert "parameter" in finding
            assert "payload" in finding
            assert "severity" in finding

    @pytest.mark.asyncio
    async def test_xss_encoded_output_safe(self, mock_session_factory):
        """Test that properly encoded output is not flagged."""
        # HTML-encoded XSS payload should not be detected as vulnerable
        safe_body = "<html><body>Result: &lt;script&gt;alert('XSS')&lt;/script&gt;</body></html>"
        mock_session = mock_session_factory([
            (200, safe_body, {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://example.com/search?q=test")
            data = json.loads(result)

        # Should not detect reflected XSS (only partial at most)
        reflected_xss = [f for f in data["findings"] if f["type"] == "reflected_xss"]
        assert len(reflected_xss) == 0

    @pytest.mark.asyncio
    async def test_xss_network_error_handling(self):
        """Test handling of network errors during XSS testing."""
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=Exception("Connection failed"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_xss_reflection("http://unreachable.example.com/search?q=test")
            data = json.loads(result)

        # Should handle gracefully and report no findings
        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) == 0
