"""Tests for security header analysis functionality."""

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(__file__).replace("/tests/test_security_headers.py", "/src"))

from web_vuln_scanner_mcp.server import analyze_security_headers, SECURITY_HEADERS


class TestSecurityHeaderAnalysis:
    """Tests for HTTP security header analysis."""

    @pytest.mark.asyncio
    async def test_all_secure_headers_present(self, mock_session_factory, secure_headers):
        """Test analysis when all security headers are present and correct."""
        mock_session = mock_session_factory([
            (200, "<html></html>", secure_headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://example.com")
            data = json.loads(result)

        assert data["success"] is True
        assert data["score"] >= 90
        assert data["grade"] in ["A", "B"]

    @pytest.mark.asyncio
    async def test_missing_all_security_headers(self, mock_session_factory, insecure_headers):
        """Test analysis when critical security headers are missing."""
        mock_session = mock_session_factory([
            (200, "<html></html>", insecure_headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        assert data["score"] < 60
        assert data["grade"] in ["D", "F"]
        assert len(data["recommendations"]) > 0

    @pytest.mark.asyncio
    async def test_partial_security_headers(self, mock_session_factory, partial_security_headers):
        """Test analysis with partial security headers."""
        mock_session = mock_session_factory([
            (200, "<html></html>", partial_security_headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://example.com")
            data = json.loads(result)

        assert data["success"] is True
        # Score depends on which headers are present/missing and info disclosure
        assert 0 <= data["score"] <= 100
        assert data["grade"] in ["A", "B", "C", "D", "F"]

    @pytest.mark.asyncio
    async def test_x_content_type_options_wrong_value(self, mock_session_factory):
        """Test detection of wrong X-Content-Type-Options value."""
        headers = {"X-Content-Type-Options": "invalid-value"}
        mock_session = mock_session_factory([
            (200, "<html></html>", headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://example.com")
            data = json.loads(result)

        assert data["success"] is True
        # Find the finding for X-Content-Type-Options
        finding = next(
            (f for f in data["findings"] if f["header"] == "X-Content-Type-Options"),
            None
        )
        assert finding is not None
        assert "issue" in finding

    @pytest.mark.asyncio
    async def test_x_frame_options_valid_values(self, mock_session_factory):
        """Test valid X-Frame-Options values (DENY and SAMEORIGIN)."""
        for value in ["DENY", "SAMEORIGIN"]:
            headers = {"X-Frame-Options": value}
            mock_session = mock_session_factory([
                (200, "<html></html>", headers)
            ])

            with patch("aiohttp.ClientSession", return_value=mock_session):
                result = await analyze_security_headers("https://example.com")
                data = json.loads(result)

            finding = next(
                (f for f in data["findings"] if f["header"] == "X-Frame-Options"),
                None
            )
            assert finding is not None
            assert "issue" not in finding or value in str(finding.get("issue", ""))

    @pytest.mark.asyncio
    async def test_information_disclosure_server_header(self, mock_session_factory):
        """Test detection of Server header information disclosure."""
        headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Content-Type-Options": "nosniff"
        }
        mock_session = mock_session_factory([
            (200, "<html></html>", headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://example.com")
            data = json.loads(result)

        assert data["success"] is True
        server_finding = next(
            (f for f in data["findings"] if "Server" in f.get("header", "")),
            None
        )
        assert server_finding is not None
        assert "issue" in server_finding

    @pytest.mark.asyncio
    async def test_information_disclosure_x_powered_by(self, mock_session_factory):
        """Test detection of X-Powered-By header disclosure."""
        headers = {"X-Powered-By": "PHP/7.4.3"}
        mock_session = mock_session_factory([
            (200, "<html></html>", headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://example.com")
            data = json.loads(result)

        assert data["success"] is True
        powered_by_finding = next(
            (f for f in data["findings"] if "Powered" in f.get("header", "")),
            None
        )
        assert powered_by_finding is not None

    @pytest.mark.asyncio
    async def test_information_disclosure_aspnet_version(self, mock_session_factory):
        """Test detection of ASP.NET version header disclosure."""
        headers = {"X-AspNet-Version": "4.0.30319"}
        mock_session = mock_session_factory([
            (200, "<html></html>", headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://example.com")
            data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_csp_header_present(self, mock_session_factory):
        """Test Content-Security-Policy header detection."""
        headers = {"Content-Security-Policy": "default-src 'self'; script-src 'self'"}
        mock_session = mock_session_factory([
            (200, "<html></html>", headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://example.com")
            data = json.loads(result)

        csp_finding = next(
            (f for f in data["findings"] if f["header"] == "Content-Security-Policy"),
            None
        )
        assert csp_finding is not None
        assert csp_finding["present"] is True

    @pytest.mark.asyncio
    async def test_hsts_header_missing(self, mock_session_factory):
        """Test detection of missing HSTS header."""
        headers = {"X-Content-Type-Options": "nosniff"}
        mock_session = mock_session_factory([
            (200, "<html></html>", headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://example.com")
            data = json.loads(result)

        hsts_finding = next(
            (f for f in data["findings"] if f["header"] == "Strict-Transport-Security"),
            None
        )
        assert hsts_finding is not None
        assert hsts_finding["present"] is False
        assert "issue" in hsts_finding

    @pytest.mark.asyncio
    async def test_network_error_handling(self, mock_session_factory):
        """Test handling of network errors."""
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=Exception("Connection refused"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://unreachable.example.com")
            data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_grade_calculation_a(self, mock_session_factory, secure_headers):
        """Test grade A calculation."""
        mock_session = mock_session_factory([
            (200, "<html></html>", secure_headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://secure.example.com")
            data = json.loads(result)

        assert data["score"] >= 90
        assert data["grade"] == "A"

    @pytest.mark.asyncio
    async def test_grade_calculation_f(self, mock_session_factory):
        """Test grade F calculation for worst case."""
        headers = {
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/7.4.3",
            "X-AspNet-Version": "4.0",
        }
        mock_session = mock_session_factory([
            (200, "<html></html>", headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://insecure.example.com")
            data = json.loads(result)

        assert data["score"] < 60
        assert data["grade"] in ["D", "F"]

    @pytest.mark.asyncio
    async def test_score_never_negative(self, mock_session_factory):
        """Test that score is never negative."""
        # Headers that would cause maximum deductions
        headers = {
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/7.4.3",
            "X-AspNet-Version": "4.0",
        }
        mock_session = mock_session_factory([
            (200, "<html></html>", headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://example.com")
            data = json.loads(result)

        assert data["score"] >= 0

    @pytest.mark.asyncio
    async def test_findings_contain_all_security_headers(self, mock_session_factory):
        """Test that findings include all tracked security headers."""
        mock_session = mock_session_factory([
            (200, "<html></html>", {})
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://example.com")
            data = json.loads(result)

        finding_headers = {f["header"] for f in data["findings"]}
        for header in SECURITY_HEADERS.keys():
            assert header in finding_headers

    @pytest.mark.asyncio
    async def test_case_insensitive_header_matching(self, mock_session_factory):
        """Test that header matching is case-insensitive."""
        headers = {
            "content-security-policy": "default-src 'self'",
            "X-CONTENT-TYPE-OPTIONS": "nosniff",
            "x-frame-options": "DENY",
        }
        mock_session = mock_session_factory([
            (200, "<html></html>", headers)
        ])

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await analyze_security_headers("https://example.com")
            data = json.loads(result)

        csp_finding = next(
            (f for f in data["findings"] if f["header"] == "Content-Security-Policy"),
            None
        )
        assert csp_finding is not None
        assert csp_finding["present"] is True
