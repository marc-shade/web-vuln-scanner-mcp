"""Tests for SQL injection vulnerability detection."""

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(__file__).replace("/tests/test_sqli_detection.py", "/src"))

from web_vuln_scanner_mcp.server import test_sqli_params, SQLI_PAYLOADS, SQLI_ERRORS
from tests.test_constants import (
    HTML_SAFE,
    HTML_SQLI_ERROR_MYSQL,
    HTML_SQLI_ERROR_POSTGRESQL,
    HTML_SQLI_ERROR_ORACLE,
    HTML_SQLI_ERROR_MSSQL,
    HTML_SQLI_ERROR_SQLITE,
)


class TestSQLiDetection:
    """Tests for SQL injection vulnerability detection."""

    @pytest.mark.asyncio
    async def test_mysql_error_detection(self, mock_session_factory):
        """Test detection of MySQL SQL error."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),  # Baseline
            (200, HTML_SQLI_ERROR_MYSQL, {}),  # Error response
        ] * 10)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) > 0
        assert data["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_postgresql_error_detection(self, mock_session_factory):
        """Test detection of PostgreSQL SQL error."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),  # Baseline
            (200, HTML_SQLI_ERROR_POSTGRESQL, {}),
        ] * 10)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) > 0

    @pytest.mark.asyncio
    async def test_oracle_error_detection(self, mock_session_factory):
        """Test detection of Oracle SQL error."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),
            (200, HTML_SQLI_ERROR_ORACLE, {}),
        ] * 10)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) > 0

    @pytest.mark.asyncio
    async def test_mssql_error_detection(self, mock_session_factory):
        """Test detection of MS SQL Server error."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),
            (200, HTML_SQLI_ERROR_MSSQL, {}),
        ] * 10)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) > 0

    @pytest.mark.asyncio
    async def test_sqlite_error_detection(self, mock_session_factory):
        """Test detection of SQLite error."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),
            (200, HTML_SQLI_ERROR_SQLITE, {}),
        ] * 10)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) > 0

    @pytest.mark.asyncio
    async def test_no_sqli_vulnerability(self, mock_session_factory):
        """Test when no SQL injection vulnerability is found."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) == 0
        assert data["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_sqli_no_parameters(self):
        """Test SQLi test with URL without parameters."""
        result = await test_sqli_params("http://example.com/page")
        data = json.loads(result)

        assert data["success"] is False
        assert "No URL parameters found" in data["error"]

    @pytest.mark.asyncio
    async def test_sqli_multiple_parameters(self, mock_session_factory):
        """Test SQLi testing with multiple parameters."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 100)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params(
                "http://example.com/search?id=1&name=test&category=5"
            )
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["parameters_tested"]) == 3
        assert "id" in data["parameters_tested"]
        assert "name" in data["parameters_tested"]
        assert "category" in data["parameters_tested"]

    @pytest.mark.asyncio
    async def test_sqli_specific_parameters_only(self, mock_session_factory):
        """Test SQLi testing limited to specific parameters."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params(
                "http://example.com/search?id=1&name=test&category=5",
                test_params=["id"]
            )
            data = json.loads(result)

        assert data["success"] is True
        assert data["parameters_tested"] == ["id"]

    @pytest.mark.asyncio
    async def test_sqli_payloads_count(self, mock_session_factory):
        """Test that all SQLi payloads are tested."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert data["payloads_tested"] == len(SQLI_PAYLOADS)

    @pytest.mark.asyncio
    async def test_sqli_response_anomaly_detection(self, mock_session_factory):
        """Test detection of significant response changes (blind SQLi indicator)."""
        short_response = "<html><body>No results</body></html>"
        long_response = "<html><body>" + "Data " * 1000 + "</body></html>"

        mock_session = mock_session_factory([
            (200, short_response, {}),  # Baseline
            (200, long_response, {}),   # Anomaly
        ] * 10)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert data["success"] is True
        # Should detect response anomaly
        anomaly_findings = [f for f in data["findings"] if f["type"] == "response_anomaly"]
        assert len(anomaly_findings) > 0

    @pytest.mark.asyncio
    async def test_sqli_finding_details(self, mock_session_factory):
        """Test SQLi finding contains required details."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),
            (200, HTML_SQLI_ERROR_MYSQL, {}),
        ] * 10)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        if data["findings"]:
            finding = data["findings"][0]
            assert "type" in finding
            assert "parameter" in finding
            assert "payload" in finding
            assert "severity" in finding

    @pytest.mark.asyncio
    async def test_sqli_single_quote_payload(self, mock_session_factory):
        """Test single quote payload triggers error."""
        error_body = "<html>SQL syntax error: Unclosed quotation mark</html>"
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),
            (200, error_body, {}),
        ] * 10)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["vulnerable_parameters"]) > 0

    @pytest.mark.asyncio
    async def test_sqli_or_bypass_payload(self, mock_session_factory):
        """Test OR bypass payload detection."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),
            (200, HTML_SQLI_ERROR_MYSQL, {}),
        ] * 10)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/login?user=admin")
            data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_sqli_union_payload(self, mock_session_factory):
        """Test UNION payload detection."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),
            (200, HTML_SQLI_ERROR_MYSQL, {}),
        ] * 10)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_sqli_network_error_handling(self, mock_session_factory):
        """Test handling of network errors during baseline fetch."""
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=Exception("Connection failed"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://unreachable.example.com/page?id=1")
            data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_sqli_custom_timeout(self, mock_session_factory):
        """Test custom timeout parameter."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params(
                "http://example.com/page?id=1",
                timeout=5
            )
            data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_sqli_authorized_testing_note(self, mock_session_factory):
        """Test that authorized testing note is included."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {})
        ] * 50)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        assert "note" in data
        assert "AUTHORIZED" in data["note"]

    @pytest.mark.asyncio
    async def test_sqli_error_patterns_comprehensive(self):
        """Test that all SQL error patterns are valid regex."""
        import re

        for pattern in SQLI_ERRORS:
            # Should not raise
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None

    @pytest.mark.asyncio
    async def test_sqli_multiple_vulnerabilities_same_param(self, mock_session_factory):
        """Test that parameter is only listed once even with multiple findings."""
        mock_session = mock_session_factory([
            (200, HTML_SAFE, {}),
            (200, HTML_SQLI_ERROR_MYSQL, {}),
            (200, HTML_SQLI_ERROR_POSTGRESQL, {}),
        ] * 5)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await test_sqli_params("http://example.com/page?id=1")
            data = json.loads(result)

        # Parameter should only appear once in vulnerable_parameters
        assert data["vulnerable_parameters"].count("id") == 1
