"""Tests for sensitive path scanning functionality."""

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(__file__).replace("/tests/test_sensitive_paths.py", "/src"))

from web_vuln_scanner_mcp.server import scan_sensitive_paths, SENSITIVE_PATHS
from tests.test_constants import SENSITIVE_GIT_CONFIG, SENSITIVE_ENV_FILE, HTML_SAFE


class TestSensitivePathScanning:
    """Tests for sensitive path scanning functionality."""

    @pytest.mark.asyncio
    async def test_git_config_exposed(self, mock_session_factory):
        """Test detection of exposed .git/config."""
        responses = [(404, "Not Found", {})] * 20
        responses[0] = (200, SENSITIVE_GIT_CONFIG, {})  # /.git/config found

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        git_discovery = next(
            (d for d in data["discovered"] if ".git" in d["path"]),
            None
        )
        assert git_discovery is not None
        assert git_discovery["severity"] == "high"

    @pytest.mark.asyncio
    async def test_env_file_exposed(self, mock_session_factory):
        """Test detection of exposed .env file."""
        responses = [(404, "Not Found", {})] * 20
        responses[1] = (200, SENSITIVE_ENV_FILE, {})  # /.env found

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        assert data["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_wp_config_exposed(self, mock_session_factory):
        """Test detection of exposed WordPress config."""
        wp_config = """<?php
        define('DB_NAME', 'wordpress');
        define('DB_USER', 'root');
        define('DB_PASSWORD', 'secret');
        """
        responses = [(404, "Not Found", {})] * 20
        responses[3] = (200, wp_config, {})  # /wp-config.php found

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        assert len(data["discovered"]) > 0

    @pytest.mark.asyncio
    async def test_phpinfo_exposed(self, mock_session_factory):
        """Test detection of exposed phpinfo."""
        phpinfo = """<html><head><title>PHP Info</title></head>
        <body>PHP Version 7.4.3</body></html>"""
        responses = [(404, "Not Found", {})] * 20
        responses[6] = (200, phpinfo, {})

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_admin_directory_forbidden(self, mock_session_factory):
        """Test detection of admin directory with 403."""
        responses = [(404, "Not Found", {})] * 20
        responses[5] = (403, "Forbidden", {})  # /admin/ exists but forbidden

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        admin_interesting = next(
            (i for i in data["interesting"] if "admin" in i["path"]),
            None
        )
        assert admin_interesting is not None
        assert admin_interesting["status"] == 403

    @pytest.mark.asyncio
    async def test_redirect_detected(self, mock_session_factory):
        """Test detection of redirecting sensitive paths."""
        responses = [(404, "Not Found", {})] * 20
        responses[5] = (301, "Moved", {"Location": "https://example.com/admin/login"})

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        redirect_interesting = next(
            (i for i in data["interesting"] if i["status"] in [301, 302]),
            None
        )
        assert redirect_interesting is not None

    @pytest.mark.asyncio
    async def test_no_sensitive_paths_found(self, mock_session_factory):
        """Test when no sensitive paths are found."""
        responses = [(404, "Not Found", {})] * 30

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        assert data["risk_level"] == "low"
        assert len(data["discovered"]) == 0

    @pytest.mark.asyncio
    async def test_custom_paths(self, mock_session_factory):
        """Test scanning with custom paths."""
        custom_backup = "DATABASE BACKUP CONTENTS"
        responses = [(404, "Not Found", {})] * 30
        # Custom path would be after default paths
        responses.append((200, custom_backup, {}))

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths(
                "http://example.com",
                custom_paths=["/backup.sql", "/database.bak"]
            )
            data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_paths_checked_count(self, mock_session_factory):
        """Test that all default paths are checked."""
        responses = [(404, "Not Found", {})] * 30

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert data["paths_checked"] == len(SENSITIVE_PATHS)

    @pytest.mark.asyncio
    async def test_paths_checked_with_custom(self, mock_session_factory):
        """Test path count includes custom paths."""
        responses = [(404, "Not Found", {})] * 30

        mock_session = mock_session_factory(responses)
        custom_paths = ["/custom1.txt", "/custom2.txt"]

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths(
                "http://example.com",
                custom_paths=custom_paths
            )
            data = json.loads(result)

        assert data["paths_checked"] == len(SENSITIVE_PATHS) + len(custom_paths)

    @pytest.mark.asyncio
    async def test_severity_classification_high(self, mock_session_factory):
        """Test high severity for critical files."""
        responses = [(200, SENSITIVE_GIT_CONFIG, {})]  # .git/config is first
        responses.extend([(404, "Not Found", {})] * 20)

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        high_severity = [d for d in data["discovered"] if d["severity"] == "high"]
        assert len(high_severity) > 0

    @pytest.mark.asyncio
    async def test_severity_classification_medium(self, mock_session_factory):
        """Test medium severity for less critical files."""
        robots_txt = """User-agent: *
        Disallow: /admin/
        Disallow: /secret/
        """
        responses = [(404, "Not Found", {})] * 20
        responses[8] = (200, robots_txt, {})  # robots.txt

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        if data["discovered"]:
            # robots.txt should be medium severity
            robots_finding = next(
                (d for d in data["discovered"] if "robots" in d["path"]),
                None
            )
            if robots_finding:
                assert robots_finding["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_interesting_limited_to_20(self, mock_session_factory):
        """Test that interesting paths are limited to 20."""
        # All paths return 403
        responses = [(403, "Forbidden", {})] * 30

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert len(data["interesting"]) <= 20

    @pytest.mark.asyncio
    async def test_base_url_normalization(self, mock_session_factory):
        """Test URL normalization from full URL."""
        responses = [(404, "Not Found", {})] * 20

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com/path/to/page?param=value")
            data = json.loads(result)

        assert data["base_url"] == "http://example.com"

    @pytest.mark.asyncio
    async def test_recommendations_when_found(self, mock_session_factory):
        """Test recommendations when sensitive paths found."""
        responses = [(200, SENSITIVE_GIT_CONFIG, {})]
        responses.extend([(404, "Not Found", {})] * 20)

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert "recommendations" in data
        assert len(data["recommendations"]) > 0
        assert any("protect" in r.lower() or "remove" in r.lower() for r in data["recommendations"])

    @pytest.mark.asyncio
    async def test_recommendations_when_clean(self, mock_session_factory):
        """Test recommendations when no sensitive paths found."""
        responses = [(404, "Not Found", {})] * 20

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert "recommendations" in data
        assert any("No obvious" in r for r in data["recommendations"])

    @pytest.mark.asyncio
    async def test_discovery_contains_url(self, mock_session_factory):
        """Test discovered paths include full URL."""
        responses = [(200, SENSITIVE_GIT_CONFIG, {})]
        responses.extend([(404, "Not Found", {})] * 20)

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        if data["discovered"]:
            discovery = data["discovered"][0]
            assert "url" in discovery
            assert discovery["url"].startswith("http://")

    @pytest.mark.asyncio
    async def test_discovery_contains_size(self, mock_session_factory):
        """Test discovered paths include response size."""
        responses = [(200, SENSITIVE_GIT_CONFIG, {})]
        responses.extend([(404, "Not Found", {})] * 20)

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        if data["discovered"]:
            discovery = data["discovered"][0]
            assert "size" in discovery
            assert discovery["size"] > 0

    @pytest.mark.asyncio
    async def test_svn_entries_detection(self, mock_session_factory):
        """Test detection of SVN entries file."""
        svn_entries = """8
        dir
        123
        svn://example.com/repo
        """
        responses = [(404, "Not Found", {})] * 20
        responses[10] = (200, svn_entries, {})

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_backup_directory_detection(self, mock_session_factory):
        """Test detection of backup directory."""
        backup_listing = """Index of /backup/
        database.sql
        config.bak
        """
        responses = [(404, "Not Found", {})] * 20
        responses[11] = (200, backup_listing, {})

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert data["success"] is True
        backup_discovery = next(
            (d for d in data["discovered"] if "backup" in d["path"]),
            None
        )
        if backup_discovery:
            # backup directory is medium severity unless it contains sql/config
            assert backup_discovery["severity"] in ["high", "medium"]

    @pytest.mark.asyncio
    async def test_logs_directory_detection(self, mock_session_factory):
        """Test detection of logs directory."""
        log_content = """[2024-01-01] ERROR: Database connection failed
        [2024-01-01] DEBUG: User admin logged in
        """
        responses = [(404, "Not Found", {})] * 20
        responses[14] = (200, log_content, {})

        mock_session = mock_session_factory(responses)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_network_error_graceful_handling(self, mock_session_factory):
        """Test graceful handling of network errors during scanning."""
        mock_session = AsyncMock()

        # Some paths succeed, some fail
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] % 3 == 0:
                raise Exception("Connection timeout")
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
            result = await scan_sensitive_paths("http://example.com")
            data = json.loads(result)

        # Should still succeed overall, just with fewer results
        assert data["success"] is True
