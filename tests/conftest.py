"""Pytest fixtures for web-vuln-scanner-mcp tests."""

import json
import ssl
import socket
from datetime import datetime, timedelta
from typing import Any, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import aiohttp


def pytest_collection_modifyitems(session, config, items):
    """Filter out items that come from the server module (not actual tests)."""
    filtered = []
    for item in items:
        # Check if this is a function from server.py by looking at file path
        if hasattr(item, 'obj') and hasattr(item.obj, '__code__'):
            code_file = item.obj.__code__.co_filename
            if 'server.py' in code_file:
                continue
        filtered.append(item)
    items[:] = filtered


# HTML response templates for testing
HTML_VULNERABLE_XSS = """
<!DOCTYPE html>
<html>
<head><title>Vulnerable Page</title></head>
<body>
    <h1>Search Results</h1>
    <p>You searched for: <script>alert('XSS')</script></p>
</body>
</html>
"""

HTML_SAFE = """
<!DOCTYPE html>
<html>
<head><title>Safe Page</title></head>
<body>
    <h1>Welcome</h1>
    <p>This is a safe page.</p>
</body>
</html>
"""

HTML_SQLI_ERROR_MYSQL = """
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Error</h1>
    <p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p>
</body>
</html>
"""

HTML_SQLI_ERROR_POSTGRESQL = """
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Error</h1>
    <p>PostgreSQL ERROR: syntax error at or near "'"</p>
</body>
</html>
"""

HTML_SQLI_ERROR_ORACLE = """
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Database Error</h1>
    <p>ORA-00933: SQL command not properly ended</p>
</body>
</html>
"""

HTML_SQLI_ERROR_MSSQL = """
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Error</h1>
    <p>Microsoft OLE DB Provider for ODBC Drivers error '80040e14' [Microsoft][ODBC SQL Server Driver]</p>
</body>
</html>
"""

HTML_SQLI_ERROR_SQLITE = """
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Error</h1>
    <p>SQLite3::Exception: near "'": syntax error</p>
</body>
</html>
"""

HTML_INFO_DISCLOSURE = """
<!DOCTYPE html>
<html>
<head><title>Debug Page</title></head>
<body>
    <h1>Debug Info</h1>
    <!-- TODO: Remove this before production -->
    <p>password = "admin123"</p>
    <p>api_key = "sk-12345abcde"</p>
    <p>AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"</p>
    <p>Internal Server: 192.168.1.100</p>
    <p>Path: /home/webuser/app/config.py</p>
    <pre>
    Stack trace at line 42:
    File "/home/webuser/app/main.py", line 42, in handle_request
        raise Exception("Debug error")
    </pre>
</body>
</html>
"""

HTML_PARTIAL_XSS = """
<!DOCTYPE html>
<html>
<head><title>Search</title></head>
<body>
    <h1>Search Results</h1>
    <p>You searched for: &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
    <input type="hidden" value="<script>al">
</body>
</html>
"""

SENSITIVE_GIT_CONFIG = """
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
[remote "origin"]
    url = git@github.com:user/secret-repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
"""

SENSITIVE_ENV_FILE = """
DATABASE_URL=postgres://admin:secretpass@localhost:5432/mydb
SECRET_KEY=super-secret-key-12345
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""


@pytest.fixture
def mock_response_factory():
    """Factory for creating mock aiohttp responses."""
    def _create_response(
        status: int = 200,
        body: str = HTML_SAFE,
        headers: dict = None,
        url: str = "http://example.com"
    ):
        mock_response = AsyncMock()
        mock_response.status = status
        mock_response.text = AsyncMock(return_value=body)
        mock_response.headers = headers or {}
        mock_response.url = url
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        return mock_response
    return _create_response


@pytest.fixture
def mock_session_factory(mock_response_factory):
    """Factory for creating mock aiohttp sessions."""
    def _create_session(responses: list = None):
        """Create a mock session with configured responses.

        Args:
            responses: List of (status, body, headers) tuples for sequential calls
        """
        if responses is None:
            responses = [(200, HTML_SAFE, {})]

        mock_session = AsyncMock()
        response_iter = iter(responses)

        def get_next_response(*args, **kwargs):
            try:
                status, body, headers = next(response_iter)
            except StopIteration:
                # Return last response if we run out
                status, body, headers = responses[-1]
            return mock_response_factory(status=status, body=body, headers=headers)

        mock_session.get = MagicMock(side_effect=get_next_response)
        mock_session.post = MagicMock(side_effect=get_next_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        return mock_session
    return _create_session


@pytest.fixture
def secure_headers():
    """Return a complete set of secure HTTP headers."""
    return {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=()",
    }


@pytest.fixture
def insecure_headers():
    """Return headers missing critical security headers."""
    return {
        "Server": "Apache/2.4.41",
        "X-Powered-By": "PHP/7.4.3",
        "Content-Type": "text/html",
    }


@pytest.fixture
def partial_security_headers():
    """Return headers with some security headers present."""
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "Server": "nginx/1.18.0",
    }


@pytest.fixture
def xss_payloads():
    """Return XSS test payloads."""
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
    ]


@pytest.fixture
def sqli_payloads():
    """Return SQL injection test payloads."""
    return [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "1' ORDER BY 1--",
        "1 UNION SELECT NULL--",
        "'; DROP TABLE--",
    ]


@pytest.fixture
def mock_ssl_context():
    """Create a mock SSL context for testing."""
    mock_ctx = MagicMock(spec=ssl.SSLContext)
    mock_ctx.check_hostname = False
    mock_ctx.verify_mode = ssl.CERT_NONE
    return mock_ctx


@pytest.fixture
def mock_ssl_socket():
    """Create a mock SSL socket with certificate info."""
    mock_socket = MagicMock()
    mock_socket.version.return_value = "TLSv1.3"
    mock_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    # Certificate info
    not_after = (datetime.now() + timedelta(days=90)).strftime('%b %d %H:%M:%S %Y GMT')
    mock_socket.getpeercert.return_value = {
        'subject': ((('commonName', 'example.com'),),),
        'notAfter': not_after,
        'notBefore': datetime.now().strftime('%b %d %H:%M:%S %Y GMT'),
    }

    mock_socket.__enter__ = MagicMock(return_value=mock_socket)
    mock_socket.__exit__ = MagicMock(return_value=None)
    return mock_socket


@pytest.fixture
def mock_ssl_socket_expired():
    """Create a mock SSL socket with an expired certificate."""
    mock_socket = MagicMock()
    mock_socket.version.return_value = "TLSv1.2"
    mock_socket.cipher.return_value = ("TLS_RSA_WITH_AES_128_CBC_SHA", "TLSv1.2", 128)

    # Expired certificate
    not_after = (datetime.now() - timedelta(days=10)).strftime('%b %d %H:%M:%S %Y GMT')
    mock_socket.getpeercert.return_value = {
        'subject': ((('commonName', 'expired.example.com'),),),
        'notAfter': not_after,
    }

    mock_socket.__enter__ = MagicMock(return_value=mock_socket)
    mock_socket.__exit__ = MagicMock(return_value=None)
    return mock_socket


@pytest.fixture
def mock_ssl_socket_weak():
    """Create a mock SSL socket with weak cipher."""
    mock_socket = MagicMock()
    mock_socket.version.return_value = "TLSv1.0"
    mock_socket.cipher.return_value = ("DES-CBC3-SHA", "TLSv1.0", 112)

    not_after = (datetime.now() + timedelta(days=30)).strftime('%b %d %H:%M:%S %Y GMT')
    mock_socket.getpeercert.return_value = {
        'subject': ((('commonName', 'weak.example.com'),),),
        'notAfter': not_after,
    }

    mock_socket.__enter__ = MagicMock(return_value=mock_socket)
    mock_socket.__exit__ = MagicMock(return_value=None)
    return mock_socket


@pytest.fixture
def sensitive_paths():
    """Return list of sensitive paths to test."""
    return [
        "/.git/config",
        "/.env",
        "/.htaccess",
        "/wp-config.php",
        "/config.php",
        "/admin/",
        "/phpinfo.php",
        "/server-status",
        "/robots.txt",
        "/sitemap.xml",
        "/.svn/entries",
        "/backup/",
        "/db/",
        "/sql/",
        "/logs/",
        "/debug/",
    ]
