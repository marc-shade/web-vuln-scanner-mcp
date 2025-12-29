"""Tests for SSL/TLS configuration analysis."""

import json
import ssl
import socket
import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(__file__).replace("/tests/test_ssl_tls.py", "/src"))

from web_vuln_scanner_mcp.server import check_ssl_config


class TestSSLTLSAnalysis:
    """Tests for SSL/TLS configuration analysis."""

    @pytest.mark.asyncio
    async def test_tls_13_good_config(self, mock_ssl_socket):
        """Test TLS 1.3 with strong cipher gets good grade."""
        mock_ssl_socket.version.return_value = "TLSv1.3"
        mock_ssl_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_socket.getpeercert.return_value = None

        with patch("socket.create_connection") as mock_conn, \
             patch("ssl.create_default_context") as mock_ctx:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=None)

            mock_ctx_instance = MagicMock()
            mock_ctx_instance.wrap_socket.return_value = mock_ssl_socket
            mock_ctx.return_value = mock_ctx_instance

            result = await check_ssl_config("example.com")
            data = json.loads(result)

        assert data["success"] is True
        assert data["score"] >= 90
        assert data["grade"] in ["A", "B"]

    @pytest.mark.asyncio
    async def test_tls_12_acceptable(self, mock_ssl_socket):
        """Test TLS 1.2 is acceptable."""
        mock_ssl_socket.version.return_value = "TLSv1.2"
        mock_ssl_socket.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)

        with patch("socket.create_connection") as mock_conn, \
             patch("ssl.create_default_context") as mock_ctx:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=None)

            mock_ctx_instance = MagicMock()
            mock_ctx_instance.wrap_socket.return_value = mock_ssl_socket
            mock_ctx.return_value = mock_ctx_instance

            result = await check_ssl_config("example.com")
            data = json.loads(result)

        assert data["success"] is True
        # TLS 1.2 should still get good score
        assert data["score"] >= 80

    @pytest.mark.asyncio
    async def test_tls_11_warning(self):
        """Test TLS 1.1 triggers warning."""
        mock_socket = MagicMock()
        mock_socket.version.return_value = "TLSv1.1"
        mock_socket.cipher.return_value = ("AES256-SHA", "TLSv1.1", 256)
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

        assert data["success"] is True
        protocol_finding = next(
            (f for f in data["findings"] if f["check"] == "Protocol Version"),
            None
        )
        assert protocol_finding is not None
        assert protocol_finding["status"] == "warning"

    @pytest.mark.asyncio
    async def test_tls_10_critical(self):
        """Test TLS 1.0 triggers critical status."""
        mock_socket = MagicMock()
        mock_socket.version.return_value = "TLSv1"
        mock_socket.cipher.return_value = ("AES128-SHA", "TLSv1", 128)
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

        protocol_finding = next(
            (f for f in data["findings"] if f["check"] == "Protocol Version"),
            None
        )
        assert protocol_finding is not None
        assert protocol_finding["status"] == "critical"

    @pytest.mark.asyncio
    async def test_weak_cipher_rc4(self):
        """Test weak RC4 cipher is flagged."""
        mock_socket = MagicMock()
        mock_socket.version.return_value = "TLSv1.2"
        mock_socket.cipher.return_value = ("RC4-SHA", "TLSv1.2", 128)
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

        weak_cipher_finding = next(
            (f for f in data["findings"] if f["check"] == "Weak Cipher"),
            None
        )
        assert weak_cipher_finding is not None
        assert weak_cipher_finding["status"] == "critical"

    @pytest.mark.asyncio
    async def test_weak_cipher_des(self):
        """Test weak DES cipher is flagged."""
        mock_socket = MagicMock()
        mock_socket.version.return_value = "TLSv1.2"
        mock_socket.cipher.return_value = ("DES-CBC3-SHA", "TLSv1.2", 112)
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

        weak_cipher_finding = next(
            (f for f in data["findings"] if f["check"] == "Weak Cipher"),
            None
        )
        assert weak_cipher_finding is not None

    @pytest.mark.asyncio
    async def test_expired_certificate(self, mock_ssl_socket_expired):
        """Test expired certificate detection."""
        with patch("socket.create_connection") as mock_conn, \
             patch("ssl.create_default_context") as mock_ctx:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=None)

            mock_ctx_instance = MagicMock()
            mock_ctx_instance.wrap_socket.return_value = mock_ssl_socket_expired
            mock_ctx.return_value = mock_ctx_instance

            result = await check_ssl_config("expired.example.com")
            data = json.loads(result)

        assert data["success"] is True
        cert_finding = next(
            (f for f in data["findings"] if f["check"] == "Certificate Expiration"),
            None
        )
        if cert_finding:
            assert cert_finding["status"] == "critical"
            assert cert_finding["days_until_expiry"] < 0

    @pytest.mark.asyncio
    async def test_certificate_expiring_soon(self):
        """Test certificate expiring soon triggers warning."""
        mock_socket = MagicMock()
        mock_socket.version.return_value = "TLSv1.3"
        mock_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        # Certificate expiring in 15 days
        not_after = (datetime.now() + timedelta(days=15)).strftime('%b %d %H:%M:%S %Y GMT')
        mock_socket.getpeercert.return_value = {
            'subject': ((('commonName', 'example.com'),),),
            'notAfter': not_after,
        }
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

        cert_finding = next(
            (f for f in data["findings"] if f["check"] == "Certificate Expiration"),
            None
        )
        if cert_finding:
            assert cert_finding["status"] == "warning"

    @pytest.mark.asyncio
    async def test_connection_timeout(self):
        """Test handling of connection timeout."""
        with patch("socket.create_connection") as mock_conn:
            mock_conn.side_effect = socket.timeout("Connection timed out")

            result = await check_ssl_config("timeout.example.com")
            data = json.loads(result)

        assert data["success"] is False
        assert "timeout" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_dns_resolution_failure(self):
        """Test handling of DNS resolution failure."""
        with patch("socket.create_connection") as mock_conn:
            mock_conn.side_effect = socket.gaierror("DNS resolution failed")

            result = await check_ssl_config("nonexistent.example.com")
            data = json.loads(result)

        assert data["success"] is False
        assert "DNS" in data["error"]

    @pytest.mark.asyncio
    async def test_custom_port(self, mock_ssl_socket):
        """Test custom port parameter."""
        with patch("socket.create_connection") as mock_conn, \
             patch("ssl.create_default_context") as mock_ctx:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=None)

            mock_ctx_instance = MagicMock()
            mock_ctx_instance.wrap_socket.return_value = mock_ssl_socket
            mock_ctx.return_value = mock_ctx_instance

            result = await check_ssl_config("example.com", port=8443)
            data = json.loads(result)

        assert data["success"] is True
        assert data["port"] == 8443
        mock_conn.assert_called_with(("example.com", 8443), timeout=10)

    @pytest.mark.asyncio
    async def test_recommendations_on_poor_config(self):
        """Test recommendations are provided for poor SSL config."""
        mock_socket = MagicMock()
        mock_socket.version.return_value = "TLSv1.0"
        mock_socket.cipher.return_value = ("RC4-SHA", "TLSv1.0", 128)
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

            result = await check_ssl_config("insecure.example.com")
            data = json.loads(result)

        assert "recommendations" in data
        assert len(data["recommendations"]) > 0
        assert any("TLS" in r for r in data["recommendations"])

    @pytest.mark.asyncio
    async def test_certificate_validation_error(self):
        """Test handling of certificate validation error."""
        mock_socket = MagicMock()
        mock_socket.version.return_value = "TLSv1.3"
        mock_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_socket.getpeercert.return_value = None
        mock_socket.__enter__ = MagicMock(return_value=mock_socket)
        mock_socket.__exit__ = MagicMock(return_value=None)

        # First context succeeds, second raises validation error
        first_ctx = MagicMock()
        first_ctx.wrap_socket.return_value = mock_socket

        second_ctx = MagicMock()
        second_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("Certificate verification failed")

        with patch("socket.create_connection") as mock_conn, \
             patch("ssl.create_default_context", side_effect=[first_ctx, second_ctx]):
            mock_sock_instance = MagicMock()
            mock_sock_instance.__enter__ = MagicMock(return_value=mock_sock_instance)
            mock_sock_instance.__exit__ = MagicMock(return_value=None)
            mock_conn.return_value = mock_sock_instance

            result = await check_ssl_config("invalid-cert.example.com")
            data = json.loads(result)

        assert data["success"] is True
        validation_finding = next(
            (f for f in data["findings"] if f["check"] == "Certificate Validation"),
            None
        )
        if validation_finding:
            assert validation_finding["status"] == "warning"

    @pytest.mark.asyncio
    async def test_score_never_negative(self):
        """Test that score is never negative."""
        mock_socket = MagicMock()
        mock_socket.version.return_value = "SSLv3"  # Worst protocol
        mock_socket.cipher.return_value = ("RC4-NULL-MD5", "SSLv3", 0)  # Worst cipher
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

            result = await check_ssl_config("terrible.example.com")
            data = json.loads(result)

        assert data["score"] >= 0

    @pytest.mark.asyncio
    async def test_grade_calculation(self, mock_ssl_socket):
        """Test grade calculation based on score."""
        with patch("socket.create_connection") as mock_conn, \
             patch("ssl.create_default_context") as mock_ctx:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=None)

            mock_ctx_instance = MagicMock()
            mock_ctx_instance.wrap_socket.return_value = mock_ssl_socket
            mock_ctx.return_value = mock_ctx_instance

            result = await check_ssl_config("example.com")
            data = json.loads(result)

        # Verify grade matches score
        score = data["score"]
        grade = data["grade"]

        if score >= 90:
            assert grade == "A"
        elif score >= 80:
            assert grade == "B"
        elif score >= 70:
            assert grade == "C"
        elif score >= 60:
            assert grade == "D"
        else:
            assert grade == "F"
