"""Tests for VirusScanner service."""

from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from services.virus_scanner import ScanResult, VirusScanner


@pytest.fixture
def mock_settings():
    """Provide mock settings for VirusScanner."""
    s = MagicMock()
    s.enable_virus_scanning = True
    s.clamav_host = "localhost"
    s.clamav_port = 3310
    s.clamav_timeout = 5.0
    with patch("services.virus_scanner.settings", s):
        yield s


@pytest.fixture
def scanner(mock_settings):
    """Create VirusScanner with mocked settings."""
    return VirusScanner()


class TestScanResult:
    """Test ScanResult model."""

    def test_clean_result(self):
        r = ScanResult(is_clean=True)
        assert r.is_clean is True
        assert r.virus_name is None
        assert repr(r) == "<ScanResult: CLEAN>"

    def test_infected_result(self):
        r = ScanResult(is_clean=False, virus_name="Eicar-Test")
        assert r.is_clean is False
        assert r.virus_name == "Eicar-Test"
        assert "INFECTED" in repr(r)
        assert "Eicar-Test" in repr(r)


class TestVirusScannerInit:
    """Test VirusScanner initialization."""

    def test_init_stores_settings(self, scanner, mock_settings):
        assert scanner.enabled is True
        assert scanner.host == "localhost"
        assert scanner.port == 3310
        assert scanner.timeout == 5.0

    def test_init_disabled(self, mock_settings):
        mock_settings.enable_virus_scanning = False
        s = VirusScanner()
        assert s.enabled is False


class TestPing:
    """Test ClamAV ping."""

    def test_ping_success(self, scanner):
        with patch.object(scanner, "_send_command", return_value=b"PONG"):
            assert scanner.ping() is True

    def test_ping_wrong_response(self, scanner):
        with patch.object(scanner, "_send_command", return_value=b"ERROR"):
            assert scanner.ping() is False

    def test_ping_exception(self, scanner):
        with patch.object(scanner, "_send_command", side_effect=RuntimeError("fail")):
            assert scanner.ping() is False

    def test_ping_disabled(self, mock_settings):
        mock_settings.enable_virus_scanning = False
        s = VirusScanner()
        assert s.ping() is False


class TestSendCommand:
    """Test low-level socket communication."""

    def test_send_command_success(self, scanner):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"PONG", b""]
        with patch("services.virus_scanner.socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
            result = scanner._send_command(b"PING\n")
            assert result == b"PONG"

    def test_send_command_timeout(self, scanner):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = TimeoutError("timeout")
        with patch("services.virus_scanner.socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(RuntimeError, match="timeout"):
                scanner._send_command(b"PING\n")

    def test_send_command_generic_error(self, scanner):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError("refused")
        with patch("services.virus_scanner.socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(RuntimeError, match="Virus scanner error"):
                scanner._send_command(b"PING\n")


class TestScanFile:
    """Test file scanning."""

    def test_scan_file_disabled(self, mock_settings):
        mock_settings.enable_virus_scanning = False
        s = VirusScanner()
        result = s.scan_file(Path("/tmp/test.txt"))
        assert result.is_clean is True

    def test_scan_file_not_found(self, scanner):
        with pytest.raises(FileNotFoundError):
            scanner.scan_file(Path("/nonexistent/file.txt"))

    def test_scan_file_calls_scan_stream(self, scanner, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")

        with patch.object(scanner, "scan_stream", return_value=ScanResult(is_clean=True)):
            result = scanner.scan_file(test_file)
            assert result.is_clean is True


class TestScanStream:
    """Test stream scanning."""

    def test_scan_stream_disabled(self, mock_settings):
        mock_settings.enable_virus_scanning = False
        s = VirusScanner()
        result = s.scan_stream(BytesIO(b"data"))
        assert result.is_clean is True

    def test_scan_stream_clean(self, scanner):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"stream: OK", b""]

        with patch("services.virus_scanner.socket.socket") as mock_cls:
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            result = scanner.scan_stream(BytesIO(b"clean data"))
            assert result.is_clean is True

    def test_scan_stream_infected(self, scanner):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"stream: Eicar-Test FOUND", b""]

        with patch("services.virus_scanner.socket.socket") as mock_cls:
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            result = scanner.scan_stream(BytesIO(b"virus"))
            assert result.is_clean is False
            assert result.virus_name == "Eicar-Test"

    def test_scan_stream_infected_signature_contains_ok(self, scanner):
        """Regression: an infected signature whose name contains the substring
        'OK' must still be classified as infected. 'FOUND' is checked before
        'OK', so 'Win.Trojan.OKifer-1 FOUND' must not match the clean branch.
        """
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"stream: Win.Trojan.OKifer-1 FOUND", b""]

        with patch("services.virus_scanner.socket.socket") as mock_cls:
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            result = scanner.scan_stream(BytesIO(b"virus"))
            assert result.is_clean is False
            assert result.virus_name == "Win.Trojan.OKifer-1"

    def test_scan_stream_unexpected_response(self, scanner):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"stream: ERROR something", b""]

        with patch("services.virus_scanner.socket.socket") as mock_cls:
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(RuntimeError, match="Unexpected scan response"):
                scanner.scan_stream(BytesIO(b"data"))

    def test_scan_stream_timeout(self, scanner):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = TimeoutError("timed out")

        with patch("services.virus_scanner.socket.socket") as mock_cls:
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(RuntimeError, match="timeout"):
                scanner.scan_stream(BytesIO(b"data"))

    def test_scan_stream_connection_error(self, scanner):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Connection refused")

        with patch("services.virus_scanner.socket.socket") as mock_cls:
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(RuntimeError, match="Virus scan error"):
                scanner.scan_stream(BytesIO(b"data"))
