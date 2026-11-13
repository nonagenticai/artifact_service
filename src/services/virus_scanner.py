"""ClamAV virus scanning service."""

import logging
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Result of a virus scan."""

    is_clean: bool
    virus_name: str | None = None

    def __repr__(self) -> str:
        """String representation."""
        if self.is_clean:
            return "<ScanResult: CLEAN>"
        return f"<ScanResult: INFECTED - {self.virus_name}>"


class VirusScanner:
    """Service for scanning files with ClamAV."""

    def __init__(self) -> None:
        """Initialize virus scanner."""
        self.enabled = settings.enable_virus_scanning
        self.host = settings.clamav_host
        self.port = settings.clamav_port
        self.timeout = settings.clamav_timeout

    def _send_command(self, command: bytes) -> bytes:
        """Send a command to ClamAV daemon and get response."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.host, self.port))
                sock.sendall(command)
                sock.shutdown(socket.SHUT_WR)

                # Receive response
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                return response
        except TimeoutError:
            logger.error("ClamAV connection timeout")
            raise RuntimeError("Virus scanner timeout")
        except (ConnectionError, OSError) as e:
            logger.error(f"Error communicating with ClamAV: {e}")
            raise RuntimeError(f"Virus scanner error: {e}")

    def ping(self) -> bool:
        """Check if ClamAV daemon is responsive."""
        if not self.enabled:
            return False

        try:
            response = self._send_command(b"PING\n")
            return response.strip() == b"PONG"
        except (ConnectionError, OSError, RuntimeError) as e:
            logger.warning(f"ClamAV ping failed: {e}")
            return False

    def scan_file(self, file_path: Path) -> ScanResult:
        """
        Scan a file for viruses.

        Args:
            file_path: Path to the file to scan

        Returns:
            ScanResult indicating if the file is clean
        """
        if not self.enabled:
            logger.debug("Virus scanning is disabled")
            return ScanResult(is_clean=True)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            # Use INSTREAM command to scan file contents
            with open(file_path, "rb") as f:
                return self.scan_stream(f)
        except (ConnectionError, OSError, RuntimeError) as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            raise

    def scan_stream(self, file_stream: BinaryIO) -> ScanResult:
        """
        Scan a file stream for viruses.

        Args:
            file_stream: Binary file stream to scan

        Returns:
            ScanResult indicating if the stream is clean
        """
        if not self.enabled:
            logger.debug("Virus scanning is disabled")
            return ScanResult(is_clean=True)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.host, self.port))

                # Send INSTREAM command
                sock.sendall(b"zINSTREAM\0")

                # Send file data in chunks
                chunk_size = 4096
                while True:
                    chunk = file_stream.read(chunk_size)
                    if not chunk:
                        break

                    # Send chunk size (4 bytes, network byte order)
                    size = len(chunk).to_bytes(4, byteorder="big")
                    sock.sendall(size)
                    sock.sendall(chunk)

                # Send terminator (0 length)
                sock.sendall(b"\x00\x00\x00\x00")
                sock.shutdown(socket.SHUT_WR)

                # Receive response
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                # Parse response
                response_str = response.decode("utf-8").strip()
                logger.debug(f"ClamAV response: {response_str}")

                # Response format: "stream: OK" or "stream: {virus_name} FOUND".
                # Check FOUND before OK: an infected reply always contains
                # "FOUND", while a signature name may itself contain the
                # substring "OK" (e.g. "Win.Trojan.OKifer-1 FOUND"). Testing OK
                # first would misclassify such infected files as clean.
                if "FOUND" in response_str:
                    virus_name = response_str.split(":")[1].strip().replace(" FOUND", "")
                    logger.warning(f"Virus detected: {virus_name}")
                    return ScanResult(is_clean=False, virus_name=virus_name)
                elif "OK" in response_str:
                    return ScanResult(is_clean=True)
                else:
                    logger.error(f"Unexpected ClamAV response: {response_str}")
                    raise RuntimeError(f"Unexpected scan response: {response_str}")

        except TimeoutError:
            logger.error("ClamAV scan timeout")
            raise RuntimeError("Virus scan timeout")
        except (ConnectionError, OSError) as e:
            logger.error(f"Error scanning stream: {e}")
            raise RuntimeError(f"Virus scan error: {e}")
