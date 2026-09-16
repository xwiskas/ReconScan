"""Self-signed certificate for LAN mode (PRD A7).

LAN access must be encrypted. Rather than make you set up a certificate
authority for a class project, ReconScan generates a self-signed certificate on
first LAN start. Your browser will warn once that it does not recognise the
issuer - that warning is expected and it is telling the truth: the certificate
proves nothing about identity. It still encrypts the connection, which is what
stops your password crossing the LAN in clear text.

Generation uses the `cryptography` package if present, otherwise the openssl
binary, which Kali always has.
"""
from __future__ import annotations

import datetime
import ipaddress
import shutil
import socket
import subprocess

from . import config

CERT_PATH = config.DATA_DIR / "reconscan-cert.pem"
KEY_PATH = config.DATA_DIR / "reconscan-key.pem"


def _local_ips() -> list[str]:
    ips = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    if config.HOST not in ("0.0.0.0", "::"):
        ips.add(config.HOST)
    return sorted(ips)


def ensure_cert() -> tuple[str, str] | None:
    """Return (certfile, keyfile), generating them if needed. None if impossible."""
    if CERT_PATH.exists() and KEY_PATH.exists():
        return str(CERT_PATH), str(KEY_PATH)
    if _generate_with_cryptography() or _generate_with_openssl():
        try:
            KEY_PATH.chmod(0o600)
        except OSError:
            pass
        return str(CERT_PATH), str(KEY_PATH)
    return None


def _generate_with_cryptography() -> bool:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        return False

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ReconScan (self-signed)"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ReconScan local install"),
    ])
    alt: list = [x509.DNSName("localhost"), x509.DNSName(socket.gethostname())]
    for ip in _local_ips():
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            pass

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY_PATH.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return True


def _generate_with_openssl() -> bool:
    if shutil.which("openssl") is None:
        return False
    sans = ",".join(["DNS:localhost", f"DNS:{socket.gethostname()}"]
                    + [f"IP:{ip}" for ip in _local_ips()])
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes",
        "-keyout", str(KEY_PATH), "-out", str(CERT_PATH),
        "-days", "825", "-subj", "/CN=ReconScan (self-signed)",
        "-addext", f"subjectAltName={sans}",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=120)
    except (subprocess.SubprocessError, OSError):
        return False
    return CERT_PATH.exists() and KEY_PATH.exists()


def fingerprint() -> str:
    """SHA-256 fingerprint, so you can check the browser is showing the right cert."""
    if not CERT_PATH.exists():
        return ""
    import hashlib
    import ssl
    try:
        der = ssl.PEM_cert_to_DER_cert(CERT_PATH.read_text())
    except (ValueError, OSError):
        return ""
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
