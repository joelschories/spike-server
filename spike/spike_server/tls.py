"""Eigenes TLS-Zertifikat des Servers. Die App merkt sich beim ersten Kontakt dessen
Fingerabdruck (SHA-256) und akzeptiert danach nur noch genau dieses Zertifikat."""
from __future__ import annotations

import datetime
import hashlib
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def ensure_certificate(directory: Path) -> tuple:
    directory.mkdir(parents=True, exist_ok=True)
    cert_file, key_file = directory / "cert.pem", directory / "key.pem"
    if not cert_file.exists() or not key_file.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Spike")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=365 * 20))
                .sign(key, hashes.SHA256()))
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        os.chmod(key_file, 0o600)
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    der = x509.load_pem_x509_certificate(cert_file.read_bytes()).public_bytes(serialization.Encoding.DER)
    return cert_file, key_file, hashlib.sha256(der).hexdigest()


def server_context(cert_file: Path, key_file: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_file, key_file)
    return ctx
