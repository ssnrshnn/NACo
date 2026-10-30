"""Throw-away PKI for the e2e stack (CA, RADIUS server cert, client certs)."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _write(path: Path, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate) -> None:
    path.with_suffix(".key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.with_suffix(".pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path.with_suffix(".key").chmod(0o644)  # test material only


def _ca(cn: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = _key()
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def _leaf(ca_key, ca_cert, cn: str, eku) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = _key()
    now = dt.datetime.now(dt.UTC)
    builder = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca_cert.subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=2))
               .add_extension(x509.ExtendedKeyUsage([eku]), critical=False))
    if eku == ExtendedKeyUsageOID.SERVER_AUTH:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def build(root: Path) -> None:
    server, client = root / "server", root / "client"
    server.mkdir(parents=True, exist_ok=True)
    client.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = _ca("NACo e2e CA")
    for d in (server, client):
        (d / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    _write(server / "server", *_leaf(ca_key, ca_cert, "naco-radius", ExtendedKeyUsageOID.SERVER_AUTH))
    for cn in ("alice", "bob", "mallory"):
        _write(client / cn, *_leaf(ca_key, ca_cert, cn, ExtendedKeyUsageOID.CLIENT_AUTH))
    rogue_key, rogue_cert = _ca("Rogue CA")
    _write(client / "rogue", *_leaf(rogue_key, rogue_cert, "alice", ExtendedKeyUsageOID.CLIENT_AUTH))
