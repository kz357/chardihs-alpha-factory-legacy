#!/usr/bin/env python3
"""Generate a self-signed TLS certificate for the chardihs_frontend relay.

Usage:
    python gen_cert.py [--ip 1.2.3.4] [--dns example.com] [--days 3650] [--out-dir certs/]

The certificate includes these Subject Alternative Names:
  - DNSName: localhost          (SSH tunnel access)
  - IPAddress: 127.0.0.1
  - IPAddress: <--ip>           (server public IP, if provided)
  - DNSName: <--dns>            (domain name, if provided)

Modern browsers require a SAN entry matching the host you connect to.
When accessing by IP, the IP must appear in the SAN — the CN alone is not enough.

Note: if you have a real domain, prefer a free Let's Encrypt cert via a reverse
proxy (Caddy does it automatically) — no browser warnings. Self-signed is for
IP-only access.
"""

import argparse
import datetime
import ipaddress
import os
import stat
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ip", default=None, help="Server public IP to include in SAN")
    parser.add_argument("--dns", default=None, help="Domain name to include in SAN")
    parser.add_argument("--days", type=int, default=3650, help="Validity period in days (default: 3650)")
    parser.add_argument("--out-dir", default="certs", help="Output directory (default: certs/)")
    args = parser.parse_args()

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        print("ERROR: 'cryptography' package required. Run: pip install cryptography")
        sys.exit(1)

    os.makedirs(args.out_dir, exist_ok=True)
    cert_path = os.path.join(args.out_dir, "server.crt")
    key_path = os.path.join(args.out_dir, "server.key")

    print("Generating RSA-4096 private key (this may take a few seconds)…")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    san_entries: list = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    if args.ip:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(args.ip)))
            print(f"  SAN includes IPAddress: {args.ip}")
        except ValueError:
            print(f"WARNING: '{args.ip}' is not a valid IP address — skipping.")
    if args.dns:
        san_entries.append(x509.DNSName(args.dns))
        print(f"  SAN includes DNSName: {args.dns}")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "chardihs_frontend"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "chardihs_frontend"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    # Write private key — no passphrase (service needs to load it unattended)
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    # Restrict to owner read/write only (0o600) on Unix
    try:
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    except (AttributeError, NotImplementedError):
        pass  # Windows — skip

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # SHA-256 fingerprint — verify this in the browser when accepting the cert
    raw_fp = cert.fingerprint(hashes.SHA256()).hex()
    fp = ":".join(raw_fp[i:i+2].upper() for i in range(0, len(raw_fp), 2))

    print(f"\n  Certificate : {cert_path}")
    print(f"  Private key : {key_path}  (mode 0o600)")
    print(f"  Valid for   : {args.days} days")
    print(f"\n  SHA-256 fingerprint (verify in browser on first visit):")
    print(f"  {fp}")
    print(f"\nNext steps:")
    print(f"  1. export TLS_CERT={cert_path} TLS_KEY={key_path}")
    print(f"  2. python hash_password.py  →  export AUTH_PASSWORD_HASH='...'")
    print(f"  3. python server.py")
    print(f"  4. Open https://<host>:8765, accept the self-signed cert warning")
    print(f"     (check the fingerprint above matches what the browser shows)\n")


if __name__ == "__main__":
    main()
