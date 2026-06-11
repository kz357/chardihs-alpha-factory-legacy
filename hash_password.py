#!/usr/bin/env python3
"""Generate an argon2id password hash for the chardihs_frontend relay.

Usage:
    python hash_password.py

Then export the hash before starting the server:
    export AUTH_PASSWORD_HASH='<paste here>'      # single quotes — hash contains $
    python server.py

Or in a systemd EnvironmentFile (no quoting/escaping needed there):
    AUTH_PASSWORD_HASH=<paste here>

Parameters follow OWASP recommended minimums for argon2id:
  time_cost=3, memory_cost=64MB, parallelism=4
"""

import sys


def main() -> None:
    try:
        from argon2 import PasswordHasher
    except ImportError:
        print("ERROR: 'argon2-cffi' required. Run: pip install argon2-cffi")
        sys.exit(1)

    import getpass

    pw1 = getpass.getpass("Enter password: ")
    if not pw1:
        print("ERROR: password cannot be empty")
        sys.exit(1)

    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        print("ERROR: passwords do not match")
        sys.exit(1)

    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)
    hashed = ph.hash(pw1)

    print("\nSet this before starting the server (single quotes matter — the hash contains $):\n")
    print(f"  export AUTH_PASSWORD_HASH='{hashed}'\n")


if __name__ == "__main__":
    main()
