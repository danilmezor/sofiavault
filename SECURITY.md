# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SofiaVault, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **danil.zanozin@gmail.com**

You should receive a response within 48 hours. Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Threat Model

SofiaVault is designed to protect passwords at rest on a single machine. It protects against:

- Unauthorized access to the vault database file
- Brute-force attacks on the master password (via Argon2id memory-hard KDF)
- Rainbow table attacks (via unique per-entry salts)
- Ciphertext tampering (via AES-256-GCM authenticated encryption)

It does **not** protect against:

- Keyloggers or malware on the host machine
- Shoulder surfing (passwords are displayed in plaintext when retrieved)
- A compromised master password
- Memory forensics while the application is running

## Cryptographic Details

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Key Derivation | Argon2id | 64 MB memory, 3 iterations, 4 parallelism |
| Encryption | AES-256-GCM | 12-byte nonce, 256-bit key |
| Salt | CSPRNG | 16 bytes per entry |
| Random | `secrets` module | OS-level CSPRNG |
