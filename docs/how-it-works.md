# How it works

## Cryptography

| Component | Algorithm |
|-----------|-----------|
| Master Key Derivation | Argon2id (64 MB memory, 3 iterations, 4 parallelism) |
| Per-Entry Keys | HKDF-SHA256 with a unique 16-byte CSPRNG salt per entry |
| Encryption | AES-256-GCM authenticated encryption (metadata included in the ciphertext) |
| File permissions | Vault directory 0700, database 0600 (POSIX) |

See [SECURITY.md](../SECURITY.md) for threat model and vulnerability reporting.

## Key hierarchy

```
Master Password
      |
      v
   Argon2id (64MB memory, 3 iterations)
      |
      v
   256-bit Master Key
      |
      +---> Verification hash (stored)
      |
      +---> HKDF-SHA256 (unique salt per entry)
              |
              v
           AES-256-GCM
              |
              v
           One authenticated blob per entry (stored):
           service + username + URL + password
```
