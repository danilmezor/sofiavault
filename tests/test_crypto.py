"""Tests for SofiaVault cryptographic operations."""

import secrets

from sofiavault import KEY_SIZE, SALT_SIZE, decrypt, derive_key, encrypt


def test_derive_key_produces_correct_length():
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key("testpassword", salt)
    assert len(key) == KEY_SIZE


def test_derive_key_deterministic():
    salt = secrets.token_bytes(SALT_SIZE)
    key1 = derive_key("testpassword", salt)
    key2 = derive_key("testpassword", salt)
    assert key1 == key2


def test_derive_key_different_salts_produce_different_keys():
    salt1 = secrets.token_bytes(SALT_SIZE)
    salt2 = secrets.token_bytes(SALT_SIZE)
    key1 = derive_key("testpassword", salt1)
    key2 = derive_key("testpassword", salt2)
    assert key1 != key2


def test_derive_key_different_passwords_produce_different_keys():
    salt = secrets.token_bytes(SALT_SIZE)
    key1 = derive_key("password1", salt)
    key2 = derive_key("password2", salt)
    assert key1 != key2


def test_encrypt_decrypt_roundtrip():
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key("masterpassword", salt)
    plaintext = "my_secret_password_123!"

    nonce, ciphertext = encrypt(plaintext, key)
    result = decrypt(nonce, ciphertext, key)

    assert result == plaintext


def test_encrypt_decrypt_unicode():
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key("masterpassword", salt)
    plaintext = "p@$$w0rd-with-unicode-chars"

    nonce, ciphertext = encrypt(plaintext, key)
    result = decrypt(nonce, ciphertext, key)

    assert result == plaintext


def test_encrypt_produces_unique_ciphertexts():
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key("masterpassword", salt)
    plaintext = "same_password"

    nonce1, ct1 = encrypt(plaintext, key)
    nonce2, ct2 = encrypt(plaintext, key)

    # Different nonces should produce different ciphertexts
    assert nonce1 != nonce2
    assert ct1 != ct2


def test_decrypt_wrong_key_fails():
    salt1 = secrets.token_bytes(SALT_SIZE)
    salt2 = secrets.token_bytes(SALT_SIZE)
    key1 = derive_key("password1", salt1)
    key2 = derive_key("password2", salt2)

    nonce, ciphertext = encrypt("secret", key1)

    import pytest
    from cryptography.exceptions import InvalidTag
    with pytest.raises(InvalidTag):
        decrypt(nonce, ciphertext, key2)
