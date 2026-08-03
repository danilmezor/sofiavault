"""Tests for SofiaVault cryptographic operations."""

import secrets

import pytest
from cryptography.exceptions import InvalidTag

from sofiavault import (
    KEY_SIZE,
    SALT_SIZE,
    decrypt,
    derive_entry_key,
    derive_key,
    encrypt,
)


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


def test_derive_entry_key_length_and_deterministic():
    master_key = secrets.token_bytes(KEY_SIZE)
    salt = secrets.token_bytes(SALT_SIZE)
    key1 = derive_entry_key(master_key, salt)
    key2 = derive_entry_key(master_key, salt)
    assert len(key1) == KEY_SIZE
    assert key1 == key2


def test_derive_entry_key_different_salts_differ():
    master_key = secrets.token_bytes(KEY_SIZE)
    key1 = derive_entry_key(master_key, secrets.token_bytes(SALT_SIZE))
    key2 = derive_entry_key(master_key, secrets.token_bytes(SALT_SIZE))
    assert key1 != key2


def test_encrypt_decrypt_roundtrip():
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key("masterpassword", salt)
    plaintext = "my_secret_password_123!"

    nonce, ciphertext = encrypt(plaintext, key)
    result = decrypt(nonce, ciphertext, key)

    assert result == plaintext


def test_encrypt_decrypt_with_aad_roundtrip():
    key = secrets.token_bytes(KEY_SIZE)
    aad = b"sofiavault-entry-v2"

    nonce, ciphertext = encrypt("secret", key, aad=aad)
    assert decrypt(nonce, ciphertext, key, aad=aad) == "secret"


def test_decrypt_wrong_aad_fails():
    key = secrets.token_bytes(KEY_SIZE)

    nonce, ciphertext = encrypt("secret", key, aad=b"context-a")

    with pytest.raises(InvalidTag):
        decrypt(nonce, ciphertext, key, aad=b"context-b")
    with pytest.raises(InvalidTag):
        decrypt(nonce, ciphertext, key)  # missing AAD must also fail


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

    with pytest.raises(InvalidTag):
        decrypt(nonce, ciphertext, key2)
