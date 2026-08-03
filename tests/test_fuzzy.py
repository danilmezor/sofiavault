"""Tests for SofiaVault fuzzy matching."""

from sofiavault import VaultEntry, fuzzy_find_service


def _entries():
    return [
        VaultEntry(1, "amazon", "user1", ""),
        VaultEntry(2, "google", "user2", ""),
        VaultEntry(3, "netflix", "user3", ""),
        VaultEntry(4, "github", "user4", ""),
        VaultEntry(5, "facebook", "user5", ""),
    ]


def test_exact_match_high_score():
    results = fuzzy_find_service(_entries(), "amazon")
    assert len(results) >= 1
    assert results[0][0].service == "amazon"
    assert results[0][1] == 100


def test_fuzzy_match_typo():
    results = fuzzy_find_service(_entries(), "amazn")
    assert len(results) >= 1
    assert results[0][0].service == "amazon"
    assert results[0][1] >= 60


def test_fuzzy_match_case_insensitive():
    results = fuzzy_find_service(_entries(), "GOOGLE")
    assert len(results) >= 1
    assert results[0][0].service == "google"


def test_no_match_below_threshold():
    results = fuzzy_find_service(_entries(), "zzzzzzz", threshold=60)
    assert len(results) == 0


def test_empty_index_returns_empty():
    results = fuzzy_find_service([], "anything")
    assert results == []


def test_duplicate_service_names_matched_individually():
    entries = [
        VaultEntry(1, "amazon", "personal", ""),
        VaultEntry(2, "amazon", "work", ""),
    ]
    results = fuzzy_find_service(entries, "amazon")
    matched_ids = {e.id for e, _score in results}
    assert matched_ids == {1, 2}
