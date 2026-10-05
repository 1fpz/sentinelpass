from sentinel_pass.generator import generate_passphrase
from sentinel_pass.matcher import find_matches
from sentinel_pass.hibp import check_pwned


def test_generator_uses_requested_word_count():
    value = generate_passphrase(6, "_")
    assert len(value.split("_")) == 6


def test_matcher_finds_dictionary_and_year():
    matches = find_matches("MyPassword2026")
    kinds = {m.kind for m in matches}
    assert "dictionary" in kinds
    assert "year" in kinds


def test_hibp_password_has_expected_prefix_for_demo():
    # HIBP's documented demo password is "password" with SHA-1 prefix 5BAA6.
    result = check_pwned("password", timeout=0.01)
    assert result.prefix == "5BAA6"
