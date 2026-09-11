from guard.secrets import SecretList, secret_paths, _parse

SECRET = "zz-testsecret-0123456789abcdef"


def test_parse_and_mask(tmp_path):
    env = tmp_path / "a.env"
    env.write_text(
        f"FAKE_KEY={SECRET}\n"
        f"export EXPORTED='{SECRET}xx'\n"
        "URLISH=https://example.com/x?y=1234567890123\n"
        "SHORT=abc\n"
        "# COMMENT=zz-commented-0123456789\n"
        "not a kv line\n"
    )
    s = SecretList([str(env)])
    assert s.names == ["EXPORTED", "FAKE_KEY"]
    masked, counts = s.mask(f"key is {SECRET} and again {SECRET}; longer {SECRET}xx; url https://example.com/x?y=1234567890123")
    assert SECRET not in masked
    assert counts == {"FAKE_KEY": 2, "EXPORTED": 1}
    assert "1234567890123" in masked, "URL-ish values are not masked by design"
    assert s.contains(f"echo {SECRET}") == ["FAKE_KEY"]
    assert s.contains("nothing here") == []


def test_export_prefix_is_a_prefix_not_a_charset(tmp_path):
    env = tmp_path / "a.env"
    env.write_text(f"export tokenish_key={SECRET}\nexpo_key={SECRET}z\n")
    assert sorted(_parse(str(env)).values()) == ["expo_key", "tokenish_key"]


def test_missing_files_are_skipped(tmp_path):
    s = SecretList([str(tmp_path / "nope.env")])
    assert len(s) == 0
    assert s.mask("anything") == ("anything", {})


def test_refresh_on_file_change(tmp_path):
    env = tmp_path / "a.env"
    s = SecretList([str(env)])          # does not exist yet
    assert len(s) == 0
    env.write_text(f"NEW_KEY={SECRET}\n")
    s._at = 0.0                          # skip the 30 s debounce
    assert s.mask(SECRET)[1] == {"NEW_KEY": 1}


def test_secret_paths_env_var(monkeypatch):
    monkeypatch.setenv("LLM_GUARD_SECRET_FILES", "/a/.env:/b/.env")
    assert secret_paths({"secret_files": ["/c/.env"]}) == ["/c/.env", "/a/.env", "/b/.env"]
    monkeypatch.delenv("LLM_GUARD_SECRET_FILES")
    assert secret_paths({}) == []


def test_encoded_forms_are_masked(tmp_path):
    import base64
    env = tmp_path / "a.env"
    env.write_text(f"FAKE_KEY={SECRET}\n")
    s = SecretList([str(env)])
    assert len(s) == 1                       # plain values only
    for prefix in (b"", b"x", b"xy", b"xyz"):     # every base64 alignment
        blob = base64.b64encode(prefix + SECRET.encode() + b"tail-bytes").decode()
        masked, counts = s.mask(f"payload: {blob}")
        assert counts == {"FAKE_KEY": 1}, (prefix, blob)
        assert "<<REDACTED:FAKE_KEY>>" in masked
    urlsafe = base64.urlsafe_b64encode(SECRET.encode()).decode().rstrip("=")
    assert s.contains(urlsafe) == ["FAKE_KEY"]
    assert s.contains(SECRET.encode().hex()) == ["FAKE_KEY"]
    assert s.contains(SECRET.encode().hex().upper()) == ["FAKE_KEY"]
    assert s.contains("plain text with nothing") == []


def test_encoded_forms_do_not_false_positive_on_short_values(tmp_path):
    env = tmp_path / "a.env"
    env.write_text("K=abcdefghijkl\n")   # exactly 12 chars
    s = SecretList([str(env)])
    assert s.contains("YWJjZGVmZ2hpamts") == ["K"]     # base64 of the value itself
    assert s.contains("YWJjZGVmZ2hp") == []          # a prefix of it: too short to count
