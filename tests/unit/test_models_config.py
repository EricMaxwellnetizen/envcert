import pytest

from envicert.core.config import load_settings
from envicert.core.errors import ConfigError
from envicert.core.models import Finding, Severity, Status, is_failure


def test_severity_rank_and_failure():
    f = Finding("EC999", "t", "d", "cat", Severity.HIGH, Status.FAIL)
    assert Severity.CRITICAL.rank > Severity.HIGH.rank
    assert is_failure(f, {Severity.HIGH})
    f2 = Finding("EC999", "t", "d", "cat", Severity.LOW, Status.PASS)
    assert not is_failure(f2, {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW})


def test_default_settings():
    s = load_settings(None, None, None)
    assert s.profile == "harbor"
    assert Severity.CRITICAL in s.fail_on


def test_strict_profile_fail_on():
    s = load_settings(None, "strict", None)
    assert Severity.MEDIUM in s.fail_on


def test_unknown_profile_rejected(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(None, "nope", None)


def test_bad_config_values(tmp_path):
    cfg = tmp_path / "envicert.toml"
    cfg.write_text('[policy]\nfail_on = ["banana"]\n', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(cfg, None, None)


def test_config_file_overrides(tmp_path):
    cfg = tmp_path / "envicert.toml"
    cfg.write_text('[envicert]\nprofile = "minimal"\n[checks]\ndisabled = ["EC031"]\n', encoding="utf-8")
    s = load_settings(cfg, None, None)
    assert s.profile == "minimal"
    assert "EC031" in s.disabled
    assert s.categories is not None and "docker" not in s.categories


def test_missing_config_file(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(tmp_path / "absent.toml", None, None)
