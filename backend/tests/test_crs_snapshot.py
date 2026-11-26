from pathlib import Path
import subprocess

from services import crs_index


def test_switches_to_published_ruleset_and_checks_its_digest(tmp_path, monkeypatch):
    for name in ("_index_dir", "_marker_key", "_status", "CRS_INDEX", "_snapshot_indexes"):
        monkeypatch.setattr(crs_index, name, getattr(crs_index, name))
    source = tmp_path / "source"
    source.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir()
    rule = source / "REQUEST-LOCAL.conf"
    script = Path(__file__).resolve().parents[2] / "nginx/docker-entrypoint.d/09-seed-crs.sh"
    monkeypatch.setenv("WAF_CRS_SOURCE_DIR", str(source))
    monkeypatch.setenv("WAF_SHARED_DIR", str(shared))

    rule.write_text('SecRule ARGS:q "@streq first" "id:10001,phase:2,log"\n')
    subprocess.run(["sh", str(script)], check=True)
    root = shared / "crs-rules"
    assert crs_index.initialize_crs_index(root)["state"] == "verified"
    first = crs_index.get_rule("10001")
    assert first.operator == "@streq first"

    rule.write_text('SecRule ARGS:q "@streq second" "id:10001,phase:2,log"\n')
    subprocess.run(["sh", str(script)], check=True)
    second = crs_index.get_rule("10001")
    assert second.operator == "@streq second"
    assert second.ruleset_digest != first.ruleset_digest
    # An alert that fired under the first snapshot is still analysed against the first rule.
    assert crs_index.get_rule_at("10001", first.ruleset_digest).operator == "@streq first"
    assert crs_index.get_rule_at("10001", second.ruleset_digest).operator == "@streq second"
    assert crs_index.get_rule_at("10001", None).operator == "@streq second"
    assert crs_index.get_rule_at("10001", "b" * 64) is None
    # If the active snapshot switches mid-lookup, a rule from the other snapshot is never returned.
    get_rule = crs_index.get_rule
    monkeypatch.setattr(crs_index, "get_rule", lambda _: first)
    assert crs_index.get_rule_at("10001", second.ruleset_digest) is None
    monkeypatch.setattr(crs_index, "get_rule", get_rule)

    marker = root / ".active-snapshot"
    fake_digest = "a" * 64
    fake = root / ".snapshots" / fake_digest
    fake.mkdir()
    (fake / rule.name).write_bytes(rule.read_bytes())
    marker.write_text(fake_digest + "\n")
    assert crs_index.get_rule("10001") is None
    assert crs_index.index_status()["state"] == "mismatched"
