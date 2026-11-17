"""A pre-registration survives a line-ending change, and nothing else.

Found on 17 Nov 2026: the merged H2c and H3c verdicts refused to run because
.gitattributes (eol=lf) checked their CRLF-written pre-registrations out as LF.
"""
import hashlib

from eval.followup import sha_matches


def test_crlf_record_verifies_after_an_lf_checkout(tmp_path):
    p = tmp_path / "prereg.json"
    p.write_bytes(b'{\r\n  "id": "H2c"\r\n}\r\n')
    recorded = hashlib.sha256(p.read_bytes()).hexdigest()
    p.write_bytes(b'{\n  "id": "H2c"\n}\n')          # what eol=lf checks out
    assert sha_matches(p, recorded)


def test_lf_record_verifies_after_a_crlf_checkout(tmp_path):
    p = tmp_path / "prereg.json"
    p.write_bytes(b"a\nb\n")
    recorded = hashlib.sha256(p.read_bytes()).hexdigest()
    p.write_bytes(b"a\r\nb\r\n")
    assert sha_matches(p, recorded)


def test_a_changed_character_still_fails(tmp_path):
    p = tmp_path / "prereg.json"
    p.write_bytes(b'{\r\n  "auc_ceiling": 0.6\r\n}\r\n')
    recorded = hashlib.sha256(p.read_bytes()).hexdigest()
    p.write_bytes(b'{\n  "auc_ceiling": 0.7\n}\n')
    assert not sha_matches(p, recorded)
