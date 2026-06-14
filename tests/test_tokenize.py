"""Tests for reversible tokenization (--mode tokenize) and detokenize."""

import tempfile
from pathlib import Path

import pytest

from cloakpii.tokenize import Tokenizer, TOKEN_PREFIX
from cloakpii.crypto import CryptoError
from cloakpii.pii import desensitize_csv, desensitize_parquet
from cloakpii.migrate import run_migration, decrypt_tree, detokenize_tree


class TestTokenizerCore:
    def test_deterministic(self):
        t = Tokenizer("pw")
        assert t.tokenize("wei@corp.cn") == t.tokenize("wei@corp.cn")

    def test_cross_instance_stable(self):
        # Same password, different instances → same token (joins across runs)
        assert Tokenizer("pw").tokenize("x@y.cn") == Tokenizer("pw").tokenize("x@y.cn")

    def test_distinct_values_distinct_tokens(self):
        t = Tokenizer("pw")
        assert t.tokenize("a@b.cn") != t.tokenize("c@d.cn")

    def test_reversible(self):
        t = Tokenizer("pw")
        for v in ["wei@corp.cn", "138-1234-5678", "李伟", ""]:
            if v:
                assert t.detokenize(t.tokenize(v)) == v

    def test_token_format(self):
        assert Tokenizer("pw").tokenize("x").startswith(TOKEN_PREFIX)

    def test_idempotent_no_double_tokenize(self):
        t = Tokenizer("pw")
        tok = t.tokenize("x@y.cn")
        assert t.tokenize(tok) == tok

    def test_different_password_different_token(self):
        assert Tokenizer("pw1").tokenize("x@y.cn") != Tokenizer("pw2").tokenize("x@y.cn")

    def test_wrong_password_cannot_reverse(self):
        tok = Tokenizer("right").tokenize("secret@x.cn")
        with pytest.raises(CryptoError):
            Tokenizer("wrong").detokenize(tok)

    def test_empty_password_rejected(self):
        with pytest.raises(CryptoError):
            Tokenizer("")

    def test_detokenize_text_embedded(self):
        t = Tokenizer("pw")
        tok = t.tokenize("a@b.cn")
        assert t.detokenize_text(f"contact {tok} now") == "contact a@b.cn now"


class TestTokenizeInFormats:
    def test_csv_join_preserved(self):
        t = Tokenizer("pw")
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.csv"
            out = Path(tmp) / "out.csv"
            src.write_text("email,city\nwei@corp.cn,SH\nwei@corp.cn,BJ\nli@corp.cn,SH\n")
            desensitize_csv(src, out, mode="tokenize", tokenizer=t)
            rows = out.read_text().splitlines()
            # Same email → same token on both rows (join/dedup preserved)
            assert rows[1].split(",")[0] == rows[2].split(",")[0]
            assert rows[1].split(",")[0] != rows[3].split(",")[0]
            # Token is reversible
            assert t.detokenize(rows[1].split(",")[0]) == "wei@corp.cn"

    def test_parquet_tokenize_detokenize_roundtrip(self):
        # Binary columnar format must round-trip via re-parsing, not text replace
        pa = pytest.importorskip("pyarrow")
        pq = pytest.importorskip("pyarrow.parquet")
        t = Tokenizer("pw")
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.parquet"
            tok = Path(tmp) / "tok.parquet"
            back = Path(tmp) / "back.parquet"
            pq.write_table(pa.table({"email": ["a@x.cn", "a@x.cn", "b@x.cn"]}), src)
            desensitize_parquet(src, tok, mode="tokenize", tokenizer=t)
            toks = pq.read_table(tok).column("email").to_pylist()
            assert toks[0] == toks[1] and toks[0] != toks[2]      # join preserved
            desensitize_parquet(tok, back, mode="detokenize", tokenizer=t)
            assert pq.read_table(back).column("email").to_pylist() == ["a@x.cn", "a@x.cn", "b@x.cn"]


class TestEndToEnd:
    def test_migrate_tokenize_then_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            out = Path(tmp) / "out"
            dec = Path(tmp) / "dec"
            orig = Path(tmp) / "orig"
            src.mkdir()
            (src / "u.csv").write_text("email,city\nwei@corp.cn,SH\nwei@corp.cn,BJ\n")

            run_migration(source_dir=src, output_dir=out, password="pw",
                          mode="tokenize", show_progress=False, generate_manifest=False)

            decrypt_tree(out / "encrypted", dec, "pw")
            # Decrypted file is tokenized, not the original
            assert "wei@corp.cn" not in (dec / "u.csv").read_text()

            report = detokenize_tree(dec, orig, "pw")
            assert report["total_detokenized"] == 1
            assert report["total_errors"] == 0
            # Fully restored
            assert (orig / "u.csv").read_text() == "email,city\nwei@corp.cn,SH\nwei@corp.cn,BJ\n"

    def test_mask_mode_unaffected(self):
        # Default mode still masks irreversibly (no tokens)
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            out = Path(tmp) / "out"
            src.mkdir()
            (src / "u.csv").write_text("email\nwei@corp.cn\n")
            run_migration(source_dir=src, output_dir=out, password="pw",
                          show_progress=False, generate_manifest=False)
            content = (out / "desensitized" / "u.csv").read_text()
            assert TOKEN_PREFIX not in content
            assert "wei@corp.cn" not in content
