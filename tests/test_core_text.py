"""Encoding, chunk boundary, line numbering and long-line handling."""

import os

from tests import SECRET_CANARY, WorkDirTestCase, codes, pem_header, synthetic, token
from shareguard.model import COMPLETE, INCOMPLETE
from shareguard.policy import Policy
from shareguard.scanner import scan_paths


def assignment(seed=1):
    return f'password = "{SECRET_CANARY}{synthetic(8, seed)}"'


class TextHandling(WorkDirTestCase):
    def scan_text_bytes(self, data: bytes, name="f.txt", policy=None):
        p = self.write(name, data)
        return scan_paths([p], policy=policy)

    def test_line_numbers_crlf(self):
        body = "a\r\nb\r\n" + token("github") + "\r\nc\r\n" + assignment() + "\r\n"
        r = self.scan_text_bytes(body.encode())
        self.assertEqual(r.completeness, COMPLETE)
        self.assertEqual(sorted((f.line, f.rule_id) for f in r.findings),
                         [(3, "token.github"), (5, "assignment.password")])

    def test_duplicate_matches_on_a_line_are_counted(self):
        t = token("npm")
        r = self.scan_text_bytes(f"{t} {t} {t}\n".encode())
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].count, 3)

    def test_utf8_bom_and_non_ascii(self):
        text = "한글 주석\n" + pem_header() + "\n"
        r = self.scan_text_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
        self.assertEqual(r.completeness, COMPLETE)
        self.assertEqual([(f.rule_id, f.line) for f in r.findings], [("private-key.pem", 2)])

    def test_utf16_with_bom(self):
        text = "설정\n" + assignment() + "\n"
        for enc in ("utf-16", "utf-16-le", "utf-16-be"):
            with self.subTest(enc=enc):
                data = text.encode(enc)
                if enc == "utf-16-le":
                    data = b"\xff\xfe" + data
                elif enc == "utf-16-be":
                    data = b"\xfe\xff" + data
                r = self.scan_text_bytes(data, name=f"{enc}.txt")
                self.assertEqual(r.completeness, COMPLETE)
                self.assertEqual([(f.rule_id, f.line) for f in r.findings],
                                 [("assignment.password", 2)])

    def test_utf16_without_bom(self):
        text = "config\n" + token("gitlab") + "\n"
        for enc in ("utf-16-le", "utf-16-be"):
            with self.subTest(enc=enc):
                r = self.scan_text_bytes(text.encode(enc), name=f"nobom-{enc}.txt")
                self.assertEqual(r.completeness, COMPLETE)
                self.assertEqual([f.rule_id for f in r.findings], ["token.gitlab"])

    def test_utf32_is_unsupported_incomplete(self):
        r = self.scan_text_bytes(("x\n" + token("npm")).encode("utf-32"))
        self.assertEqual(r.completeness, INCOMPLETE)
        self.assertIn("UNSUPPORTED_ENCODING", codes(r))

    def test_invalid_utf8_is_incomplete_but_still_scanned(self):
        data = "주석".encode("cp949") + b"\n" + token("stripe").encode() + b"\n"
        r = self.scan_text_bytes(data)
        self.assertEqual(r.completeness, INCOMPLETE)
        self.assertIn("UNSUPPORTED_ENCODING", codes(r))
        self.assertEqual([f.rule_id for f in r.findings], ["token.stripe-live"])

    def test_binary_is_incomplete(self):
        r = self.scan_text_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + os.urandom(64))
        self.assertEqual(r.completeness, INCOMPLETE)
        self.assertEqual(codes(r), {"BINARY_CONTENT"})

    def test_tiny_binary_not_mistaken_for_utf16(self):
        """Regression: short NUL-containing blobs once decoded as BOM-less
        UTF-16 and were reported complete."""
        for data in (b"\x00\x01", b"\x00\x01\x02", b"\x01\x00\x02\x00", b"\x00\x00\x00\x00"):
            with self.subTest(data=data):
                r = self.scan_text_bytes(data, name="tiny.bin")
                self.assertEqual(codes(r), {"BINARY_CONTENT"})

    def test_nul_after_sniff_window_is_binary(self):
        data = b"a" * 10000 + b"\x00" * 10 + b"\n"
        r = self.scan_text_bytes(data)
        self.assertIn("BINARY_CONTENT", codes(r))

    def test_other_archive_formats_incomplete(self):
        r = self.scan_text_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 20, name="x.gz")
        self.assertEqual(codes(r), {"UNSUPPORTED_ARCHIVE"})

    def test_secret_across_chunk_and_sniff_boundaries(self):
        t = token("github")
        for boundary in (4096, 65536, 65536 + 4096):
            with self.subTest(boundary=boundary):
                prefix = ("z" * 99 + "\n") * (boundary // 100) + "y" * (boundary % 100 - 11) + " "
                data = (prefix + t + "\nend\n").encode()
                r = self.scan_text_bytes(data, name=f"b{boundary}.txt")
                self.assertEqual(r.completeness, COMPLETE)
                self.assertEqual([f.rule_id for f in r.findings], ["token.github"])
                self.assertEqual(r.findings[0].line, boundary // 100 + 1)

    def test_long_line_is_windowed_and_incomplete(self):
        policy = Policy(max_line_chars=10_000)
        t = token("github")
        # Secrets at the start, straddling every window edge, and at the end.
        parts = [t]
        for i in range(1, 8):
            parts.append("q" * (9_000 - len(t)) + " " + t)
        line = " ".join(parts) + " " + "w" * 3000 + " " + t
        data = ("first\n" + line + "\nlast " + token("npm") + "\n").encode()
        r = self.scan_text_bytes(data, policy=policy)
        self.assertEqual(r.completeness, INCOMPLETE)
        self.assertEqual(codes(r), {"LINE_TOO_LONG"})
        got = {(f.rule_id, f.line): f.count for f in r.findings}
        self.assertEqual(got, {("token.github", 2): 9, ("token.npm", 3): 1})

    def test_long_line_without_newline_at_eof(self):
        policy = Policy(max_line_chars=5000)
        t = token("aws")
        data = ("k" * 12000 + " " + t).encode()
        r = self.scan_text_bytes(data, policy=policy)
        self.assertIn("LINE_TOO_LONG", codes(r))
        self.assertEqual([(f.rule_id, f.line) for f in r.findings],
                         [("token.aws-access-key-id", 1)])

    def test_env_example_not_blanket_ignored(self):
        body = ("# synthetic fixture\nDB_PASSWORD=changeme\nAPI_KEY=${API_KEY}\n"
                f"STRIPE_KEY={token('stripe')}\nCLIENT_SECRET=\"{synthetic(16, 3)}\"\n")
        r = self.scan_text_bytes(body.encode(), name=".env.example")
        self.assertEqual(sorted((f.rule_id, f.line) for f in r.findings),
                         [("assignment.client-secret", 5), ("token.stripe-live", 4)])

    def test_certificate_file_clean(self):
        cert = ("-" * 5 + "BEGIN CERTIFICATE" + "-" * 5 + "\n" + synthetic(64, 9) + "\n"
                + "-" * 5 + "END CERTIFICATE" + "-" * 5 + "\n")
        r = self.scan_text_bytes(cert.encode(), name="server.crt")
        self.assertEqual(r.completeness, COMPLETE)
        self.assertEqual(r.findings, [])

    def test_empty_file_complete(self):
        r = self.scan_text_bytes(b"")
        self.assertEqual(r.completeness, COMPLETE)
        self.assertEqual(r.counts["files_scanned"], 1)
