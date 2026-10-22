"""Rule positives, negatives and placeholder exclusions (synthetic data)."""

import unittest

from tests import pem_header, synthetic, token
from shareguard import rules


def ids(text):
    return sorted({m.rule.rule_id for m in rules.iter_matches(text)})


class PrivateKeyRules(unittest.TestCase):
    def test_pem_variants(self):
        for label in ("", "RSA ", "EC ", "DSA ", "ENCRYPTED "):
            self.assertEqual(ids(pem_header(label)), ["private-key.pem"], label)

    def test_openssh_pgp_putty_ssh2(self):
        self.assertEqual(ids(pem_header("OPENSSH ")), ["private-key.openssh"])
        pgp = "-" * 5 + "BEGIN PGP PRIVATE KEY BLOCK" + "-" * 5
        self.assertEqual(ids(pgp), ["private-key.pgp"])
        self.assertEqual(ids("PuTTY-User-Key-File-3: ssh-ed25519"), ["private-key.putty"])
        ssh2 = "-" * 4 + " BEGIN SSH2 ENCRYPTED PRIVATE KEY " + "-" * 4
        self.assertEqual(ids(ssh2), ["private-key.ssh2"])

    def test_public_keys_and_certificates_do_not_match(self):
        for label in ("PUBLIC KEY", "RSA PUBLIC KEY", "CERTIFICATE",
                      "CERTIFICATE REQUEST", "PGP PUBLIC KEY BLOCK", "X509 CRL"):
            text = "-" * 5 + "BEGIN " + label + "-" * 5
            self.assertEqual(ids(text), [], label)
        self.assertEqual(ids("ssh-ed25519 " + synthetic(68, 3) + " user@host"), [])
        self.assertEqual(ids("---- BEGIN SSH2 PUBLIC KEY ----"), [])


class TokenRules(unittest.TestCase):
    EXPECT = {
        "aws": "token.aws-access-key-id",
        "github": "token.github",
        "github_pat": "token.github",
        "gitlab": "token.gitlab",
        "slack": "token.slack",
        "slack_webhook": "token.slack-webhook",
        "stripe": "token.stripe-live",
        "google": "token.google-api-key",
        "openai": "token.openai",
        "anthropic": "token.anthropic",
        "npm": "token.npm",
        "pypi": "token.pypi",
        "sendgrid": "token.sendgrid",
    }

    def test_each_format_detected(self):
        for kind, rule_id in self.EXPECT.items():
            with self.subTest(kind=kind):
                self.assertIn(rule_id, ids(f"value: {token(kind)}\n"))

    def test_embedded_in_longer_identifier_not_matched(self):
        self.assertEqual(ids("x" + token("github")), [])
        self.assertEqual(ids(token("aws") + "Q"), [])

    def test_only_exact_placeholder_tokens_excluded(self):
        samples = [
            "AKIA" + "IOSFODNN7" + "EXAMPLE",   # vendor-documented example key
            "ghp_" + "x" * 36,                  # single repeated character
            "glpat-" + "X" * 20,
            "npm_" + "0" * 36,
        ]
        for s in samples:
            self.assertEqual(ids(s), [], s)

    def test_token_bodies_with_marker_words_or_low_variety_still_flag(self):
        """Regression: body substrings/variety must not hide real formats."""
        samples = {
            "gh" + "p_" + "Example" + synthetic(29, 40): "token.github",
            "gh" + "p_" + "fake" + synthetic(32, 41): "token.github",
            "sk" + "_live_" + "sample" + synthetic(26, 42): "token.stripe-live",
            "gh" + "p_" + "0123" * 9: "token.github",
            "np" + "m_" + "ab" * 18: "token.npm",
            "AK" + "IA" + "EXAMPLE" + synthetic(9, 43, "ABCDEFGHJKLMNP0123456789"):
                "token.aws-access-key-id",
        }
        for s, rule_id in samples.items():
            self.assertEqual(ids(s), [rule_id], s)


class AssignmentRules(unittest.TestCase):
    def test_quoted_and_unquoted_literals(self):
        value = synthetic(14, 11)
        cases = {
            f'password = "{value}"': ("assignment.password", "medium"),
            f"DB_PASSWORD={value}9": ("assignment.password", "low"),
            f'"client_secret": "{value}"': ("assignment.client-secret", "medium"),
            f"api_key: '{value}'": ("assignment.api-key", "medium"),
            f"apiKey => '{value}'": ("assignment.api-key", "medium"),
            f'ACCESS_TOKEN="{value}"': ("assignment.access-token", "medium"),
            f"secret-key := \"{value}\"": ("assignment.secret-key", "medium"),
            f"spring.datasource.password: {value}7": ("assignment.password", "low"),
        }
        for text, (rule_id, conf) in cases.items():
            with self.subTest(text=text):
                ms = list(rules.iter_matches(text))
                self.assertEqual([(m.rule.rule_id, m.confidence) for m in ms],
                                 [(rule_id, conf)])

    def test_exact_placeholders_and_references_excluded(self):
        texts = [
            'password = "changeme"',
            'password = "${DB_PASSWORD}"',
            'password = "${DB_PASSWORD:-}"',
            "password=$DB_PASSWORD",
            "password=%DB_PASSWORD%",
            'password: "<your-password>"',
            'password = "********"',
            'password = "xxxxxxxx"',
            "password: ${{ secrets.DB_PASSWORD }}",
            "password: {{ vault_password }}",
            "password = $(cat /run/secret)",
            'password = os.environ["DB_PASSWORD"]',
            "password = process.env.DB_PASSWORD",
            "password = get_password()",
            "password = self.password",
            "password = settings.DB_PASSWORD",
            "password = new_password",
            "password=password",
            "password = None",
            "password: str",
            "password: string;",
            'password = ""',
            'api_key = "YOUR_API_KEY_HERE"',
            'api_key = "your-api-key"',
            'client_secret = "{{ client_secret }}"',
            'password = "REDACTED"',
            'password = "%s"',
            "password = ?",
            "password = :password",
            "password: !vault |",
            "password: *default_password",
            'passwordHint = "anything"',
        ]
        for t in texts:
            self.assertEqual(ids(t), [], t)

    def test_literals_with_marker_substrings_dots_or_letters_flag(self):
        """Regression for over-broad placeholder suppression."""
        cases = {
            "password='mysampleRealP@ss987'": "medium",
            'api_key = "AbcExample9RealKey_28"': "medium",
            'access_token = "sample-is-part-of-a-real-value-8420"': "medium",
            "password=CorrectHorseBatteryStaple": "low",
            "password=S3cure.pass987": "low",
            'password = "S3cure.pass987"': "medium",
            "PASSWORD=letmein": "low",
            'password = "admin"': "low",
            '"password": "1234"': "low",
            "password=Abcdefgh": "low",
            'password = "short"': "low",
            "password = user_supplied_value": "low",
        }
        for text, conf in cases.items():
            with self.subTest(text=text):
                ms = list(rules.iter_matches(text))
                self.assertEqual([(m.rule.category, m.confidence) for m in ms],
                                 [("credential_assignment", conf)])

    def test_is_placeholder_is_exact(self):
        for v in ("AbcExample9RealKey_28", "sample-is-part-of-a-real-value-8420",
                  "letmein", "admin", "fake-but-real-123", "x<y>z", "${A}b"):
            self.assertFalse(rules.is_placeholder(v), v)
        for v in ("", "  ", "${A}", "<secret>", "***", "placeholder", "YOUR_TOKEN_HERE",
                  "{{ x }}", "%APPDATA%"):
            self.assertTrue(rules.is_placeholder(v), v)

    def test_comparisons_and_unrelated_keys_not_assignments(self):
        value = synthetic(12, 5)
        for t in (f'if password == "{value}":', f'password != "{value}"',
                  "password_length = 12", "password_policy: strict",
                  f'passwordHint = "{value}"', "max_api_key_count = 20000"):
            self.assertEqual(ids(t), [], t)


class UrlCredentialRules(unittest.TestCase):
    def test_url_credentials(self):
        pw = synthetic(12, 21)
        self.assertEqual(ids(f"postgres://svc:{pw}@db.internal:5432/app"),
                         ["url.credentials"])
        self.assertEqual(ids(f"https://deploy:{pw}@git.example.org/repo.git"),
                         ["url.credentials"])

    def test_url_placeholders_excluded(self):
        for t in ("https://user:password@host/x", "https://${USER}:${PASS}@host/x",
                  "redis://:$REDIS_PASSWORD@cache:6379", "https://host/path?a=b@c",
                  "mailto:someone@host", "https://user:pass@host",
                  "https://deploy:<token>@host/x"):
            self.assertEqual(ids(t), [], t)

    def test_url_short_or_marker_password_still_flags(self):
        for t in ("redis://:hunter2@cache:6379", "ftp://admin:admin@10.0.0.1/",
                  "https://bot:sampletoken99@host/x"):
            self.assertEqual(ids(t), ["url.credentials"], t)


class NoEntropyOnly(unittest.TestCase):
    def test_random_blob_alone_is_not_a_finding(self):
        self.assertEqual(ids(synthetic(64, 77) + "\n" + synthetic(40, 78)), [])


if __name__ == "__main__":
    unittest.main()
