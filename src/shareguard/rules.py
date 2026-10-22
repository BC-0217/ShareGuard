"""Detection rules.

Independently written, generic public-format patterns. All patterns are
single-line (no character class may match a newline) and use bounded
quantifiers. Matching code never stores or returns matched text: callers only
receive rule metadata, a confidence and the match position.

Placeholder policy (precise, documented):
* A value is excluded only when it *entirely* is an explicit placeholder or a
  reference: empty, a complete template/environment/variable reference
  (``${X}``, ``$X``, ``%X%``, ``{{ x }}``, ``$(cmd)``, ``<your-password>``...),
  a mask (``xxx``, ``***``), an explicit "your ... here" phrase, or one of a
  small set of exact marker words (``placeholder``, ``redacted``,
  ``changeme``, ``string``, code literals ``null``/``none``/``true``...).
  Substrings never suppress a value: ``mysampleValue9`` is still a finding.
* Recognizable token formats are never suppressed by body content, except
  exact documented example keys and bodies made of one repeated character.
* There is no entropy-only detection and no minimum length for literals;
  short literals are reported with low confidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

CATEGORY_PRIVATE_KEY = "private_key"
CATEGORY_TOKEN = "service_token"
CATEGORY_ASSIGNMENT = "credential_assignment"
CATEGORY_URL = "url_credential"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    confidences: tuple  # allowed confidences, strongest first
    description: str

    @property
    def confidence(self) -> str:
        return self.confidences[0]


@dataclass(frozen=True)
class Match:
    rule: Rule
    start: int
    confidence: str


# --------------------------------------------------------------------------
# Placeholder / reference recognition (fullmatch only)
# --------------------------------------------------------------------------

_REFERENCE_RE = re.compile(
    r"""
      \$[A-Za-z_][A-Za-z0-9_]{0,127}                 # $VAR
    | \$\{\{[^\r\n]{0,128}\}\}                       # ${{ secrets.X }}
    | \$\{[^{}\r\n]{1,128}\}                         # ${VAR} / ${VAR:-x}
    | \{\{[^\r\n]{0,128}\}\}                         # {{ var }}
    | \$\([^()\r\n]{1,128}\)                         # $(command)
    | %[A-Za-z_][A-Za-z0-9_]{0,127}%                 # %VAR%
    | %\([A-Za-z_][A-Za-z0-9_]{0,127}\)[sdr]         # %(name)s
    | %[sdr]                                         # %s
    | \{[A-Za-z0-9_]{0,64}\}                         # {} / {0} / {name}
    | <[^<>\r\n]{1,128}>                             # <your-password>
    """,
    re.X,
)

_MASK_RE = re.compile(r"(?:x{3,}|X{3,}|\*{3,}|\.{3,}|#{3,}|-{3,}|_{3,}|\u2022{3,}|\?{3,})")

_KW = (r"(?:api[_\- ]?key|password|passwd|pass|secret|client[_\- ]?secret"
       r"|access[_\- ]?token|auth[_\- ]?token|token|key)")
_YOUR_HERE_RE = re.compile(
    rf"(?:(?:your|my|enter|insert|replace|put)[_\- ]?(?:own[_\- ]?)?(?:real[_\- ]?)?{_KW}"
    rf"(?:[_\- ]?here)?|{_KW}[_\- ]?here)",
    re.I,
)

_EXACT_MARKERS = frozenset({
    "placeholder", "redacted", "[redacted]", "changeme", "change_me", "change-me",
    "string", "null", "none", "nil", "undefined", "true", "false",
})

# Unquoted values that are code references rather than literals.
_CODE_ROOTS = (
    "os.environ", "os.getenv", "process.env", "env", "settings", "config", "cfg",
    "conf", "self", "this", "cls", "args", "kwargs", "opts", "options", "params",
    "request", "req", "ctx", "context", "props", "secrets", "vars", "creds",
    "credentials", "form", "data", "body", "input",
)
_CODE_REFERENCE_RE = re.compile(
    r"(?:" + "|".join(re.escape(r) for r in _CODE_ROOTS) + r")(?:\.[A-Za-z_][A-Za-z0-9_]*)+",
    re.I,
)
_TYPE_NAMES = frozenset({
    "str", "string", "bytes", "int", "bool", "boolean", "any", "object", "text",
    "secretstr", "secretbytes", "optional", "char", "varchar",
})
_SQL_PARAM_RE = re.compile(r"(?:\?|[:@][A-Za-z_][A-Za-z0-9_]{0,63})")
_KEYWORD_IN_IDENT_RE = re.compile(r"[A-Za-z_]*(?:pass|secret|token|key)[A-Za-z_]*", re.I)

# Exact documented example credentials (vendor documentation samples).
_DOCUMENTED_EXAMPLES = frozenset({"AKIAIOSFODNN7EXAMPLE"})


def is_placeholder(value: str) -> bool:
    """True only for an explicit placeholder or a complete reference."""
    v = value.strip()
    if not v:
        return True
    if _REFERENCE_RE.fullmatch(v) or _MASK_RE.fullmatch(v) or _YOUR_HERE_RE.fullmatch(v):
        return True
    return v.lower() in _EXACT_MARKERS


def _token_excluded(full: str, body: str) -> bool:
    return full in _DOCUMENTED_EXAMPLES or len(set(body)) == 1


# --------------------------------------------------------------------------
# Rule table
# --------------------------------------------------------------------------

_HIGH = ("high",)
_ASSIGN = ("medium", "low")


def _r(rule_id, category, severity, confidences, description):
    return Rule(rule_id, category, severity, confidences, description)


PEM_PRIVATE = _r("private-key.pem", CATEGORY_PRIVATE_KEY, "high", _HIGH,
                 "PEM private key header")
OPENSSH_PRIVATE = _r("private-key.openssh", CATEGORY_PRIVATE_KEY, "high", _HIGH,
                     "OpenSSH private key header")
PGP_PRIVATE = _r("private-key.pgp", CATEGORY_PRIVATE_KEY, "high", _HIGH,
                 "PGP private key block header")
PUTTY_PRIVATE = _r("private-key.putty", CATEGORY_PRIVATE_KEY, "high", _HIGH,
                   "PuTTY private key file header")
SSH2_PRIVATE = _r("private-key.ssh2", CATEGORY_PRIVATE_KEY, "high", _HIGH,
                  "SSH2 encrypted private key header")

AWS_KEY_ID = _r("token.aws-access-key-id", CATEGORY_TOKEN, "medium", _HIGH,
                "AWS access key ID format")
GITHUB = _r("token.github", CATEGORY_TOKEN, "high", _HIGH, "GitHub token format")
GITLAB = _r("token.gitlab", CATEGORY_TOKEN, "high", _HIGH, "GitLab token format")
SLACK = _r("token.slack", CATEGORY_TOKEN, "high", _HIGH, "Slack token format")
SLACK_WEBHOOK = _r("token.slack-webhook", CATEGORY_TOKEN, "medium", _HIGH,
                   "Slack incoming webhook URL")
STRIPE = _r("token.stripe-live", CATEGORY_TOKEN, "high", _HIGH,
            "Stripe live secret/restricted key format")
GOOGLE_API = _r("token.google-api-key", CATEGORY_TOKEN, "medium", _HIGH,
                "Google API key format")
OPENAI = _r("token.openai", CATEGORY_TOKEN, "high", _HIGH, "OpenAI API key format")
ANTHROPIC = _r("token.anthropic", CATEGORY_TOKEN, "high", _HIGH,
               "Anthropic API key format")
NPM = _r("token.npm", CATEGORY_TOKEN, "high", _HIGH, "npm access token format")
PYPI = _r("token.pypi", CATEGORY_TOKEN, "high", _HIGH, "PyPI API token format")
SENDGRID = _r("token.sendgrid", CATEGORY_TOKEN, "high", _HIGH, "SendGrid API key format")

ASSIGN_PASSWORD = _r("assignment.password", CATEGORY_ASSIGNMENT, "medium", _ASSIGN,
                     "Literal password assignment")
ASSIGN_API_KEY = _r("assignment.api-key", CATEGORY_ASSIGNMENT, "medium", _ASSIGN,
                    "Literal API key assignment")
ASSIGN_CLIENT_SECRET = _r("assignment.client-secret", CATEGORY_ASSIGNMENT, "medium",
                          _ASSIGN, "Literal client secret assignment")
ASSIGN_TOKEN = _r("assignment.access-token", CATEGORY_ASSIGNMENT, "medium", _ASSIGN,
                  "Literal access/auth/refresh token assignment")
ASSIGN_SECRET_KEY = _r("assignment.secret-key", CATEGORY_ASSIGNMENT, "medium", _ASSIGN,
                       "Literal secret key assignment")

URL_CREDENTIALS = _r("url.credentials", CATEGORY_URL, "high", ("medium",),
                     "Credentials embedded in URL")

RULES = (
    PEM_PRIVATE, OPENSSH_PRIVATE, PGP_PRIVATE, PUTTY_PRIVATE, SSH2_PRIVATE,
    AWS_KEY_ID, GITHUB, GITLAB, SLACK, SLACK_WEBHOOK, STRIPE, GOOGLE_API,
    OPENAI, ANTHROPIC, NPM, PYPI, SENDGRID,
    ASSIGN_PASSWORD, ASSIGN_API_KEY, ASSIGN_CLIENT_SECRET, ASSIGN_TOKEN,
    ASSIGN_SECRET_KEY, URL_CREDENTIALS,
)
RULES_BY_ID = {rule.rule_id: rule for rule in RULES}


# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

# Header-only patterns: certificates and public keys never match.
# (Written with -{n} quantifiers so this source file does not match itself.)
_HEADER_PATTERNS = (
    (re.compile(r"-{5}BEGIN OPENSSH PRIVATE KEY-{5}"), OPENSSH_PRIVATE),
    (re.compile(r"-{5}BEGIN PGP PRIVATE KEY BLOCK-{5}"), PGP_PRIVATE),
    (re.compile(r"-{5}BEGIN (?:(?:RSA|DSA|EC|DH|ENCRYPTED) )?PRIVATE KEY-{5}"),
     PEM_PRIVATE),
    (re.compile(r"PuTTY-User-Key-File-[23]: "), PUTTY_PRIVATE),
    (re.compile(r"-{4} BEGIN SSH2 ENCRYPTED PRIVATE KEY -{4}"), SSH2_PRIVATE),
)

# (pattern, rule); group 1 holds the variable token body.
_TOKEN_PATTERNS = (
    (re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)([A-Z0-9]{16})(?![A-Za-z0-9])"),
     AWS_KEY_ID),
    (re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_([A-Za-z0-9]{36,251})(?![A-Za-z0-9_])"),
     GITHUB),
    (re.compile(r"(?<![A-Za-z0-9_])github_pat_([A-Za-z0-9]{22}_[A-Za-z0-9]{59})"
                r"(?![A-Za-z0-9_])"), GITHUB),
    (re.compile(r"(?<![A-Za-z0-9_\-])glpat-([A-Za-z0-9_\-]{20,64})(?![A-Za-z0-9_\-])"),
     GITLAB),
    (re.compile(r"(?<![A-Za-z0-9_\-])xox[abprs]-((?:[0-9]{6,20}-){1,3}[A-Za-z0-9]{8,64})"
                r"(?![A-Za-z0-9\-])"), SLACK),
    (re.compile(r"https://hooks\.slack\.com/services/"
                r"(T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,32})"
                r"(?![A-Za-z0-9])"), SLACK_WEBHOOK),
    (re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_live_([A-Za-z0-9]{24,99})(?![A-Za-z0-9_])"),
     STRIPE),
    (re.compile(r"(?<![A-Za-z0-9_\-])AIza([A-Za-z0-9_\-]{35})(?![A-Za-z0-9_\-])"),
     GOOGLE_API),
    (re.compile(r"(?<![A-Za-z0-9_\-])sk-(?:proj-|svcacct-|admin-)?"
                r"([A-Za-z0-9_\-]{16,200}T3BlbkFJ[A-Za-z0-9_\-]{16,200})"
                r"(?![A-Za-z0-9_\-])"), OPENAI),
    (re.compile(r"(?<![A-Za-z0-9_\-])sk-ant-(?:api|admin)[0-9]{2}-([A-Za-z0-9_\-]{80,120})"
                r"(?![A-Za-z0-9_\-])"), ANTHROPIC),
    (re.compile(r"(?<![A-Za-z0-9_])npm_([A-Za-z0-9]{36})(?![A-Za-z0-9_])"), NPM),
    (re.compile(r"(?<![A-Za-z0-9_\-])pypi-AgEIcHlwaS5vcmc([A-Za-z0-9_\-]{50,250})"
                r"(?![A-Za-z0-9_\-])"), PYPI),
    (re.compile(r"(?<![A-Za-z0-9_\-.])SG\.([A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})"
                r"(?![A-Za-z0-9_\-])"), SENDGRID),
)

_KEYWORD_GROUPS = (
    ("client_secret", ASSIGN_CLIENT_SECRET),
    ("access_token", ASSIGN_TOKEN),
    ("auth_token", ASSIGN_TOKEN),
    ("refresh_token", ASSIGN_TOKEN),
    ("secret_key", ASSIGN_SECRET_KEY),
    ("api_key", ASSIGN_API_KEY),
    ("apikey", ASSIGN_API_KEY),
    ("password", ASSIGN_PASSWORD),
    ("passwd", ASSIGN_PASSWORD),
    ("passphrase", ASSIGN_PASSWORD),
)

_ASSIGNMENT_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_.\-])
    ["']?
    (?P<key>[A-Za-z0-9_.\-]{0,64}?
        (?:client[_\-.]?secret|access[_\-.]?token|auth[_\-.]?token
          |refresh[_\-.]?token|secret[_\-.]?key|api[_\-.]?key|apikey
          |password|passwd|passphrase))
    ["']?
    [ \t]{0,16}
    (?::=|=>|=|:)(?!=)
    [ \t]{0,16}
    (?:
        "(?P<dq>(?:[^"\\\r\n]|\\.){0,256})"
      | '(?P<sq>(?:[^'\\\r\n]|\\.){0,256})'
      | (?P<tpl>\$\{\{[^\r\n}]{0,128}\}\}|\$\{[^\r\n}]{0,128}\}|\$\([^\r\n)]{0,128}\)
               |\{\{[^\r\n}]{0,128}\}\}|%[A-Za-z_][A-Za-z0-9_]{0,127}%)
      | (?P<uq>[^\s"'`,;\#&|<>(){}\[\]]{1,256})
    )
    """,
    re.X | re.I,
)

_URL_CRED_RE = re.compile(
    r"(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{1,19}://"
    r"(?P<user>[^\s:/?#@'\"<>\\]{0,128}):(?P<pw>[^\s/?#@'\"<>\\]{1,256})@"
    r"(?=[A-Za-z0-9\[])"
)

_URL_PLACEHOLDER_PAIRS = frozenset({
    ("user", "pass"), ("user", "password"), ("username", "password"),
    ("user", "pwd"), ("username", "pass"), ("login", "password"),
})

_SHORT_LITERAL = 8  # literals shorter than this are reported with low confidence


def _classify_key(key: str) -> Rule:
    norm = re.sub(r"[\-.]", "_", key.lower())
    for keyword, rule in _KEYWORD_GROUPS:
        if norm.endswith(keyword):
            return rule
    return ASSIGN_PASSWORD


def _is_code_reference(value: str, following: str) -> bool:
    """Unquoted value that is a code expression, not a literal."""
    if following == "(" or following == "[":
        return True  # call or subscript expression
    low = value.lower()
    if low in _TYPE_NAMES:
        return True
    if value[0] in "!*&$%":  # YAML tags/aliases, shell/env/template references
        return True
    if _CODE_REFERENCE_RE.fullmatch(value) or _SQL_PARAM_RE.fullmatch(value):
        return True
    # Variable names that themselves name a credential (password=new_password).
    return bool(_KEYWORD_IN_IDENT_RE.fullmatch(value))


def _assignment_confidence(m: re.Match) -> str | None:
    """Return confidence for a literal assignment, or None to ignore it."""
    if m.group("tpl") is not None:
        return None
    quoted = m.group("dq")
    if quoted is None:
        quoted = m.group("sq")
    if quoted is not None:
        if is_placeholder(quoted):
            return None
        return "medium" if len(quoted) >= _SHORT_LITERAL else "low"
    value = m.group("uq")
    if is_placeholder(value):
        return None
    following = m.string[m.end(): m.end() + 1]
    if _is_code_reference(value, following):
        return None
    return "low"


def _url_confidence(m: re.Match) -> str | None:
    user, pw = m.group("user"), m.group("pw")
    if is_placeholder(pw) or pw[0] in "$%":
        return None
    if (user.lower(), pw.lower()) in _URL_PLACEHOLDER_PAIRS:
        return None
    return "medium"


_HEADER_HINTS = ("PRIVATE KEY", "PuTTY-User-Key-File-")
_TOKEN_HINTS = ("AKIA", "ASIA", "gh", "github_pat_", "glpat-", "xox", "hooks.slack.com",
                "_live_", "AIza", "T3BlbkFJ", "sk-ant-", "npm_", "pypi-", "SG.")
_ASSIGNMENT_HINTS = ("pass", "secret", "key", "token")


def iter_matches(text: str) -> Iterator[Match]:
    """Lazily yield matches in ``text`` (any order). Never exposes text.

    Cheap substring prefilters skip regexes that cannot match.
    """
    if any(hint in text for hint in _HEADER_HINTS):
        for pattern, rule in _HEADER_PATTERNS:
            for m in pattern.finditer(text):
                yield Match(rule, m.start(), rule.confidence)
    if any(hint in text for hint in _TOKEN_HINTS):
        for pattern, rule in _TOKEN_PATTERNS:
            for m in pattern.finditer(text):
                if not _token_excluded(m.group(0), m.group(1)):
                    yield Match(rule, m.start(), rule.confidence)
    lowered = text.lower()
    if any(hint in lowered for hint in _ASSIGNMENT_HINTS):
        for m in _ASSIGNMENT_RE.finditer(text):
            confidence = _assignment_confidence(m)
            if confidence is not None:
                yield Match(_classify_key(m.group("key")), m.start(), confidence)
    if "://" in text and "@" in text:
        for m in _URL_CRED_RE.finditer(text):
            confidence = _url_confidence(m)
            if confidence is not None:
                yield Match(URL_CREDENTIALS, m.start(), confidence)


# Longest possible single match; used to size overlap windows.
MAX_MATCH_CHARS = 1024
