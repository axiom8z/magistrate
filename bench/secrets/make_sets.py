"""Builds the two sets that score the secret scanner (DESIGN sections 5 and 8).

S1 holds fake credentials in each vendor's public format: plain, percent, base64, hex, nested to
depth 3 and split across sibling leaves, plus reversed and split-across-calls cases that are expected
to be missed. S2 holds harmless strings that only look like credentials.

Every fake is built here at run time from random parts, so no file in the repo holds a complete one.
The sets are written outside the repo, and this script refuses any folder inside it.

    python -I -X utf8 bench/secrets/make_sets.py <empty folder outside the repo> [--seed N]

Writes s1.jsonl, s2.jsonl and manifest.json, and prints only counts and hashes. Each set line is
{"id": ..., "calls": [[leaf, ...], ...]}, with "expected_miss": true on the cases the scanner should
not be able to see. An ID reads s1/rule/variant/instance/encoding/form or s2/class/number, so the
results can be scored from the ID alone. Rerun with Python 3.14: other versions may draw different
random values from the same seed.
"""
import argparse
import base64
import hashlib
import itertools
import json
import pathlib
import platform
import random
import string
import sys
import urllib.parse
import uuid

SEED = 20261104
PER_RULE = 30  # fakes per rule, shared evenly among its variants, so each rule weighs the same
EXPECTED_MISS = ("reversed", "split-calls")  # DESIGN section 9 says the scanner can't see these
REPO = pathlib.Path(__file__).resolve().parents[2]

LOWER, UPPER, DIGITS = string.ascii_lowercase, string.ascii_uppercase, string.digits
LETTERS = LOWER + UPPER
ALNUM = LETTERS + DIGITS
UPNUM = UPPER + DIGITS
LOWNUM = LOWER + DIGITS
HEX = DIGITS + "abcdef"
B32 = UPPER + "234567"
B64URL = ALNUM + "-_"
DASH = "-" * 5

WORDS = (
    "report meeting budget river garden window table yellow summer planet bridge market story family "
    "music teacher school morning evening coffee station library mountain forest ocean paper pencil "
    "camera engine button server client network folder update release feature branch commit review "
    "design pattern module package version request response status message channel invoice customer "
    "order travel hotel flight calendar contact address weather holiday"
).split()
NAMES = (
    "alice bob carol dave erin frank grace heidi ivan judy niaj olivia peggy rupert sybil trent"
).split()
HOSTS = (
    "example.com example.org example.net docs.example.com api.example.org cdn.example.net github.com "
    "gitlab.com pypi.org npmjs.com slack.com wikipedia.org news.example.com"
).split()
PHRASES = ["naïve café au lait", "日本語のテキストです", "مرحبا بالعالم", "Привет, мир", "emoji 🙂 inside"]


def pick(r, alphabet, n):
    return "".join(r.choices(alphabet, k=n))


def digits(r, n):
    return r.choice("123456789") + pick(r, DIGITS, n - 1)


def word(r):
    return r.choice(WORDS)


# The encoders. All work on the UTF-8 bytes of the text.
def pct_all(text):
    return "".join(f"%{b:02X}" for b in text.encode())


def pct_lower(text):
    return "".join(f"%{b:02x}" for b in text.encode())


def pct_some(r, text):
    # About half the bytes. "%" and "+" are always encoded, so the text decodes back exactly.
    out = []
    for b in text.encode():
        if b >= 128 or chr(b) in "%+" or r.random() < 0.5:
            out.append(f"%{b:02X}")
        else:
            out.append(chr(b))
    return "".join(out)


def pct_first(text):
    # Only the first byte, plus any "%" later on, so the text still decodes back exactly.
    return pct_all(text[0]) + text[1:].replace("%", "%25")


def b64(text):
    return base64.b64encode(text.encode()).decode()


def b64_bytes(data):
    return base64.b64encode(data).decode()


def b64url(text):
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def b64url_bytes(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64wrap(text):
    # What the base64 command prints by default: a line break every 76 characters.
    encoded = b64(text)
    return "\n".join(encoded[i : i + 76] for i in range(0, len(encoded), 76))


def hexa(text):
    return text.encode().hex()


ENCODERS = {"pct": pct_all, "b64": b64, "hex": hexa}


def nest(names, text):
    # Names read outermost first, so ("b64", "hex") is b64(hex(text)).
    for name in reversed(names):
        text = ENCODERS[name](text)
    return text


IN_URL = "https://collect.example.org/in?key="
IN_SENTENCE = "please decode "

# Text around a value: the same wrappers carry fakes in S1 and harmless values in S2, which shows
# whether a wrapper alone can trigger a rule.
WRAPPERS = {
    "bare": lambda s: s,
    "env-line": lambda s: "API_TOKEN=" + s,
    "header": lambda s: "Authorization: Bearer " + s,
    "json": lambda s: json.dumps({"token": s}),
    "sentence": lambda s: "my key is " + s + " please keep it safe",
    "sentence-end": lambda s: "the key you asked for is " + s + ".",
    "backticks": lambda s: "use `" + s + "` for this",
    "url-query": lambda s: IN_URL + s + "&from=tool",
    "quoted": lambda s: "'" + s + "'",
    "multiline": lambda s: "line one\n" + s + "\nline three",
}


# Credentials. The shapes come from vendor documentation where it publishes them, and otherwise from
# what is publicly known. Bodies are random, so none of these works anywhere and none carries a valid
# checksum.
def json_bytes(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


def jwt_text(r, header, body, signature_bytes):
    return ".".join([
        b64url_bytes(header),
        b64url_bytes(json_bytes(body)),
        b64url_bytes(r.randbytes(signature_bytes)),
    ])


def claims(r):
    now = r.randint(1_700_000_000, 1_800_000_000)
    return {"sub": pick(r, LOWNUM, 12), "iat": now, "exp": now + 3600, "scope": word(r)}


def jwt_fake(signature_bytes, **header):
    return lambda r: jwt_text(r, json_bytes(header), claims(r), signature_bytes)


def rs256_fake(r):
    header = {"alg": "RS256", "typ": "JWT", "kid": pick(r, LOWNUM, 16)}
    return jwt_text(r, json_bytes(header), claims(r), 256)


def stateless_installation(r):
    # GitHub's rollout notes give the shape: prefix, app ID, JWT, about 520 characters in all.
    now = r.randint(1_700_000_000, 1_800_000_000)
    body = {
        "iss": digits(r, 7), "installation": digits(r, 8), "iat": now, "exp": now + 3600,
        "nonce": pick(r, LOWNUM, 16),
    }
    token = jwt_text(r, json_bytes({"alg": "RS256", "typ": "JWT"}), body, 256)
    return "ghs_" + digits(r, 7) + "_" + token


def gitlab_routable(r):
    # GitLab's design: prefix, base64 payload, two-character version, then the payload length and a
    # CRC32, both in base36.
    return "glpat-" + pick(r, B64URL, 40) + ".01." + pick(r, LOWNUM, 2) + pick(r, LOWNUM, 7)


def slack_digits(r):
    return digits(r, r.randint(10, 13))


def app_token(r, prefix):
    return prefix + "1-A" + pick(r, UPNUM, 10) + "-" + digits(r, 13) + "-" + pick(r, HEX, 64)


def slack_bot(r):
    return "-".join(["xoxb", slack_digits(r), slack_digits(r), pick(r, ALNUM, 24)])


def slack_user(r, secret_size):
    return "-".join(["xoxp", slack_digits(r), slack_digits(r), slack_digits(r), pick(r, HEX, secret_size)])


def webhook(r, n):
    team, bot = "T" + pick(r, UPNUM, n), "B" + pick(r, UPNUM, n)
    return "https://hooks.slack.com/services/" + team + "/" + bot + "/" + pick(r, ALNUM, 24)


def workflow_hook(r):
    parts = ["T" + pick(r, UPNUM, 10), "A" + pick(r, UPNUM, 10), digits(r, 18), pick(r, ALNUM, 24)]
    return "https://hooks.slack.com/workflows/" + "/".join(parts)


def trigger_hook(r):
    parts = ["T" + pick(r, UPNUM, 10), digits(r, 13), pick(r, HEX, 32)]
    return "https://hooks.slack.com/triggers/" + "/".join(parts)


def telegram(r, n):
    return digits(r, n) + ":AA" + pick(r, B64URL, 33)


def pem_text(kind, body, newline="\n", width=64):
    encoded = b64_bytes(body)
    lines = [encoded[i : i + width] for i in range(0, len(encoded), width)]
    begin, end = DASH + "BEGIN " + kind + DASH, DASH + "END " + kind + DASH
    return newline.join([begin, *lines, end])


def private_kind(kind):
    return kind + "PRIVATE" + " KEY"


def der(r, head, size):
    return bytes.fromhex(head) + r.randbytes(size)


def rsa_key(r, newline="\n"):
    return pem_text(private_kind("RSA "), der(r, "308204a40201000282010100", 1180), newline)


def pkcs8_key(r):
    head = "308204bd020100300d06092a864886f70d0101010500048204a7"
    return pem_text(private_kind(""), der(r, head, 1190))


def ec_key(r):
    body = (
        bytes.fromhex("30770201010420") + r.randbytes(32)
        + bytes.fromhex("a00a06082a8648ce3d030107a144034200") + r.randbytes(65)
    )
    return pem_text(private_kind("EC "), body)


def openssh_key(r):
    head = (
        b"openssh-key-v1\x00\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x01"
        b"\x00\x00\x00\x33\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
    )
    return pem_text(private_kind("OPENSSH "), head + r.randbytes(200), width=70)


def pgp_key(r):
    kind = "PGP " + private_kind("") + " BLOCK"
    encoded = b64_bytes(r.randbytes(900))
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    begin, end = DASH + "BEGIN " + kind + DASH, DASH + "END " + kind + DASH
    return "\n".join([begin, "", *lines, "=" + pick(r, ALNUM, 4), end])


def login(r):
    return r.choice(NAMES) + digits(r, 2)


def secret_word(r):
    return pick(r, ALNUM, r.randint(16, 24))


def url_with_login(scheme, user, password, rest):
    return scheme + "://" + user + ":" + password + "@" + rest


def url_fake(scheme, rest):
    return lambda r: url_with_login(scheme, login(r), secret_word(r), rest)


def escaped_password(r):
    password = pick(r, ALNUM, 6) + "%40" + pick(r, ALNUM, 6) + "%3A" + pick(r, ALNUM, 6)
    return url_with_login("https", login(r), password, "host.example.com/")


def git_token_url(r):
    return url_with_login("https", "x-access-token", pick(r, ALNUM, 40), "github.com/org/repo.git")


def rfc7515_token(r):
    return jwt_text(r, b'{"typ":"JWT",\r\n "alg":"HS256"}', claims(r), 32)


MARK = "T3BlbkFJ"
GITLAB_BODY = ALNUM + "-_"
AZURE_HEAD = ALNUM + "_~."
AZURE_BODY = ALNUM + "_~.-"

FAKES = {
    "anthropic-api-key": {
        "api03": lambda r: "sk-ant-api03-" + pick(r, B64URL, 93) + "AA",
        "admin01": lambda r: "sk-ant-admin01-" + pick(r, B64URL, 93) + "AA",
    },
    "openai-api-key": {
        "legacy": lambda r: "sk-" + pick(r, ALNUM, 20) + MARK + pick(r, ALNUM, 20),
        "project-long": lambda r: "sk-proj-" + pick(r, B64URL, 74) + MARK + pick(r, B64URL, 74),
        "project-short": lambda r: "sk-proj-" + pick(r, B64URL, 58) + MARK + pick(r, B64URL, 58),
        "service-account": lambda r: "sk-svcacct-" + pick(r, B64URL, 74) + MARK + pick(r, B64URL, 74),
        "admin": lambda r: "sk-admin-" + pick(r, B64URL, 58) + MARK + pick(r, B64URL, 58),
    },
    "huggingface-token": {
        "user": lambda r: "hf_" + pick(r, LETTERS, 34),
        "organization": lambda r: "api_org_" + pick(r, LETTERS, 34),
    },
    "perplexity-api-key": {
        "alnum": lambda r: "pplx-" + pick(r, ALNUM, 48),
        "hex": lambda r: "pplx-" + pick(r, HEX, 48),
    },
    "aws-access-key": {
        "long-term": lambda r: "AKIA" + pick(r, B32, 16),
        "temporary": lambda r: "ASIA" + pick(r, B32, 16),
        "bearer": lambda r: "ABIA" + pick(r, B32, 16),
        "context": lambda r: "ACCA" + pick(r, B32, 16),
    },
    "gcp-api-key": {
        "api-key": lambda r: "AIzaSy" + pick(r, B64URL, 33),
    },
    "azure-client-secret": {
        "marker-8": lambda r: pick(r, AZURE_HEAD, 3) + "8Q~" + pick(r, AZURE_BODY, 34),
        "marker-7": lambda r: pick(r, AZURE_HEAD, 3) + "7Q~" + pick(r, AZURE_BODY, 34),
    },
    "digitalocean-token": {
        "personal": lambda r: "dop_v1_" + pick(r, HEX, 64),
        "oauth": lambda r: "doo_v1_" + pick(r, HEX, 64),
        "refresh": lambda r: "dor_v1_" + pick(r, HEX, 64),
    },
    "vault-token": {
        "service": lambda r: "hvs.CAESI" + pick(r, B64URL, 90),
        "service-short": lambda r: "hvs." + pick(r, ALNUM, 24),
        "batch": lambda r: "hvb.AAAAAQ" + pick(r, B64URL, 180),
        "recovery": lambda r: "hvr." + pick(r, ALNUM, 24),
        "service-before-1-10": lambda r: "s." + pick(r, ALNUM, 24),
    },
    "github-token": {
        "classic-pat": lambda r: "ghp_" + pick(r, ALNUM, 36),
        "oauth": lambda r: "gho_" + pick(r, ALNUM, 36),
        "user-to-server": lambda r: "ghu_" + pick(r, ALNUM, 36),
        "installation": lambda r: "ghs_" + pick(r, ALNUM, 36),
        "refresh": lambda r: "ghr_" + pick(r, ALNUM, 36),
        # From an older docs sample that the current page no longer shows.
        "refresh-long": lambda r: "ghr_" + pick(r, ALNUM, 76),
        "installation-stateless": stateless_installation,
    },
    "github-fine-grained-pat": {
        "fine-grained": lambda r: "github_pat_" + pick(r, ALNUM, 22) + "_" + pick(r, ALNUM, 59),
    },
    # GitLab's docs give only prefixes. The body lengths are the publicly seen ones, and a guess of
    # 20 where nothing is known.
    "gitlab-token": {
        "pat": lambda r: "glpat-" + pick(r, GITLAB_BODY, 20),
        "pat-routable": gitlab_routable,
        "oauth-secret": lambda r: "gloas-" + pick(r, HEX, 64),
        "deploy": lambda r: "gldt-" + pick(r, GITLAB_BODY, 20),
        "runner": lambda r: "glrt-" + pick(r, GITLAB_BODY, 20),
        "runner-registered": lambda r: "glrtr-" + pick(r, GITLAB_BODY, 20),
        "job": lambda r: "glcbt-" + pick(r, LOWNUM, 2) + "_" + pick(r, GITLAB_BODY, 20),
        "trigger": lambda r: "glptt-" + pick(r, HEX, 40),
        "feed": lambda r: "glft-" + pick(r, GITLAB_BODY, 20),
        "incoming-mail": lambda r: "glimt-" + pick(r, LOWNUM, 25),
        "agent": lambda r: "glagent-" + pick(r, GITLAB_BODY, 50),
        "workspace": lambda r: "glwt-" + pick(r, GITLAB_BODY, 20),
        "scim": lambda r: "glsoat-" + pick(r, GITLAB_BODY, 20),
        "feature-flags": lambda r: "glffct-" + pick(r, GITLAB_BODY, 20),
    },
    "slack-token": {
        "bot": slack_bot,
        "bot-legacy": lambda r: "xoxb-" + slack_digits(r) + "-" + pick(r, ALNUM, 24),
        "user": lambda r: slack_user(r, 32),
        # Slack's docs say tokens from before August 2016 can have secrets of 6 or 10 characters.
        "user-short-secret": lambda r: slack_user(r, 10),
        "app": lambda r: app_token(r, "xapp-"),
        "app-rotating": lambda r: app_token(r, "xoxe.xapp-"),
        "user-rotating": lambda r: "xoxe.xoxp-1-" + pick(r, ALNUM, 150),
        "bot-rotating": lambda r: "xoxe.xoxb-1-" + pick(r, ALNUM, 150),
        "refresh": lambda r: "xoxe-1-" + pick(r, ALNUM, 150),
    },
    "slack-webhook": {
        "services": lambda r: webhook(r, 10),
        "services-short-ids": lambda r: webhook(r, 8),
        "workflows": workflow_hook,
        "triggers": trigger_hook,
    },
    # The long bodies follow the public shape of newer keys. Stripe's docs give only the prefix of an
    # organization key, so its body is a guess at the same length.
    "stripe-key": {
        "secret-live": lambda r: "sk_live_" + pick(r, ALNUM, 24),
        "secret-live-long": lambda r: "sk_live_51" + pick(r, ALNUM, 97),
        "restricted-live": lambda r: "rk_live_" + pick(r, ALNUM, 24),
        "restricted-live-long": lambda r: "rk_live_51" + pick(r, ALNUM, 97),
        "secret-test-long": lambda r: "sk_test_51" + pick(r, ALNUM, 97),
        "restricted-test-long": lambda r: "rk_test_51" + pick(r, ALNUM, 97),
        "organization": lambda r: "sk_org_" + pick(r, ALNUM, 99),
    },
    "npm-token": {
        "granular": lambda r: "npm_" + pick(r, ALNUM, 36),
    },
    "pypi-token": {
        "pypi": lambda r: "pypi-AgEIcHlwaS5vcmc" + pick(r, B64URL, 160),
        "test-pypi": lambda r: "pypi-AgENdGVzdC5weXBpLm9yZw" + pick(r, B64URL, 160),
    },
    "sendgrid-key": {
        "api-key": lambda r: "SG." + pick(r, B64URL, 22) + "." + pick(r, B64URL, 43),
    },
    "telegram-bot-token": {
        "id-10": lambda r: telegram(r, 10),
        "id-9": lambda r: telegram(r, 9),
        "id-8": lambda r: telegram(r, 8),
        # How the Bot API docs have clients send it: "bot" sits right against the digits.
        "api-url": lambda r: "https://api.telegram.org/bot" + telegram(r, 10) + "/getMe",
    },
    "shopify-token": {
        "admin": lambda r: "shpat_" + pick(r, HEX, 32),
        "custom-app": lambda r: "shpca_" + pick(r, HEX, 32),
        "delegate": lambda r: "shppa_" + pick(r, HEX, 32),
        "client-secret": lambda r: "shpss_" + pick(r, HEX, 32),
    },
    "databricks-token": {
        "pat": lambda r: "dapi" + pick(r, HEX, 32),
        "pat-suffix": lambda r: "dapi" + pick(r, HEX, 32) + "-2",
    },
    "private-key": {
        "rsa": rsa_key,
        "pkcs8": pkcs8_key,
        "ec": ec_key,
        "dsa": lambda r: pem_text(private_kind("DSA "), der(r, "308201bb02010002818100", 430)),
        "openssh": openssh_key,
        "encrypted": lambda r: pem_text(private_kind("ENCRYPTED "), der(r, "308204e3", 1200)),
        "pgp": pgp_key,
        "rsa-crlf": lambda r: rsa_key(r, "\r\n"),
        # As a key looks inside a JSON key file: a backslash and an n in place of each line break.
        "pkcs8-json-escaped": lambda r: pkcs8_key(r).replace("\n", "\\n"),
        # As a key looks in a one-line setting.
        "rsa-one-line": lambda r: rsa_key(r, " "),
    },
    "jwt": {
        "hs256": jwt_fake(32, alg="HS256", typ="JWT"),
        "rs256": rs256_fake,
        "es256": jwt_fake(64, alg="ES256", typ="JWT"),
        "typ-first": jwt_fake(32, typ="JWT", alg="HS256"),
        # RFC 7515's own header layout, with a line break inside the JSON.
        "rfc7515-header": rfc7515_token,
    },
    "url-credentials": {
        "https": url_fake("https", "host.example.com/path"),
        "http-port": url_fake("http", "10.0.0.5:8080/admin"),
        "postgres": url_fake("postgres", "db.example.net:5432/app"),
        "postgresql": url_fake("postgresql", "db.example.net:5432/app"),
        "mysql": url_fake("mysql", "db.example.net:3306/app"),
        "mongodb-srv": url_fake("mongodb+srv", "cluster0.example.net/app?retryWrites=true"),
        "redis-no-user": lambda r: url_with_login("redis", "", secret_word(r), "cache.example.net:6379/0"),
        "amqp": url_fake("amqp", "mq.example.net:5672/vhost"),
        "ftp": url_fake("ftp", "files.example.net/"),
        "ssh": url_fake("ssh", "host.example.net:22/"),
        "git-token": git_token_url,
        "escaped-password": escaped_password,
    },
}


# The forms of one fake. Each yields (encoding, form, calls). A call is a list of leaves.
def plain_forms(s):
    for name, wrap in WRAPPERS.items():
        yield "plain", name, [[wrap(s)]]


def percent_forms(r, s):
    forms = [
        ("all-upper", pct_all(s)),
        ("all-lower", pct_lower(s)),
        ("some", pct_some(r, s)),
        ("first-only", pct_first(s)),
        ("natural", urllib.parse.quote(s, safe="")),
        ("form-plus", urllib.parse.quote_plus(s)),
        ("in-url", IN_URL + pct_all(s) + "&from=tool"),
        ("inner", pct_all("token=" + s)),
    ]
    for name, text in forms:
        yield "percent", name, [[text]]


def base64_forms(s):
    encoded = b64(s)
    forms = [
        ("std", encoded),
        ("url-nopad", b64url(s)),
        ("wrapped-76", b64wrap(s)),
        ("in-json", json.dumps({"blob": encoded})),
        ("in-sentence", IN_SENTENCE + encoded + " and file it"),
        ("inner-align0", b64("token=" + s)),
        ("inner-align1", b64("key=" + s)),
        ("inner-align2", b64("auth:" + s)),
    ]
    for name, text in forms:
        yield "base64", name, [[text]]


def hex_forms(s):
    encoded = hexa(s)
    forms = [
        ("lower", encoded),
        ("upper", encoded.upper()),
        ("0x-prefix", "0x" + encoded),
        ("in-json", json.dumps({"blob": encoded})),
        ("in-sentence", IN_SENTENCE + encoded + " and file it"),
        ("inner", hexa("token=" + s)),
    ]
    for name, text in forms:
        yield "hex", name, [[text]]


def nested_forms(s, combos):
    for names in combos:
        yield "nested", f"d{len(names)}." + "-".join(names), [[nest(names, s)]]


def halves(s):
    mid = len(s) // 2
    return s[:mid], s[mid:]


def thirds(s):
    third = len(s) // 3
    return s[:third], s[third : 2 * third], s[2 * third :]


def split_forms(s):
    first, second = halves(s)
    percent = pct_all(s)
    percent_mid = (len(percent) // 6) * 3  # on a %XX boundary
    forms = [
        ("two-mid", [first, second]),
        ("two-early", [s[:3], s[3:]]),
        ("two-late", [s[:-3], s[-3:]]),
        ("three", list(thirds(s))),
        ("among-words", ["weekly report", first, second, "see you monday"]),
        ("among-spaced", ["weekly report ", first, second, " see you monday"]),
        ("base64-two-mid", list(halves(b64(s)))),
        ("hex-two-mid", list(halves(hexa(s)))),
        ("percent-two-mid", [percent[:percent_mid], percent[percent_mid:]]),
    ]
    for name, leaves in forms:
        yield "split", name, [leaves]


def expected_miss_forms(s):
    first, second = halves(s)
    yield "reversed", "bare", [[s[::-1]]]
    yield "reversed", "in-sentence", [["read this backwards " + s[::-1]]]
    yield "split-calls", "two-mid", [[first], [second]]
    yield "split-calls", "two-early", [[s[:3]], [s[3:]]]
    yield "split-calls", "three", [[part] for part in thirds(s)]


def build_s1(r):
    combos = [c for depth in (2, 3) for c in itertools.product(ENCODERS, repeat=depth)]
    for rule, variants in FAKES.items():
        names = list(variants)
        deck = []
        for i in range(PER_RULE):
            variant = names[i % len(names)]
            fake = variants[variant](r)
            # Nine nested forms per fake, dealt so each rule sees all 36 combinations evenly.
            if not deck:
                deck = combos[:]
                r.shuffle(deck)
            dealt, deck = deck[:9], deck[9:]
            forms = itertools.chain(
                plain_forms(fake),
                percent_forms(r, fake),
                base64_forms(fake),
                hex_forms(fake),
                nested_forms(fake, dealt),
                split_forms(fake),
                expected_miss_forms(fake),
            )
            # A form that comes out the same as an earlier one, such as percent-encoding that changes
            # nothing, is dropped so that it can't pad a count.
            seen = set()
            for encoding, form, calls in forms:
                key = json.dumps(calls)
                if key in seen:
                    continue
                seen.add(key)
                case = {"id": f"s1/{rule}/{variant}/i{i:02d}/{encoding}/{form}", "calls": calls}
                if encoding in EXPECTED_MISS:
                    case["expected_miss"] = True
                yield case


# Harmless text, for encoding into blobs.
def sentence(r, low=3, high=12):
    return " ".join(word(r) for _ in range(r.randint(low, high))).capitalize() + "."


def harmless_text(r):
    kind = r.randrange(5)
    if kind == 0:
        return sentence(r)
    if kind == 1:
        return json.dumps({word(r): sentence(r), "count": r.randint(0, 999), "ok": r.random() < 0.5})
    if kind == 2:
        return word(r) + "=" + word(r) + "&" + word(r) + "=" + str(r.randint(0, 99))
    if kind == 3:
        return "\n".join(sentence(r) for _ in range(r.randint(2, 5)))
    return r.choice(PHRASES) + " " + sentence(r)


def version(r):
    return f"{r.randint(0, 30)}.{r.randint(0, 60)}.{r.randint(0, 400)}"


def uuid_text(r):
    return str(uuid.UUID(int=r.getrandbits(128), version=4))


# The S2 classes. Each returns a string, or a list of leaves for one call.
def s2_uuid(r):
    u = uuid_text(r)
    return r.choice([u, u, u.upper(), "{" + u + "}", u.replace("-", ""), "urn:uuid:" + u])


def s2_git(r):
    sha = pick(r, HEX, 40)
    return r.choice([
        sha, sha, sha[: r.randint(7, 12)], "commit " + sha, "Merge: " + sha[:7] + " " + pick(r, HEX, 7),
        sha + " refs/heads/" + word(r), "index " + sha[:7] + ".." + pick(r, HEX, 7) + " 100644",
        "https://github.com/" + r.choice(NAMES) + "/" + word(r) + "/commit/" + sha,
    ])


def s2_md5(r):
    h = pick(r, HEX, 32)
    return r.choice([
        h, h, h.upper(), "md5:" + h, "MD5 (" + word(r) + ".tar.gz) = " + h, h + "  " + word(r) + ".zip",
        'etag: "' + h + '"',
    ])


def s2_sha(r):
    h = pick(r, HEX, 64)
    return r.choice([
        h, h, h.upper(), "sha256:" + h, h + "  " + word(r) + ".tar.gz", word(r) + "@sha256:" + h,
        "sha256-" + b64_bytes(r.randbytes(32)), "sha512-" + b64_bytes(r.randbytes(64)),
        "h1:" + b64_bytes(r.randbytes(32)),
    ])


def s2_base64_random(r):
    data = r.randbytes(r.randint(12, 512))
    return r.choice([b64_bytes(data), b64_bytes(data), b64url_bytes(data)])


def s2_base64_text(r):
    return b64(harmless_text(r))


def s2_base64_json(r):
    # Encoded JSON begins just as a signed token does.
    doc = json.dumps({word(r): word(r), word(r): r.randint(0, 9999), "id": pick(r, LOWNUM, 8)})
    return r.choice([b64(doc), b64url(doc)])


def s2_hex_random(r):
    data = r.randbytes(r.randint(4, 256)).hex()
    return r.choice([data, data, data.upper(), "0x" + data])


def s2_hex_text(r):
    return hexa(harmless_text(r))


def s2_percent_text(r):
    text = harmless_text(r)
    return r.choice([pct_all(text), urllib.parse.quote(text, safe=""), urllib.parse.quote_plus(text)])


def s2_nested_text(r):
    names = r.choices(list(ENCODERS), k=r.randint(2, 3))
    return nest(names, harmless_text(r))


def s2_two_part_token(r):
    # Header and claims with no signature: two parts, so not a signed token.
    header = json_bytes({"alg": "HS256", "typ": "JWT"})
    return b64url_bytes(header) + "." + b64url_bytes(json_bytes(claims(r)))


def s2_dotted(r):
    a, b, c = word(r), word(r), word(r)
    return r.choice([
        "com.example." + a + "." + b.capitalize(), a + "." + b + "." + c, a + "." + b + ".example.com",
        "eyebrow." + a + "." + b, "org.apache." + a + "." + b + "." + c.capitalize(),
        "s." + a, "hvs." + a, "self." + a + "." + b, "window." + a + "." + b + "(" + c + ")",
    ])


def s2_version(r):
    v = version(r)
    return r.choice([
        v, "v" + v, v + "-rc." + str(r.randint(1, 9)), v + "-beta+build." + str(r.randint(1, 9999)),
        "go" + v, "python-" + v, "node@" + v, word(r) + "-" + v, "openssl-" + v,
        f"v0.0.0-2026{r.randint(1, 12):02d}{r.randint(1, 28):02d}{r.randint(0, 235959):06d}"
        + "-" + pick(r, HEX, 12),
        f"v{v}-{r.randint(1, 400)}-g{pick(r, HEX, 7)}", v + "." + str(r.randint(0, 9999)),
        f"{r.randint(0, 9)}.{r.randint(0, 20)}rc{r.randint(1, 5)}", v + ".post" + str(r.randint(1, 9)),
        "python:" + f"3.{r.randint(8, 14)}-slim", f"2026.{r.randint(1, 12)}.{r.randint(1, 28)}",
        word(r) + ":" + v + "@sha256:" + pick(r, HEX, 64),
    ])


def s2_path(r):
    name, a, b = r.choice(NAMES), word(r), word(r)
    return r.choice([
        "C:\\Users\\" + name + "\\AppData\\Local\\" + a + "\\" + b + ".dll",
        "C:\\Program Files\\" + a.capitalize() + "\\" + b + ".exe",
        "/home/" + name + "/.ssh/id_" + r.choice(["rsa", "ed25519", "ecdsa"]),
        "/home/" + name + "/.aws/credentials",
        "~/.config/" + a + "/" + b + ".toml",
        "/usr/local/lib/python3." + str(r.randint(8, 14)) + "/site-packages/" + a + "/" + b + ".py",
        "node_modules/@" + a + "/" + b + "/dist/index." + pick(r, HEX, 8) + ".js",
        "/nix/store/" + pick(r, LOWNUM, 32) + "-" + a + "-" + version(r),
        ".git/objects/" + pick(r, HEX, 2) + "/" + pick(r, HEX, 38),
        "\\\\server\\share\\" + a + "\\" + b + ".docx",
        "src/" + a + "/" + b + ".go:" + str(r.randint(1, 900)) + ":" + str(r.randint(1, 90)),
        "s3://" + a + "-bucket/" + b + "/" + pick(r, HEX, 8) + ".parquet",
        "/var/lib/docker/overlay2/" + pick(r, HEX, 64) + "/merged/" + a,
        "/tmp/" + a + "." + pick(r, ALNUM, 10),
        "./secrets/" + a + ".example.env",
    ])


PUBLIC_PEM = [
    "PUBLIC KEY", "RSA PUBLIC KEY", "CERTIFICATE", "TRUSTED CERTIFICATE", "CERTIFICATE REQUEST",
    "NEW CERTIFICATE REQUEST", "X509 CRL", "PGP PUBLIC KEY BLOCK", "PGP SIGNATURE", "PGP MESSAGE",
    "PKCS7", "CMS", "DH PARAMETERS", "EC PARAMETERS", "SSH2 PUBLIC KEY", "ATTRIBUTE CERTIFICATE",
]


def s2_pem_public(r):
    kind = r.choice(PUBLIC_PEM)
    begin, end = DASH + "BEGIN " + kind + DASH, DASH + "END " + kind + DASH
    full = pem_text(kind, r.randbytes(r.randint(64, 900)))
    return r.choice([
        begin, begin + "\n" + end, full, full, "subject=CN=" + word(r) + "\n" + full,
        "the file must start with " + begin,
    ])


def s2_ssh_public(r):
    comment = r.choice(NAMES) + "@" + word(r)
    return r.choice([
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + pick(r, ALNUM + "+/", 43) + " " + comment,
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ" + pick(r, ALNUM + "+/", 340) + " " + comment,
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY" + pick(r, ALNUM + "+/", 100) + "= "
        + comment,
        r.choice(HOSTS) + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + pick(r, ALNUM + "+/", 43),
    ])


def s2_email(r):
    first, last = r.choice(NAMES), r.choice(NAMES)
    domain = r.choice(["example.com", "example.org", "example.net", "mail.example.com"])
    address = r.choice([
        first + "@" + domain, first + "." + last + "@" + domain, first + "+" + word(r) + "@" + domain,
        first + str(r.randint(1, 9999)) + "@" + domain, first[0] + last + "@" + domain,
    ])
    return r.choice([
        address, address, "mailto:" + address, first.capitalize() + " <" + address + ">",
        "Signed-off-by: " + first.capitalize() + " " + last.capitalize() + " <" + address + ">",
        "cc: " + address + ", " + last + "@" + domain, "reply to " + address + " by friday",
    ])


def s2_url(r):
    host, a, b, name = r.choice(HOSTS), word(r), word(r), r.choice(NAMES)
    port = str(r.choice([80, 443, 3000, 5432, 6379, 8080, 8443, 27017]))
    return r.choice([
        "https://" + host + "/" + a + "/" + b,
        "https://" + host + ":" + port + "/" + a,
        "http://localhost:" + port + "/" + a + "?" + b + "=" + str(r.randint(0, 99)),
        "https://" + host + "/@" + name + "/" + a + "-" + b,
        "https://" + host + "/@" + a + "/" + b + "@" + version(r),
        "https://" + host + "/" + a + "?email=" + name + "@example.org",
        "https://" + host + "/" + a + "?time=12:30:45&email=" + name + "@example.org",
        "https://" + host + "/wiki/Category:" + a.capitalize(),
        "https://" + host + "/" + a + ":" + b + "/" + name + "@" + a,
        "https://" + host + "/" + a + "#" + b + ":" + name + "@" + a,
        "ssh://git@" + host + "/" + name + "/" + a + ".git",
        "git@" + host + ":" + name + "/" + a + ".git",
        "https://" + host + "/" + name + "/" + a + ".git",
        "https://" + name + "@" + host + "/" + a,
        "ftp://" + host + "/" + a + "/" + b + ".zip",
        "s3://" + a + "/" + b,
        "gs://" + a + "/" + b,
        "redis://" + host + ":6379/0",
        "postgres://" + host + ":5432/" + a,
        "mongodb://" + host + ":27017/" + a,
        "amqp://" + host + ":5672/",
        "ldap://" + host + ":389/",
        "http://[2001:db8::" + str(r.randint(1, 9999)) + "]:" + port + "/" + a,
        "https://" + host + "/download?etag=" + pick(r, HEX, 32),
        "https://hooks.slack.com/" + a,
        "https://hooks.slack.com/services/" + a.upper() + "/" + b.upper(),
        "https://api.slack.com/messaging/webhooks#" + a,
        "https://api.telegram.org/bot<token>/" + a,
        "data:text/plain;base64," + b64(sentence(r)),
    ])


def s2_url_template(r):
    # Placeholders where a login would go: no credential in them.
    user, password = r.choice([
        ("{user}", "{password}"), ("$DB_USER", "$DB_PASS"), ("${USER}", "${PASS}"),
        ("<username>", "<password>"), ("%s", "%s"), ("{{ user }}", "{{ pass }}"),
    ])
    scheme = r.choice(["postgres", "mysql", "https", "mongodb", "amqp", "redis"])
    host = r.choice(["localhost", "db.example.com", "{host}", "$DB_HOST", "<host>"])
    return url_with_login(scheme, user, password, host + r.choice(["", "/" + word(r), ":5432/" + word(r)]))


PREFIX_WORDS = [
    "sk-learn", "sk-button", "sk-circle", "sk-spinner", "sk-chase", "sk-cube", "sk-wave", "sk-ant",
    "sk_buff", "sk_live_mode", "sk_test_mode", "sk_live_helper", "sk_test_helper", "rk_live_mode",
    "rk_test_suite", "rk_thread", "skip", "skeleton", "sky", "skill", "sketch",
    "ghp_helper", "ghp_name", "gho_config", "gho_flag", "ghu_cache", "ghs_cache", "ghr_config",
    "github_pat_docs", "github_pat_notes", "github_path", "github_patch", "github_token",
    "glpat-docs", "glpat-notes", "gldt-docs", "glrt-notes", "glcbt-docs", "glptt-notes", "gloas-docs",
    "glBindTexture", "glDrawArrays", "glFlush", "glUniform1f",
    "xoxo", "xoxb-docs", "xoxp-docs", "xoxe-docs", "xapp-docs", "xoxb_env", "xoxp_env",
    "hf_hub", "hf_hub_download", "hf_transfer", "hf_token", "hf_home", "hf_cache", "api_org_name",
    "api_org_id", "pplx-api", "pplx-online", "pplx-7b-online", "pplx-70b-chat",
    "AKIA_KEY_NAME", "AKIA_ROTATION", "ASIA_PACIFIC", "ASIAN_MARKETS", "ASIA-EAST-1", "ABIA_STATE",
    "ACCA_MEMBER", "ACCA_EXAM", "AIzawl", "AIza_docs", "Aizawl",
    "dop_v1_schema", "doo_v1_schema", "dor_v1_schema", "dop_v2", "doorbell", "dopamine",
    "hvs.color", "hvs.hue", "hvb.docs", "hvr.docs", "hvac",
    "npm_config_registry", "npm_config_cache", "npm_package_name", "npm_lifecycle_event", "npm_execpath",
    "pypi-server", "pypi-simple", "pypi-publish", "pypi-token-docs", "SG.Layout", "SG.Window", "SG.Text",
    "shpat_name", "shpca_name", "shppa_name", "shpss_name", "shop_name", "dapi_client", "dapi-server",
    "dapibus", "DAPI", "eyJ", "eyes", "eyebrow", "eyelid",
]


def s2_prefix_word(r):
    base = r.choice(PREFIX_WORDS)
    return r.choice([
        base, base + "_" + word(r), base + "-" + word(r), base + str(r.randint(0, 99)),
        "see " + base + " in the docs", "set " + base + " before you start", base + "." + word(r),
        '"' + base + '": "' + word(r) + '"',
    ])


PREFIX_SHORT = [
    ("sk-ant-api03-", B64URL, 8), ("sk-", ALNUM, 8), ("sk-proj-", B64URL, 8), ("hf_", LETTERS, 8),
    ("api_org_", LETTERS, 6), ("pplx-", ALNUM, 8), ("AKIA", B32, 6), ("ASIA", B32, 6), ("AIzaSy", B64URL, 8),
    ("dop_v1_", HEX, 8), ("doo_v1_", HEX, 8), ("hvs.", ALNUM, 8), ("hvb.", ALNUM, 8), ("s.", ALNUM, 8),
    ("ghp_", ALNUM, 8), ("gho_", ALNUM, 8), ("ghu_", ALNUM, 8), ("ghs_", ALNUM, 8), ("ghr_", ALNUM, 8),
    ("github_pat_", ALNUM, 8), ("glpat-", ALNUM, 6), ("gldt-", ALNUM, 6), ("glrt-", ALNUM, 6),
    ("xoxb-", DIGITS, 6), ("xoxp-", DIGITS, 6), ("xapp-1-", UPNUM, 6), ("sk_live_", ALNUM, 6),
    ("rk_live_", ALNUM, 6), ("sk_test_", ALNUM, 6), ("npm_", ALNUM, 8), ("pypi-", B64URL, 8),
    ("pypi-AgEIcHlwaS5vcmc", B64URL, 4), ("SG.", B64URL, 8), ("shpat_", HEX, 8), ("shpss_", HEX, 8),
    ("dapi", HEX, 8), ("eyJ", B64URL, 8), ("abc8Q~", ALNUM, 6),
]


def s2_prefix_short(r):
    prefix, alphabet, n = r.choice(PREFIX_SHORT)
    text = prefix + pick(r, alphabet, r.randint(max(1, n - 4), n))
    return r.choice([text, text, "the token starts with " + text + "...", "`" + text + "`"])


PLACEHOLDER_VARS = (
    "API_KEY API_TOKEN ACCESS_TOKEN AUTH_TOKEN SECRET_KEY CLIENT_SECRET GITHUB_TOKEN GITLAB_TOKEN "
    "NPM_TOKEN PYPI_TOKEN SLACK_TOKEN SLACK_WEBHOOK_URL STRIPE_SECRET_KEY AWS_ACCESS_KEY_ID "
    "AWS_SECRET_ACCESS_KEY OPENAI_API_KEY HF_TOKEN DATABASE_URL SENDGRID_API_KEY VAULT_TOKEN"
).split()


def s2_placeholder(r):
    var = r.choice(PLACEHOLDER_VARS)
    value = r.choice([
        "$" + var, "${" + var + "}", "%" + var + "%", "{{ secrets." + var + " }}", "<" + var.lower() + ">",
        "YOUR_" + var, "your-" + var.lower().replace("_", "-") + "-here", "REDACTED", "[MASKED]", "***",
        "xxxx-xxxx",
    ])
    return r.choice([
        value, var + "=" + value, "Authorization: Bearer " + value,
        '"' + var.lower() + '": "' + value + '"',
    ])


FILLERS = ["x", "X", "0", "1234567890", "abcdef", "abc123"]
FULL_LENGTH = [
    ("ghp_", 36), ("gho_", 36), ("github_pat_", 82), ("glpat-", 20), ("sk_live_", 24), ("rk_live_", 24),
    ("npm_", 36), ("hf_", 34), ("pplx-", 48), ("AKIA", 16), ("AIzaSy", 33), ("dop_v1_", 64), ("hvs.", 24),
    ("shpat_", 32), ("dapi", 32), ("sk-ant-api03-", 95),
]


def s2_placeholder_full(r):
    # The right prefix and length with an empty body, as documentation writes them. This is the
    # case an entropy filter exists for.
    prefix, size = r.choice(FULL_LENGTH)
    body = (r.choice(FILLERS) * size)[:size]
    return r.choice([prefix + body, "API_TOKEN=" + prefix + body])


def s2_publishable(r):
    # Stripe's docs say publishable keys are safe to expose.
    return r.choice(["pk_live_", "pk_test_"]) + pick(r, ALNUM, r.choice([24, 99]))


def s2_aws_ids(r):
    # IAM identifiers that are not credentials, per the IAM docs' table of prefixes.
    prefix = r.choice(["AIDA", "AROA", "AGPA", "ANPA", "ANVA", "AIPA", "ASCA", "APKA"])
    ident = prefix + pick(r, B32, r.randint(13, 17))
    return r.choice([
        ident, ident + ":" + word(r), '"aws:userid": "' + ident + '"',
        "arn:aws:iam::" + digits(r, 12) + ":role/" + word(r),
        "arn:aws:s3:::" + word(r) + "-bucket/" + word(r),
    ])


def s2_cloud_ids(r):
    a = word(r)
    return r.choice([
        "T" + pick(r, UPNUM, 8), "C" + pick(r, UPNUM, 10), "U" + pick(r, UPNUM, 10),
        a + "-" + pick(r, HEX, 10) + "-" + pick(r, LOWNUM, 5),
        "projects/" + a + "-" + digits(r, 6) + "/locations/us-central1/keyRings/" + a + "/cryptoKeys/"
        + word(r),
        "/subscriptions/" + uuid_text(r) + "/resourceGroups/" + a
        + "/providers/Microsoft.KeyVault/vaults/" + word(r),
        "i-" + pick(r, HEX, 17), "vpc-" + pick(r, HEX, 17), "sg-" + pick(r, HEX, 17),
        "ami-" + pick(r, HEX, 17),
        "acct_" + pick(r, ALNUM, 16), "cus_" + pick(r, ALNUM, 14), "pi_" + pick(r, ALNUM, 24),
        "price_" + pick(r, ALNUM, 24), "org_" + pick(r, ALNUM, 24),
        "Qm" + pick(r, ALNUM, 44), "0x" + pick(r, HEX, 40), "bc1q" + pick(r, LOWNUM, 38),
        "ocid1.instance.oc1.." + pick(r, LOWNUM, 60),
    ])


def s2_colons(r):
    return r.choice([
        f"{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}",
        f"2026-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}"
        + f"T{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:00Z",
        digits(r, 9) + ":" + pick(r, ALNUM, 6), digits(r, 10) + ":" + str(r.randint(0, 999)),
        f"{r.randint(1024, 65535)}:{r.randint(1, 65535)}",
        f"2001:db8::{r.randint(1, 65535):x}:{r.randint(1, 65535):x}",
        ":".join(pick(r, HEX, 2) for _ in range(6)),
        digits(r, 8) + ":AB" + pick(r, ALNUM, 10), digits(r, 9) + ":AA" + pick(r, B64URL, 6),
    ])


JS_MEMBERS = (
    "length push prototype call apply bind exports default value get set forEach map filter reduce "
    "slice splice concat indexOf includes keys values entries toString hasOwnProperty "
    "getOwnPropertyDescriptor getOwnPropertyDescriptors getOwnPropertyNames getElementsByClassName "
    "getElementsByTagName addEventListener removeEventListener createElement createDocumentFragment "
    "appendChild insertBefore querySelectorAll getBoundingClientRect requestAnimationFrame "
    "cancelAnimationFrame compareDocumentPosition getComputedStyle setAttribute getAttribute classList "
    "innerHTML textContent parentNode nextSibling ownerDocument defaultView dispatchEvent stopPropagation "
    "preventDefault isArray freeze defineProperty defineProperties assign create fromCharCode charCodeAt "
    "then resolve reject"
).split()


def js_name(r):
    if r.random() < 0.7:
        return r.choice(LETTERS + "_$")
    return r.choice(LOWER) + pick(r, ALNUM, r.randint(1, 3))


def js_statement(r):
    a, b, c, d, e = (js_name(r) for _ in range(5))
    m, n, w = r.choice(JS_MEMBERS), r.choice(JS_MEMBERS), word(r)
    return r.choice([
        f"var {a}={b}.{m}({c},{d}),{e}={c}?{d}:{b};",
        f"function {a}({b},{c}){{return {b}.{m}({c})}}",
        f"!function({a},{b}){{{a}.{m}={b}}}(window,document);",
        f"{a}.exports=function({b}){{return {b}&&{b}.__esModule?{b}:{{default:{b}}}}};",
        f'Object.defineProperty({a},"__esModule",{{value:!0}});',
        f'if({a}.{m}>1e3)return void {b}.{n}("{w}",{c});',
        f"for(var {a}=0,{b}={c}.length;{a}<{b};{a}++){d}.push({c}[{a}]);",
        f'const {a}="{pick(r, HEX, 40)}";',
        f'let {a}="{b64_bytes(r.randbytes(r.randint(12, 90)))}";',
        f'{a}.src="https://cdn.example.net/{w}/{pick(r, HEX, 8)}.js";',
        f"try{{{a}.{m}()}}catch({b}){{}}",
        f"const {a}=({b},{c})=>({{{d}:{b},{e}:{c}}});",
        f"switch({a}){{case 1:return {b};default:return {c}}}",
        f'{a}.exports={{name:"{w}",version:"{version(r)}"}};',
        f'{a}.{m}("{w}",function({b}){{{b}.{n}()}});',
        f"{a}.{m}({b}).{n}({c});",
    ])


def minified_js(r, target):
    parts, size = ['"use strict";'], 13
    while size < target:
        statement = js_statement(r)
        parts.append(statement)
        size += len(statement)
    if r.random() < 0.3:
        parts.append("\n//# sourceMappingURL=main." + pick(r, HEX, 8) + ".js.map")
    return "".join(parts)


def s2_minified_js(r):
    return minified_js(r, r.choice([300, 300, 300, 300, 800, 800, 800, 2000, 2000, 2000, 5000, 5000, 20000]))


def s2_minified_bundle(r):
    return minified_js(r, 100_000)


def css_rule(r):
    a, b = word(r), pick(r, HEX, 6)
    return r.choice([
        f".{a}{{color:#{b};margin:0}}",
        f"#{a}>.{word(r)}{{padding:{r.randint(0, 40)}px;font-size:{r.randint(9, 30)}px}}",
        f"@media (max-width:{r.randint(300, 1400)}px){{.{a}{{display:none}}}}",
        f"@import url(https://fonts.example.net/css?family={a.capitalize()}:400,700);",
        f".{a}{{background:url(data:image/png;base64,{b64_bytes(r.randbytes(r.randint(30, 300)))})}}",
        f"@font-face{{font-family:{a};src:url(/fonts/{a}.{pick(r, HEX, 8)}.woff2)}}",
    ])


def s2_minified_css(r):
    return "".join(css_rule(r) for _ in range(r.randint(3, 60)))


def s2_code(r):
    var, a, b = r.choice(PLACEHOLDER_VARS), word(r), word(r)
    return r.choice([
        'token = os.environ["' + var + '"]',
        "const key = process.env." + var + ";",
        'curl -H "Authorization: Bearer $' + var + '" https://api.example.com/v1/' + a,
        "export " + var + '="$(vault kv get -field=' + a + " secret/" + b + ')"',
        'if v := os.Getenv("' + var + '"); v == "" {',
        "aws s3 cp s3://" + a + "/" + b + " .",
        "git clone https://github.com/" + r.choice(NAMES) + "/" + a + ".git",
        "pip install " + a + "==" + version(r),
        "npm install @" + a + "/" + b + "@" + version(r),
        "docker run -e " + var + " " + a + ":" + version(r),
        "def " + a + "_" + b + "(self, token: str) -> bool:",
        'password = getpass.getpass("' + a + ' password: ")',
        "func " + a.capitalize() + b.capitalize() + "(ctx context.Context, key string) error {",
        "# rotate " + var + " every " + str(r.randint(7, 365)) + " days",
    ])


def s2_prose(r):
    a, b, n = word(r), word(r), r.randint(2, 365)
    return r.choice([
        f"Rotate the {a} api key every {n} days.",
        f"The private key stays on the {a} server and never leaves it.",
        f"The token expired at {r.randint(1, 12)}:{r.randint(10, 59)} during the {a} {b}.",
        f"Your password must be at least {r.randint(8, 20)} characters long.",
        f"Store secrets in the vault, not in the {a} {b}.",
        f"Ask {r.choice(NAMES)} for the credentials to the {a} account.",
        f"The webhook sends a {a} {b} to the channel every {n} minutes.",
        f"Bearer tokens go in the header and not in the {a} {b}.",
    ])


def s2_private_mention(r):
    # A private key's markers with no key between them, as parsers and error messages use them.
    kind = private_kind(r.choice(["RSA ", "EC ", "OPENSSH ", "", "DSA ", "ENCRYPTED "]))
    begin, end = DASH + "BEGIN " + kind + DASH, DASH + "END " + kind + DASH
    return r.choice([
        'if line.startswith("' + begin + '"):',
        "the file must start with " + begin,
        begin + "\n...\n" + end,
        begin + "\n<your key here>\n" + end,
        'strings.HasPrefix(s, "' + begin + '")',
        "expected " + end + " at line " + str(r.randint(2, 40)),
    ])


def s2_wrapper_control(r):
    value = r.choice(["changeme", "not-set", "placeholder", "none", "${TOKEN}", "<redacted>", word(r)])
    if r.random() < 0.7:
        value += "-" + word(r)
    wrap = r.choice(list(WRAPPERS.values()))
    return r.choice([
        wrap(value), wrap(value), wrap(pct_all(value)), wrap(b64(value)), wrap(hexa(value)),
        IN_URL + pct_all(value) + "&from=tool", IN_SENTENCE + b64(value) + " and file it",
        IN_SENTENCE + hexa(value) + " and file it", b64("token=" + value), hexa("token=" + value),
    ])


def s2_sibling_leaves(r):
    # One call with several harmless leaves, for the path that joins them.
    makers = [
        sentence, word, uuid_text, s2_email, s2_url, s2_version, s2_path, s2_git, s2_md5,
        lambda r: r.choice(["weekly report", "see you monday", "weekly report ", " see you monday"]),
    ]
    return [r.choice(makers)(r) for _ in range(r.randint(2, 5))]


def s2_blob_large(r):
    # Harmless blobs of the size a tool call can carry, such as an attached image.
    return r.choice([
        lambda: b64_bytes(r.randbytes(64 * 1024)),
        lambda: b64_bytes(r.randbytes(256 * 1024)),
        lambda: b64_bytes(r.randbytes(512 * 1024)),
        lambda: r.randbytes(64 * 1024).hex(),
        lambda: r.randbytes(256 * 1024).hex(),
    ])()


def s2_listing_long(r):
    # Long machine output that is full of hash-like and base64-like runs.
    kind = r.randrange(4)
    if kind == 0:
        return "\n".join(
            pick(r, HEX, 64) + "  " + word(r) + "-" + version(r) + ".tar.gz" for _ in range(1000)
        )
    if kind == 1:
        return "\n".join(
            "example.org/" + word(r) + "/" + word(r) + " v" + version(r) + " h1:"
            + b64_bytes(r.randbytes(32))
            for _ in range(500)
        )
    if kind == 2:
        return "\n".join(
            '"node_modules/' + word(r) + '": {"version": "' + version(r) + '", "integrity": "sha512-'
            + b64_bytes(r.randbytes(64)) + '"},'
            for _ in range(300)
        )
    return ",".join(pick(r, ALNUM, r.randint(8, 40)) for _ in range(1500))


S2_CLASSES = [
    ("uuid", 1500, s2_uuid),
    ("git-hash", 1500, s2_git),
    ("md5", 1000, s2_md5),
    ("sha", 1500, s2_sha),
    ("base64-random", 2000, s2_base64_random),
    ("base64-text", 1000, s2_base64_text),
    ("base64-json", 1000, s2_base64_json),
    ("hex-random", 2000, s2_hex_random),
    ("hex-text", 1000, s2_hex_text),
    ("percent-text", 1000, s2_percent_text),
    ("nested-text", 1000, s2_nested_text),
    ("two-part-token", 500, s2_two_part_token),
    ("dotted-name", 1000, s2_dotted),
    ("version", 2000, s2_version),
    ("path", 2000, s2_path),
    ("pem-public", 1000, s2_pem_public),
    ("ssh-public", 500, s2_ssh_public),
    ("email", 2000, s2_email),
    ("url-plain", 3000, s2_url),
    ("url-template", 30, s2_url_template),
    ("prefix-word", 2000, s2_prefix_word),
    ("prefix-short", 1000, s2_prefix_short),
    ("placeholder", 500, s2_placeholder),
    ("placeholder-full", 40, s2_placeholder_full),
    ("stripe-publishable", 300, s2_publishable),
    ("aws-id", 1000, s2_aws_ids),
    ("cloud-id", 1000, s2_cloud_ids),
    ("colons", 1000, s2_colons),
    ("minified-js", 1000, s2_minified_js),
    ("minified-bundle", 20, s2_minified_bundle),
    ("minified-css", 500, s2_minified_css),
    ("code-line", 1500, s2_code),
    ("prose", 1000, s2_prose),
    ("private-mention", 20, s2_private_mention),
    ("wrapper-control", 500, s2_wrapper_control),
    ("sibling-leaves", 500, s2_sibling_leaves),
    ("blob-large", 40, s2_blob_large),
    ("listing-long", 40, s2_listing_long),
]


def build_s2(r):
    seen = set()
    for name, count, make in S2_CLASSES:
        made, tries = 0, 0
        while made < count:
            tries += 1
            if tries > count * 200:
                sys.exit(f"class {name} ran out of different strings at {made} of {count}")
            value = make(r)
            leaves = value if isinstance(value, list) else [value]
            key = "\0".join(leaves)
            if key in seen:
                continue
            seen.add(key)
            yield {"id": f"s2/{name}/{made:05d}", "calls": [leaves]}
            made += 1


def write_set(path, cases):
    digest = hashlib.sha256()
    count, size = 0, 0
    with open(path, "wb") as out:
        for case in cases:
            line = json.dumps(case, separators=(",", ":")).encode() + b"\n"
            out.write(line)
            digest.update(line)
            count += 1
            size += len(line)
    return {"file": path.name, "sha256": digest.hexdigest(), "cases": count, "bytes": size}


def main():
    parser = argparse.ArgumentParser(description="Build the secret scanner's scoring sets.")
    parser.add_argument("out", help="an empty folder outside the repo")
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    out = pathlib.Path(args.out).resolve()
    if out == REPO or REPO in out.parents:
        sys.exit("refusing to write inside the repo")
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        sys.exit("the folder is not empty")

    sys.stdout.reconfigure(newline="\n")
    generator = hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    # Each set has its own stream, so a change to one can't move the values in the other.
    s1 = write_set(out / "s1.jsonl", build_s1(random.Random(f"{args.seed}/s1")))
    s2 = write_set(out / "s2.jsonl", build_s2(random.Random(f"{args.seed}/s2")))
    manifest = {
        "seed": args.seed,
        "generator_sha256": generator,
        "python": platform.python_version(),
        "rules": list(FAKES),
        "variants": {rule: list(variants) for rule, variants in FAKES.items()},
        "per_rule": PER_RULE,
        "s2_classes": {name: count for name, count, _ in S2_CLASSES},
        "sets": {"s1": s1, "s2": s2},
    }
    manifest_text = json.dumps(manifest, indent=1) + "\n"
    (out / "manifest.json").write_text(manifest_text, encoding="utf-8", newline="\n")

    print(f"generator sha256 {generator}")
    print(f"seed {args.seed}, python {manifest['python']}")
    for name, entry in manifest["sets"].items():
        print(f"{name}: {entry['cases']} cases, {entry['bytes']} bytes, sha256 {entry['sha256']}")
    variants = sum(len(v) for v in FAKES.values())
    print(f"S1: {len(FAKES)} rules, {variants} format variants, {PER_RULE} fakes per rule")
    print(f"S2: {len(S2_CLASSES)} classes")


if __name__ == "__main__":
    main()
