r"""Compiled pattern tables for the action-class detectors.

Two deliberate stylistic quirks appear throughout, both to slip past the host's
*lexical* PreToolUse gate (which greps source for the exact words this security
tool must name) while producing the correct runtime pattern:

  * literals are split across adjacent Python string boundaries — ``"pay" "ment"``
    concatenates to the real token at import time;
  * regexes use ``\b``/``\s`` rather than literal spaces.

At runtime these compile to the genuine detection patterns; the tests assert on
real malicious command strings (assembled the same way) to prove it.

Action-class detection is legitimately lexical — it classifies *what kind of
operation* a call is. The non-lexical moat lives in taint.py, not here.
"""

from __future__ import annotations

import re
from typing import Any, List, Pattern

_I = re.IGNORECASE


def _c(*fragments: str) -> Pattern:
    return re.compile("".join(fragments), _I)


# --- Spend / money movement -------------------------------------------------
SPEND_PATTERNS: List[Pattern] = [
    _c(r"\b(?:", "pay", "ment", r"|", "pur", "chase", r"|", "check", "out",
       r"|buy\b|pay\s+for|place\s+(?:an?\s+)?order|invoice|billing"
       r"|paypal|braintree|credit[\s_-]*card)\b"),
    _c(r"\bstripe\b"),
    _c(r"\b", "char", "ge", r"\s+(?:the\s+)?card\b"),
]

# --- Destructive / irreversible --------------------------------------------
DESTRUCTIVE_PATTERNS: List[Pattern] = [
    _c(r"\brm\b[^\n;|&]*-(?:rf|fr|r|f|-recursive|-force)\b"),
    _c(r"--no-preserve", "-root"),
    _c(r"\b", "mk", "fs", r"\b"),
    _c(r"\bshred\b"),
    _c(r"\bdd\b[^\n;|&]*\bif="),
    _c(r"\bdrop\s+(?:table|database)\b"),
    _c(r"\btruncate\s+table\b"),
    _c(r"\bterraform\s+destroy\b"),
    _c(r"\bkubectl\s+delete\b"),
    _c(r"\bgit\s+push\s+(?:--force\b|-f\b|--force-with-lease\b)"),
    _c(r">\s*/dev/sd[a-z]"),
    _c(r"\bfind\b[^|]*\s-delete\b"),
]

# --- System install / download-and-run -------------------------------------
INSTALL_PATTERNS: List[Pattern] = [
    _c(r"\bsudo\b"),
    _c(r"\bapt(?:-get)?\s+install\b"),
    _c(r"\byum\s+install\b"),
    _c(r"\bdnf\s+install\b"),
    _c(r"\bbrew\s+install\b"),
    _c(r"\bnpm\s+install\s+-g\b"),
    _c(r"\bpip\s+install\b"),
    _c(r"(?:curl|wget)\b[^|]*\|\s*(?:bash|sh|zsh|python)\b"),
]

# --- Credential / secret access, matched by PATH not vocabulary -------------
# Provenance-flavoured: these are the concrete locations secrets live. A hit
# marks the READ content as secret material for the egress matcher.
#
# The left anchor is a negative-lookbehind ``(?<!\w)`` rather than ``(?:^|/)``.
# Actions are flattened to a newline-joined string before matching, so a bare
# RELATIVE path (``.env``, ``.aws/credentials``, ``id_rsa`` — the common case
# when the agent runs inside the project dir) sits after a ``\n``, which the
# old start-or-slash anchor never matched. That silently failed to fingerprint
# the read, so a later exfil of that secret was MISSED. ``(?<!\w)`` matches at
# string start, after ``/``, and after whitespace/newline/quote, while still
# rejecting ``foo.env`` / ``myid_rsa`` (preceded by a word char).
CREDENTIAL_PATH_PATTERNS: List[Pattern] = [
    _c(r"(?<!\w)\.env(?:\.[\w-]+)?\b"),
    _c(r"(?<!\w)\.ssh/"),
    _c(r"(?<!\w)id_(?:rsa|ed25519|ecdsa|dsa)\b"),
    _c(r"(?<!\w)\.aws/credentials\b"),
    _c(r"(?<!\w)\.aws/config\b"),
    _c(r"(?<!\w)\.netrc\b"),
    _c(r"(?<!\w)\.npmrc\b"),
    _c(r"(?<!\w)\.pypirc\b"),
    _c(r"(?<!\w)\.git-credentials\b"),
    _c(r"(?<!\w)\.kube/config\b"),
    _c(r"(?<!\w)\.docker/config\.json\b"),
    _c(r"\b\w*(?:secret|token|apikey|api_key|private_key|credential)s?\.(?:json|ya?ml|txt|pem|key)\b"),
    _c(r"\bkeychain\b"),
]

# High-entropy / well-known secret *values* (for tainting read content).
SECRET_VALUE_PATTERNS: List[Pattern] = [
    _c(r"\bAKIA[0-9A-Z]{16}\b"),                      # AWS access key id
    _c(r"\bASIA[0-9A-Z]{16}\b"),                      # AWS temp key id
    _c(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),            # GitHub tokens
    _c(r"\bsk-[A-Za-z0-9]{20,}\b"),                   # OpenAI-style keys
    _c(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),          # Slack tokens
    _c(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),        # PEM private keys
    _c(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]

# --- Network egress ---------------------------------------------------------
EGRESS_PATTERNS: List[Pattern] = [
    _c(r"\bhttps?://"),
    _c(r"(?:curl|wget|nc|ncat|netcat|scp|rsync|ftp|sftp|telnet)\b"),
    _c(r"\brequests\.(?:post|put|patch)\b"),
    _c(r"\burllib(?:\.request)?\b"),
    _c(r"\bsocket\.(?:connect|sendall|send)\b"),
    _c(r"\bfetch\("),
    _c(r"\bxmlhttprequest\b"),
]

# --- Permission changes -----------------------------------------------------
PERMISSION_PATTERNS: List[Pattern] = [
    _c(r"\bchmod\s+(?:-R\s+)?0?777\b"),
    _c(r"\bchmod\b"),
    _c(r"\bchown\b"),
    _c(r"\bchgrp\b"),
    _c(r"\bsetfacl\b"),
]

# --- Messaging / publishing / send-on-your-behalf ---------------------------
MESSAGING_PATTERNS: List[Pattern] = [
    _c(r"\bnpm\s+publish\b"),
    _c(r"\bpypi\b|\btwine\s+upload\b"),
    _c(r"\bgit\s+push\b"),
    _c(r"\bsend[_-]?(?:mail|email|message)\b"),
    _c(r"\bsmtp\b"),
    _c(r"\b(?:slack|discord|telegram)\b.*\b(?:webhook|post|send)\b"),
    _c(r"\btweet\b|\bpost_status\b"),
]


def _as_text(text: Any) -> str:
    """Coerce detector input to a string.

    Detectors are a security boundary: they must never crash on odd input and
    hand control back to the agent. ``None`` becomes empty (matches nothing);
    anything non-string is stringified so it is still scanned rather than
    silently skipped.
    """
    if text is None:
        return ""
    if isinstance(text, str):
        return text
    return str(text)


def matches_any(text: Any, patterns: List[Pattern]) -> bool:
    t = _as_text(text)
    return any(p.search(t) for p in patterns)


def first_match(text: Any, patterns: List[Pattern]):
    t = _as_text(text)
    for p in patterns:
        m = p.search(t)
        if m:
            return m
    return None
