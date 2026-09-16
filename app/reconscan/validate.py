"""Input validation - the first line of defence against command injection.

Every value that ends up in a command argument passes through here first.
Nothing is ever interpolated into a shell string (see runner.py); on top of
that, we refuse anything that doesn't match a strict pattern, so even a bug
downstream can't turn a target into a flag or a shell metacharacter.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# --- patterns ---------------------------------------------------------------
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*\.?$")
PORTSPEC_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
# nmap-style trailing octet range: 192.168.1.10-40
V4_RANGE_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3})$")
# explicit start-end pair: 10.0.0.1-10.0.0.50
V4_PAIR_RE = re.compile(r"^([0-9.]+)-([0-9.]+)$")
SAFE_WORD_RE = re.compile(r"^[A-Za-z0-9._@:/-]{1,128}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~%/-]{0,255}$")

TARGET_TYPES = ("ip", "cidr", "range", "host", "url")


class ValidationError(ValueError):
    """Raised with a message that is safe (and useful) to show a beginner."""


# --- targets ----------------------------------------------------------------
def classify(value: str) -> str:
    """Return the target type, or raise ValidationError with a plain-English why."""
    v = (value or "").strip()
    if not v:
        raise ValidationError("Target is empty.")
    if len(v) > 255:
        raise ValidationError("Target is too long (max 255 characters).")
    if any(c.isspace() for c in v):
        raise ValidationError("Targets cannot contain spaces - add one per line instead.")

    if v.lower().startswith(("http://", "https://")):
        parts = urlsplit(v)
        if not parts.hostname:
            raise ValidationError(f"{v!r} looks like a URL but has no host part.")
        _check_host_part(parts.hostname)
        return "url"

    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ValidationError(
                f"{v!r} looks like a CIDR range but isn't valid ({exc}). "
                "A CIDR looks like 192.168.1.0/24 - the /24 means "
                "'the 256 addresses 192.168.1.0 through 192.168.1.255'."
            ) from exc
        return "cidr"

    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass

    if "-" in v and _looks_numeric_range(v):
        _range_bounds(v)  # raises if malformed
        return "range"

    if HOSTNAME_RE.match(v):
        return "host"

    raise ValidationError(
        f"{v!r} isn't a valid IP, CIDR, range, hostname or URL. Examples: "
        "10.0.0.5 | 192.168.1.0/24 | 192.168.1.10-40 | scanme.nmap.org | http://10.0.0.5:8080"
    )


def _check_host_part(host: str) -> None:
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    if not HOSTNAME_RE.match(host):
        raise ValidationError(f"{host!r} is not a valid hostname.")


def _looks_numeric_range(v: str) -> bool:
    if V4_RANGE_RE.match(v):
        return True
    m = V4_PAIR_RE.match(v)
    return bool(m and v.count(".") >= 6)


def _range_bounds(v: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    m = V4_RANGE_RE.match(v)
    if m:
        a, b, c, d, last = (int(x) for x in m.groups())
        for octet in (a, b, c, d, last):
            if not 0 <= octet <= 255:
                raise ValidationError(f"{v!r} has an octet outside 0-255.")
        if last < d:
            raise ValidationError(f"{v!r} counts backwards - the end must be >= the start.")
        return (ipaddress.IPv4Address(f"{a}.{b}.{c}.{d}"),
                ipaddress.IPv4Address(f"{a}.{b}.{c}.{last}"))
    m = V4_PAIR_RE.match(v)
    if m:
        try:
            start = ipaddress.IPv4Address(m.group(1))
            end = ipaddress.IPv4Address(m.group(2))
        except ValueError as exc:
            raise ValidationError(f"{v!r} is not a valid address range ({exc}).") from exc
        if int(end) < int(start):
            raise ValidationError(f"{v!r} counts backwards - the end must be >= the start.")
        return start, end
    raise ValidationError(f"{v!r} is not a valid address range.")


def validate_target(value: str) -> tuple[str, str]:
    """Return (normalised_value, type). Raises ValidationError."""
    v = (value or "").strip()
    t = classify(v)
    if t == "cidr":
        v = str(ipaddress.ip_network(v, strict=False))
    return v, t


def host_count(value: str) -> int:
    """How many addresses this target expands to - used by the preflight screen."""
    t = classify(value)
    if t == "cidr":
        return ipaddress.ip_network(value, strict=False).num_addresses
    if t == "range":
        start, end = _range_bounds(value)
        return int(end) - int(start) + 1
    return 1


def scan_host_part(value: str) -> str:
    """The bare host a network scanner should aim at (strips scheme/path from URLs)."""
    if classify(value) == "url":
        return urlsplit(value).hostname or value
    return value


# --- scope ------------------------------------------------------------------
def covers(scope_value: str, target_value: str) -> bool:
    """True if an in-scope entry covers the requested target."""
    if scope_value == target_value:
        return True
    try:
        s_type = classify(scope_value)
        t_type = classify(target_value)
    except ValidationError:
        return False

    t_host = scan_host_part(target_value)
    if s_type in ("host", "url") or t_type == "host":
        return scan_host_part(scope_value) == t_host

    try:
        addr = ipaddress.ip_address(t_host)
    except ValueError:
        return False

    if s_type == "ip":
        return str(addr) == scope_value
    if s_type == "cidr":
        return addr in ipaddress.ip_network(scope_value, strict=False)
    if s_type == "range":
        start, end = _range_bounds(scope_value)
        return int(start) <= int(addr) <= int(end)
    return False


def check_in_scope(scope_values: list[str], target_value: str,
                   excluded_values: list[str] | None = None) -> None:
    """Allow only what is in scope, and never what has been explicitly excluded.

    An exclusion always wins over an inclusion. That matters because scope is
    usually written broadly ("10.10.10.0/24") with carve-outs for the one machine
    you must not touch - the domain controller, the production box someone left on
    the lab network. If the broad rule beat the carve-out, marking a host excluded
    would be a lie.
    """
    for e in (excluded_values or []):
        if covers(e, target_value):
            raise ValidationError(
                f"{target_value!r} is covered by {e!r}, which you marked as excluded from "
                "this project's scope. An exclusion always wins over an in-scope range - "
                "put it back in scope on the Targets screen if you do mean to scan it."
            )
    if any(covers(s, target_value) for s in scope_values):
        return
    raise ValidationError(
        f"{target_value!r} is not inside this project's declared scope. "
        "Add it as an in-scope target first - and only if you are authorized to scan it."
    )


# --- other user-supplied fragments -----------------------------------------
def validate_ports(spec: str) -> str:
    s = (spec or "").strip().replace(" ", "")
    if not s:
        raise ValidationError("Port list is empty.")
    if not PORTSPEC_RE.match(s):
        raise ValidationError(
            f"{spec!r} isn't a valid port list. "
            "Use numbers, commas and dashes: 22,80,443 or 1-1024."
        )
    for chunk in s.split(","):
        for p in chunk.split("-"):
            if not 0 <= int(p) <= 65535:
                raise ValidationError(f"Port {p} is outside the valid range 0-65535.")
        if "-" in chunk:
            lo, hi = (int(x) for x in chunk.split("-"))
            if hi < lo:
                raise ValidationError(f"Port range {chunk!r} counts backwards.")
    return s


def port_count(spec: str) -> int:
    total = 0
    for chunk in spec.split(","):
        if "-" in chunk:
            lo, hi = (int(x) for x in chunk.split("-"))
            total += hi - lo + 1
        else:
            total += 1
    return total


def validate_choice(value: str, allowed: list[str], field: str) -> str:
    if value not in allowed:
        raise ValidationError(f"{value!r} is not a valid {field}. Allowed: {', '.join(allowed)}.")
    return value


def validate_int(value, lo: int, hi: int, field: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field} must be a whole number.") from exc
    if not lo <= n <= hi:
        raise ValidationError(f"{field} must be between {lo} and {hi}.")
    return n


def validate_path(value: str, field: str = "path") -> str:
    v = (value or "/").strip()
    if not PATH_RE.match(v):
        raise ValidationError(f"{field} must start with / and contain no spaces or shell characters.")
    return v


def validate_wordlist(value: str) -> str:
    v = (value or "").strip()
    if not re.match(r"^[A-Za-z0-9._/\\:-]{1,255}$", v):
        raise ValidationError("Wordlist path contains characters that aren't allowed.")
    if ".." in v:
        raise ValidationError("Wordlist path may not contain '..'.")
    return v


def validate_raw_flags(value: str) -> list[str]:
    """Advanced mode: extra flags, split on whitespace, each checked strictly.

    Shell metacharacters are refused outright. These become individual argv
    entries and never a shell string, but we still refuse them so the command
    preview can never lie about what is going to happen.
    """
    v = (value or "").strip()
    if not v:
        return []
    bad = set(";|&`$><\n\r\"'\\(){}*?!")
    out: list[str] = []
    for token in v.split():
        if bad & set(token):
            raise ValidationError(
                f"{token!r} contains a shell character we don't allow. "
                "ReconScan never runs a shell, so these cannot do what you might expect."
            )
        if not re.match(r"^[A-Za-z0-9._,=:/@+-]{1,128}$", token):
            raise ValidationError(f"{token!r} isn't an allowed flag or value.")
        out.append(token)
    return out
